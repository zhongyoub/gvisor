// Copyright 2021 The gVisor Authors.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package lisafs

import (
	"runtime"
	"syscall"

	"gvisor.dev/gvisor/pkg/fdchannel"
	"gvisor.dev/gvisor/pkg/flipcall"
	"gvisor.dev/gvisor/pkg/log"
	"gvisor.dev/gvisor/pkg/marshal"
)

var (
	// maxChannels is the number of channels a client can create.
	//
	// The server will reject channel creation requests beyond this (per client).
	// Note that we don't want the number of channels to be too large, because each
	// accounts for a large region of shared memory.
	maxChannels = func() int {
		n := runtime.NumCPU()
		if n < 2 {
			return 2
		}
		if n > 4 {
			return 4
		}
		return n
	}()

	chanHeaderLen = (*channelHeader)(nil).SizeBytes()
)

// channelSize is the channel size to create.
//
// We simply ensure that this is larger than the largest possible message size,
// plus the flipcall packet header.
const channelSize = int(2 + flipcall.PacketHeaderBytes + MaxMessageSize)

// channel represents the communication endpoint for the client and server and
// is used to perform fast IPC. Apart from communicating data, a channel is
// also capable of donating file descriptors.
type channel struct {
	data   flipcall.Endpoint
	fdChan fdchannel.Endpoint
}

func (ch *channel) shutdown() {
	ch.data.Shutdown()
}

func (ch *channel) destroy() {
	ch.fdChan.Destroy()
	ch.data.Destroy()
}

// createChannel creates a server side channel. It returns a packet window
// descriptor (for the data channel) and an open socket for the FD channel.
func (c *Connection) createChannel() (*channel, flipcall.PacketWindowDescriptor, int, error) {
	c.channelsMu.Lock()
	defer c.channelsMu.Unlock()
	if c.channels == nil || len(c.channels) >= maxChannels {
		return nil, flipcall.PacketWindowDescriptor{}, -1, syscall.ENOSYS
	}
	ch := &channel{}

	// Set up data channel.
	desc, err := c.channelAlloc.Allocate(channelSize)
	if err != nil {
		return nil, flipcall.PacketWindowDescriptor{}, -1, err
	}
	if err := ch.data.Init(flipcall.ServerSide, desc); err != nil {
		return nil, flipcall.PacketWindowDescriptor{}, -1, err
	}

	// Set up FD channel.
	fdSocks, err := fdchannel.NewConnectedSockets()
	if err != nil {
		ch.data.Destroy()
		return nil, flipcall.PacketWindowDescriptor{}, -1, err
	}
	ch.fdChan.Init(fdSocks[0])
	clientFDSock := fdSocks[1]

	c.channels = append(c.channels, ch)
	return ch, desc, clientFDSock, nil
}

// writeMsg mashals the passed message into the channel buffer and donates any
// passed FDs. Note that FD donation is destructive: the donated FD is closed
// after donation.
func (ch *channel) writeMsg(m MID, msg marshal.Marshallable, fds []int) (uint32, error) {
	// Send any FDs.
	if len(fds) > 0 {
		defer closeFDs(fds)
		for _, fd := range fds {
			if err := ch.fdChan.SendFD(fd); err != nil {
				return 0, err
			}
		}
	}

	// Write header.
	buf := ch.data.Data()
	var header channelHeader
	header.message = m
	header.numFDs = uint8(len(fds))
	header.MarshalBytes(buf)
	buf = buf[chanHeaderLen:]

	// Write the message.
	dataLen := chanHeaderLen
	if msg != nil {
		dataLen += msg.SizeBytes()
		if dataLen > int(MaxMessageSize) {
			log.Warningf("message %d has payload which is too long: %d bytes", m, dataLen)
			return 0, syscall.EIO
		}
		msg.MarshalBytes(buf)
	}
	return uint32(dataLen), nil
}

func (ch *channel) readMsg(dataLen uint32, fds []int) (MID, []byte, error) {
	if int(dataLen) < chanHeaderLen {
		log.Warningf("received data has size smaller than header length: %d", dataLen)
		return 0, nil, syscall.EINVAL
	}
	buf := ch.data.Data()

	// Read header first.
	var header channelHeader
	header.UnmarshalBytes(buf)
	buf = buf[chanHeaderLen:]

	if int(header.numFDs) != len(fds) {
		log.Warningf("expected %d FDs but got %d", len(fds), header.numFDs)
	}
	// Set all FDs to -1 which indicates that the FD is not set.
	for i := 0; i < len(fds); i++ {
		fds[i] = -1
	}
	// Read any FDs.
	for i := 0; i < int(header.numFDs); i++ {
		fd, err := ch.fdChan.RecvFDNonblock()
		if err != nil {
			log.Warningf("expected %d FDs, recieved %d successfully, got err after that: %v", header.numFDs, i, err)
			break
		}
		if i < len(fds) {
			fds[i] = fd
		} else {
			log.Warningf("closing the %d FD recieved on channel because its extra", i+1)
			syscall.Close(fd)
		}
	}

	return header.message, buf[:int(dataLen)-chanHeaderLen], nil
}
