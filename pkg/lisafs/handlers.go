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
	"syscall"

	"gvisor.dev/gvisor/pkg/flipcall"
	"gvisor.dev/gvisor/pkg/log"
	"gvisor.dev/gvisor/pkg/marshal"
)

// RPCHanlder defines a handler that the server implementation must define. It
// returns the message to respond along with any FDs to donate.
type RPCHanlder func(c *Connection, payload []byte) (marshal.Marshallable, []int, error)

// ChannelHandler handles the Channel RPC.
func ChannelHandler(c *Connection, payload []byte) (marshal.Marshallable, []int, error) {
	ch, desc, fdSock, err := c.createChannel()
	if err != nil {
		return nil, nil, err
	}

	// Start servicing the channel in a separate goroutine.
	c.activeWg.Add(1)
	go func() {
		if err := c.service(ch); err != nil {
			// Don't log shutdown error which is expected during server shutdown.
			if _, ok := err.(flipcall.ShutdownError); !ok {
				log.Warningf("lisafs.Connection.service(channel = @%p): %v", ch, err)
			}
		}
		c.activeWg.Done()
	}()

	clientDataFD, err := syscall.Dup(desc.FD)
	if err != nil {
		syscall.Close(fdSock)
		ch.shutdown()
		return nil, nil, err
	}

	// Respond to client with successful channel creation message.
	msg := &ChannelResp{
		dataOffset: desc.Offset,
		dataLength: uint64(desc.Length),
	}
	return msg, []int{clientDataFD, fdSock}, nil
}

var _ RPCHanlder = ChannelHandler
