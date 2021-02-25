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
	"gvisor.dev/gvisor/pkg/marshal"
	"gvisor.dev/gvisor/pkg/marshal/primitive"
)

// MID (message ID) is used to identify messages to parse from payload.
//
// +marshal slice:MIDSlice
type MID uint16

// These constants are used to identify their corresponding message types.
// Note that this order must be preserved across versions and new messages must
// only be appended at the end.
const (
	// Error is only used in responses to pass errors to client.
	Error MID = iota

	// Mount is used to establish connection and set up server side filesystem.
	Mount

	// Channel request starts a new channel.
	Channel
)

// MaxMessageSize is the largest possible message in bytes.
const MaxMessageSize uint32 = 1 << 20

// sockHeader is the header present in front of each message received on a UDS.
//
// +marshal
type sockHeader struct {
	size    uint32
	message MID
	_       uint16
}

// channelHeader is the header present in front of each message received on
// flipcall endpoint.
//
// +marshal
type channelHeader struct {
	message MID
	numFDs  uint8
	_       uint8
}

// SizedString represents a string in memory.
//
// +marshal dynamic
type SizedString struct {
	size primitive.Uint32
	str  []byte `marshal:"unaligned"`
}

var _ marshal.Marshallable = (*SizedString)(nil)

func (s *SizedString) String() string {
	return string(s.str)
}

func (s *SizedString) setString(str string) {
	if len(str) > int(^uint16(0)) {
		panic("string too long")
	}
	s.size = primitive.Uint32(len(str))
	s.str = []byte(str)
}

func (s *SizedString) reset() {
	s.size = 0
	s.str = s.str[:0]
}

// SizeBytes implements marshal.Marshallable.SizeBytes.
func (s *SizedString) SizeBytes() int {
	if s == nil {
		// Only return the size of primitive.Uint32 as no string actually exists.
		return (*primitive.Uint32)(nil).SizeBytes()
	}
	return s.size.SizeBytes() + len(s.str)
}

// MarshalBytes implements marshal.Marshallable.MarshalBytes.
func (s *SizedString) MarshalBytes(dst []byte) {
	s.size.MarshalBytes(dst)
	copy(dst[s.size.SizeBytes():], s.str)
}

// UnmarshalBytes implements marshal.Marshallable.UnmarshalBytes.
func (s *SizedString) UnmarshalBytes(src []byte) {
	s.size.UnmarshalBytes(src)
	// Try to reuse s.str as much as possible.
	if cap(s.str) < int(s.size) {
		s.str = make([]byte, s.size)
	} else {
		s.str = s.str[:s.size]
	}
	sizeSize := s.size.SizeBytes()
	copy(s.str, src[sizeSize:sizeSize+int(s.size)])
}

// MountReq represents a Mount request.
//
// +marshal dynamic
type MountReq struct {
	MountPath SizedString
}

var _ marshal.Marshallable = (*MountReq)(nil)

// SizeBytes implements marshal.Marshallable.SizeBytes.
func (m *MountReq) SizeBytes() int {
	return m.MountPath.SizeBytes()
}

// MarshalBytes implements marshal.Marshallable.MarshalBytes.
func (m *MountReq) MarshalBytes(dst []byte) {
	m.MountPath.MarshalBytes(dst)
}

// UnmarshalBytes implements marshal.Marshallable.UnmarshalBytes.
func (m *MountReq) UnmarshalBytes(src []byte) {
	m.MountPath.UnmarshalBytes(src)
}

// MountResp represents a Mount response.
//
// +marshal dynamic
type MountResp struct {
	Root           FDID
	MaxM           MID
	NumUnsupported primitive.Uint16
	UnsupportedMs  []MID
}

var _ marshal.Marshallable = (*MountResp)(nil)

// SizeBytes implements marshal.Marshallable.SizeBytes.
func (m *MountResp) SizeBytes() int {
	return m.Root.SizeBytes() +
		m.MaxM.SizeBytes() +
		m.NumUnsupported.SizeBytes() +
		(len(m.UnsupportedMs) * (*MID)(nil).SizeBytes())
}

// MarshalBytes implements marshal.Marshallable.MarshalBytes.
func (m *MountResp) MarshalBytes(dst []byte) {
	m.Root.MarshalBytes(dst)
	dst = dst[m.Root.SizeBytes():]
	m.MaxM.MarshalBytes(dst)
	dst = dst[m.MaxM.SizeBytes():]
	m.NumUnsupported.MarshalBytes(dst)
	dst = dst[m.NumUnsupported.SizeBytes():]
	MarshalUnsafeMIDSlice(m.UnsupportedMs, dst)
}

// UnmarshalBytes implements marshal.Marshallable.UnmarshalBytes.
func (m *MountResp) UnmarshalBytes(src []byte) {
	m.Root.UnmarshalBytes(src)
	src = src[m.Root.SizeBytes():]
	m.MaxM.UnmarshalBytes(src)
	src = src[m.MaxM.SizeBytes():]
	m.NumUnsupported.UnmarshalBytes(src)
	src = src[m.NumUnsupported.SizeBytes():]
	m.UnsupportedMs = make([]MID, m.NumUnsupported)
	UnmarshalUnsafeMIDSlice(m.UnsupportedMs, src)
}

// ChannelResp is the response to the create channel request.
//
// +marshal
type ChannelResp struct {
	dataOffset int64
	dataLength uint64
}

// ErrorRes is returned to represent an error while handling a request.
// A field holding value 0 indicates no error on that field.
//
// +marshal
type ErrorRes struct {
	errno uint32
}
