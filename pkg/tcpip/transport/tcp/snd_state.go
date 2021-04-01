// Copyright 2018 The gVisor Authors.
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

package tcp

import (
	"time"
)

// +stateify savable
type unixTime struct {
	second int64
	nano   int64
}

// saveLastSendTime is invoked by stateify.
func (s *sender) saveLastSendTime() unixTime {
	return unixTime{s.LastSendTime.Unix(), s.LastSendTime.UnixNano()}
}

// loadLastSendTime is invoked by stateify.
func (s *sender) loadLastSendTime(unix unixTime) {
	s.LastSendTime = time.Unix(unix.second, unix.nano)
}

// saveRttMeasureTime is invoked by stateify.
func (s *sender) saveRttMeasureTime() unixTime {
	return unixTime{s.RTTMeasureTime.Unix(), s.RTTMeasureTime.UnixNano()}
}

// loadRttMeasureTime is invoked by stateify.
func (s *sender) loadRttMeasureTime(unix unixTime) {
	s.RTTMeasureTime = time.Unix(unix.second, unix.nano)
}

// afterLoad is invoked by stateify.
func (s *sender) afterLoad() {
	s.resendTimer.init(&s.resendWaker)
	s.reorderTimer.init(&s.reorderWaker)
	s.probeTimer.init(&s.probeWaker)
}

// saveFirstRetransmittedSegXmitTime is invoked by stateify.
func (s *sender) saveFirstRetransmittedSegXmitTime() unixTime {
	return unixTime{s.firstRetransmittedSegXmitTime.Unix(), s.firstRetransmittedSegXmitTime.UnixNano()}
}

// loadFirstRetransmittedSegXmitTime is invoked by stateify.
func (s *sender) loadFirstRetransmittedSegXmitTime(unix unixTime) {
	s.firstRetransmittedSegXmitTime = time.Unix(unix.second, unix.nano)
}
