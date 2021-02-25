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

package connection_test

import (
	"reflect"
	"syscall"
	"testing"

	"gvisor.dev/gvisor/pkg/lisafs"
	"gvisor.dev/gvisor/pkg/lisafs/test"
	"gvisor.dev/gvisor/pkg/log"
	"gvisor.dev/gvisor/pkg/marshal"
	"gvisor.dev/gvisor/pkg/marshal/primitive"
	"gvisor.dev/gvisor/pkg/sync"
	"gvisor.dev/gvisor/pkg/unet"
)

func runServerClient(t testing.TB, mountPath string, handlers []lisafs.RPCHanlder, clientFn func(c *lisafs.Client)) {
	serverSocket, clientSocket, err := unet.SocketPair(false)
	if err != nil {
		t.Fatalf("socketpair got err %v expected nil", err)
	}

	var serverWg sync.WaitGroup
	serverWg.Add(1)
	go func() {
		defer serverWg.Done()

		var cm lisafs.ConnectionManager
		if err := cm.StartConnection(serverSocket, mountPath, handlers, nil); err != nil {
			t.Errorf("starting connection failed: %v", err)
			return
		}

		cm.Wait()
	}()

	c, err := lisafs.NewClient(clientSocket, mountPath)
	if err != nil {
		t.Errorf("client creation failed: %v", err)
	}

	clientFn(c)

	c.Close() // This should trigger client and server shutdown.
	serverWg.Wait()
}

var mountHandler lisafs.RPCHanlder = func(c *lisafs.Connection, payload []byte) (marshal.Marshallable, []int, error) {
	var req lisafs.MountReq
	req.UnmarshalBytes(payload)

	if gotMountPath := req.MountPath.String(); gotMountPath != c.Server().MountPath() {
		log.Warningf("incorrect mount path found in request: expected %q, got %q", c.Server().MountPath(), gotMountPath)
		return nil, nil, syscall.EINVAL
	}

	var resp lisafs.MountResp
	resp.Root = 1 // Dummy FDID.
	resp.MaxM = c.MaxMessage()
	resp.UnsupportedMs = c.UnsupportedMessages()
	resp.NumUnsupported = primitive.Uint16(len(resp.UnsupportedMs))
	return &resp, nil, nil
}

// TestStartUp tests that the server and client can be started up correctly.
func TestStartUp(t *testing.T) {
	mountPath := "/"
	var serverHandlers [3]lisafs.RPCHanlder
	serverHandlers[lisafs.Error] = nil // No error handler needed.
	serverHandlers[lisafs.Mount] = mountHandler
	serverHandlers[lisafs.Channel] = lisafs.ChannelHandler
	runServerClient(t, mountPath, serverHandlers[:], func(c *lisafs.Client) {
		if c.IsSupported(lisafs.Error) {
			t.Errorf("sending error messages should not be supported")
		}
	})
}

func TestUnsupportedMessage(t *testing.T) {
	mountPath := "/"
	var serverHandlers [3]lisafs.RPCHanlder
	serverHandlers[lisafs.Error] = nil // No error handler needed.
	serverHandlers[lisafs.Mount] = mountHandler
	serverHandlers[lisafs.Channel] = lisafs.ChannelHandler
	unsupportedM := lisafs.MID(len(serverHandlers))
	runServerClient(t, mountPath, serverHandlers[:], func(c *lisafs.Client) {
		if err := c.SndRcvMessage(unsupportedM, nil, nil, nil); err != syscall.EOPNOTSUPP {
			t.Errorf("expected EOPNOTSUPP but got err: %v", err)
		}
	})
}

// TestStress stress tests sending many messages from various goroutines.
func TestStress(t *testing.T) {
	mountPath := "/"

	var dynamicMsgHandler lisafs.RPCHanlder = func(c *lisafs.Connection, payload []byte) (marshal.Marshallable, []int, error) {
		var req test.MsgDynamic
		req.UnmarshalBytes(payload)

		// Just echo back the message.
		return &req, nil, nil
	}

	dynamicMsgID := lisafs.MID(3)
	var serverHandlers [4]lisafs.RPCHanlder
	serverHandlers[lisafs.Error] = nil // No error handler needed.
	serverHandlers[lisafs.Mount] = mountHandler
	serverHandlers[lisafs.Channel] = lisafs.ChannelHandler
	serverHandlers[dynamicMsgID] = dynamicMsgHandler

	runServerClient(t, mountPath, serverHandlers[:], func(c *lisafs.Client) {
		concurrency := 8
		numMsgPerGoroutine := 5000
		var clientWg sync.WaitGroup
		for i := 0; i < concurrency; i++ {
			clientWg.Add(1)
			go func() {
				defer clientWg.Done()

				for j := 0; j < numMsgPerGoroutine; j++ {
					// Create a massive random message.
					var req test.MsgDynamic
					req.Randomize(100)

					var resp test.MsgDynamic
					if err := c.SndRcvMessage(dynamicMsgID, &req, &resp, nil); err != nil {
						t.Errorf("SndRcvMessage: received unexpected error %v", err)
						return
					}
					if !reflect.DeepEqual(&req, &resp) {
						t.Errorf("response should be the same as request: request = %+v, response = %+v", req, resp)
					}
				}
			}()
		}

		clientWg.Wait()
	})
}

// BenchmarkSendRecv exists to compete against p9's BenchmarkSendRecvChannel.
func BenchmarkSendRecv(b *testing.B) {
	b.ReportAllocs()

	mountPath := "/"
	versionM := lisafs.MID(3)
	var serverHandlers [4]lisafs.RPCHanlder
	serverHandlers[lisafs.Error] = nil // No error handler needed.
	serverHandlers[lisafs.Mount] = mountHandler
	serverHandlers[lisafs.Channel] = lisafs.ChannelHandler
	serverHandlers[versionM] = func(c *lisafs.Connection, payload []byte) (marshal.Marshallable, []int, error) {
		// To be fair, usually handlers will create their own objects and return a
		// pointer to those. Might be tempting to reuse above variables, but don't.
		var rv test.Version
		rv.UnmarshalBytes(payload)

		// Create a new response.
		var sv test.Version
		sv.MSize = rv.MSize
		sv.Version = []byte("9P2000.L.Google.11")
		sv.VersionLen = primitive.Uint16(len(sv.Version))
		return &sv, nil, nil
	}

	var sendV test.Version
	sendV.MSize = primitive.Uint32(lisafs.MaxMessageSize)
	sendV.Version = []byte("9P2000.L.Google.12")
	sendV.VersionLen = primitive.Uint16(len(sendV.Version))

	var recvV test.Version
	runServerClient(b, mountPath, serverHandlers[:], func(c *lisafs.Client) {
		for i := 0; i < b.N; i++ {
			if err := c.SndRcvMessage(versionM, &sendV, &recvV, nil); err != nil {
				b.Fatalf("unexpected error occured: %v", err)
			}
		}
	})
}
