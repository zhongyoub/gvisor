// Copyright 2020 The gVisor Authors.
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

package udp_send_recv_dgram_test

import (
	"context"
	"flag"
	"fmt"
	"net"
	"testing"
	"time"

	"github.com/google/go-cmp/cmp"
	"golang.org/x/sys/unix"
	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/tcpip/header"
	"gvisor.dev/gvisor/test/packetimpact/testbench"
)

func init() {
	testbench.Initialize(flag.CommandLine)
	testbench.RPCTimeout = 500 * time.Millisecond
}

type testCase struct {
	bindTo, sendTo                            net.IP
	sendToBroadcast, bindToDevice, expectData bool
	proto                                     protoTest
}

type protoTest interface {
	Name() string
	Send(t *testing.T, dut testbench.DUT, tc testCase)
	Recv(t *testing.T, dut testbench.DUT, tc testCase)
}

func TestSocket(t *testing.T) {
	dut := testbench.NewDUT(t)
	subnetBcast := func() net.IP {
		subnet := (&tcpip.AddressWithPrefix{
			Address:   tcpip.Address(dut.Net.RemoteIPv4.To4()),
			PrefixLen: dut.Net.IPv4PrefixLength,
		}).Subnet()
		return net.IP(subnet.Broadcast())
	}()

	t.Run("Send", func(t *testing.T) {
		var testCases []testCase
		// Test every valid combination of bound/unbound, broadcast/multicast/unicast
		// bound/destination address, and bound/not-bound to device.
		for _, bindTo := range []net.IP{
			nil, // Do not bind.
			net.IPv4zero,
			net.IPv4bcast,
			net.IPv4allsys,
			subnetBcast,
			dut.Net.RemoteIPv4,
			dut.Net.RemoteIPv6,
		} {
			for _, sendTo := range []net.IP{
				net.IPv4bcast,
				net.IPv4allsys,
				subnetBcast,
				dut.Net.LocalIPv4,
				dut.Net.LocalIPv6,
			} {
				// Cannot send to an IPv4 address from a socket bound to IPv6 (except for IPv4-mapped IPv6),
				// and viceversa.
				if bindTo != nil && ((bindTo.To4() == nil) != (sendTo.To4() == nil)) {
					continue
				}
				for _, bindToDevice := range []bool{true, false} {
					expectData := true
					switch {
					case bindTo.Equal(dut.Net.RemoteIPv4):
						// If we're explicitly bound to an interface's unicast address,
						// packets are always sent on that interface.
					case bindToDevice:
						// If we're explicitly bound to an interface, packets are always
						// sent on that interface.
					case !sendTo.Equal(net.IPv4bcast) && !sendTo.IsMulticast():
						// If we're not sending to limited broadcast or multicast, the route table
						// will be consulted and packets will be sent on the correct interface.
					default:
						expectData = false
					}

					testCases = append(
						testCases,
						testCase{
							bindTo:          bindTo,
							sendTo:          sendTo,
							sendToBroadcast: sendTo.Equal(subnetBcast) || sendTo.Equal(net.IPv4bcast),
							bindToDevice:    bindToDevice,
							expectData:      expectData,
							proto:           &udpTest{},
						},
					)

					switch {
					case bindTo.Equal(net.IPv4bcast) || bindTo.Equal(subnetBcast):
						// ICMP sockets do not allow binding to broadcast addresses.
					case bindTo.IsMulticast():
						// ICMP sockets do not allow binding to multicast addresses.
					case sendTo.IsMulticast() || sendTo.Equal(net.IPv4bcast) || sendTo.Equal(subnetBcast):
						// TODO(gvisor.dev/issue/5681): Allow sending to
						// multicast and broadcast addresses from ICMP sockets.
					default:
						testCases = append(
							testCases,
							testCase{
								bindTo:          bindTo,
								sendTo:          sendTo,
								sendToBroadcast: sendTo.Equal(subnetBcast) || sendTo.Equal(net.IPv4bcast),
								bindToDevice:    bindToDevice,
								expectData:      expectData,
								proto:           &icmpTest{},
							},
						)
					}
				}
			}
		}
		for _, tc := range testCases {
			boundTestCaseName := "unbound"
			if tc.bindTo != nil {
				boundTestCaseName = fmt.Sprintf("bindTo=%s", tc.bindTo)
			}
			t.Run(fmt.Sprintf("%s/%s/sendTo=%s/bindToDevice=%t/expectData=%t", tc.proto.Name(), boundTestCaseName, tc.sendTo, tc.bindToDevice, tc.expectData), func(t *testing.T) {
				tc.proto.Send(t, dut, tc)
			})
		}
	})
	t.Run("Recv", func(t *testing.T) {
		// Test every valid combination of broadcast/multicast/unicast
		// bound/destination address, and bound/not-bound to device.
		var testCases []testCase
		for _, addr := range []net.IP{
			net.IPv4bcast,
			net.IPv4allsys,
			dut.Net.RemoteIPv4,
			dut.Net.RemoteIPv6,
		} {
			for _, bindToDevice := range []bool{true, false} {
				testCases = append(
					testCases,
					testCase{
						bindTo:          addr,
						sendTo:          addr,
						sendToBroadcast: addr.Equal(subnetBcast) || addr.Equal(net.IPv4bcast),
						bindToDevice:    bindToDevice,
						expectData:      true,
						proto:           &udpTest{},
					},
				)

				switch {
				case addr.Equal(net.IPv4bcast):
					// ICMP sockets do not allow binding to broadcast addresses.
				case addr.IsMulticast():
					// ICMP sockets do not allow binding to multicast addresses.
				default:
					testCases = append(
						testCases,
						testCase{
							bindTo:          addr,
							sendTo:          addr,
							sendToBroadcast: addr.Equal(subnetBcast) || addr.Equal(net.IPv4bcast),
							bindToDevice:    bindToDevice,
							expectData:      true,
							proto:           &icmpTest{},
						},
					)
				}
			}
		}
		for _, bindTo := range []net.IP{
			net.IPv4zero,
			subnetBcast,
			dut.Net.RemoteIPv4,
		} {
			for _, sendTo := range []net.IP{
				subnetBcast,
				net.IPv4bcast,
				net.IPv4allsys,
			} {
				// TODO(gvisor.dev/issue/4896): Add bindTo=subnetBcast/sendTo=IPv4bcast
				// and bindTo=subnetBcast/sendTo=IPv4allsys test cases.
				if bindTo.Equal(subnetBcast) && (sendTo.Equal(net.IPv4bcast) || sendTo.IsMulticast()) {
					continue
				}
				// Expect that a socket bound to a unicast address does not receive
				// packets sent to an address other than the bound unicast address.
				//
				// Note: we cannot use net.IP.IsGlobalUnicast to test this condition
				// because IsGlobalUnicast does not check whether the address is the
				// subnet broadcast, and returns true in that case.
				expectData := !bindTo.Equal(dut.Net.RemoteIPv4) || sendTo.Equal(dut.Net.RemoteIPv4)
				for _, bindToDevice := range []bool{true, false} {
					testCases = append(
						testCases,
						testCase{
							bindTo:          bindTo,
							sendTo:          sendTo,
							sendToBroadcast: sendTo.Equal(subnetBcast) || sendTo.Equal(net.IPv4bcast),
							bindToDevice:    bindToDevice,
							expectData:      expectData,
							proto:           &udpTest{},
						},
					)

					switch {
					case bindTo.Equal(subnetBcast):
						// ICMP sockets do not allow binding to broadcast addresses.
					case bindTo.Equal(net.IPv4zero):
						// TODO(gvisor.dev/issue/5673): Remove this case when
						// ICMP sockets no longer accept traffic from multicast
						// and broadcast when bound to IPv4zero.
					default:
						testCases = append(
							testCases,
							testCase{
								bindTo:          bindTo,
								sendTo:          sendTo,
								sendToBroadcast: sendTo.Equal(subnetBcast) || sendTo.Equal(net.IPv4bcast),
								bindToDevice:    bindToDevice,
								// ICMP sockets do not allow receiving from
								// broadcast or multicast addresses.
								expectData: false,
								proto:      &icmpTest{},
							},
						)
					}
				}
			}
		}
		for _, tc := range testCases {
			t.Run(fmt.Sprintf("%s/bindTo=%s/sendTo=%s/bindToDevice=%t/expectData=%t", tc.proto.Name(), tc.bindTo, tc.sendTo, tc.bindToDevice, tc.expectData), func(t *testing.T) {
				tc.proto.Recv(t, dut, tc)
			})
		}
	})
}

type udpConn interface {
	SrcPort(*testing.T) uint16
	SendFrame(*testing.T, testbench.Layers, ...testbench.Layer)
	ExpectFrame(*testing.T, testbench.Layers, time.Duration) (testbench.Layers, error)
	Close(*testing.T)
}

type udpTest struct{}

func (*udpTest) Name() string { return "udp" }

func (*udpTest) Send(t *testing.T, dut testbench.DUT, tc testCase) {
	t.Helper()
	udpTestCase(
		t,
		dut,
		tc,
		func(t *testing.T, dut testbench.DUT, conn udpConn, socketFD int32, tc testCase, payload []byte, layers testbench.Layers) {
			var destSockaddr unix.Sockaddr
			if sendTo4 := tc.sendTo.To4(); sendTo4 != nil {
				addr := unix.SockaddrInet4{
					Port: int(conn.SrcPort(t)),
				}
				copy(addr.Addr[:], sendTo4)
				destSockaddr = &addr
			} else {
				addr := unix.SockaddrInet6{
					Port:   int(conn.SrcPort(t)),
					ZoneId: dut.Net.RemoteDevID,
				}
				copy(addr.Addr[:], tc.sendTo.To16())
				destSockaddr = &addr
			}
			if got, want := dut.SendTo(t, socketFD, payload, 0, destSockaddr), len(payload); int(got) != want {
				t.Fatalf("got dut.SendTo = %d, want %d", got, want)
			}
			layers = append(layers, &testbench.Payload{
				Bytes: payload,
			})
			_, err := conn.ExpectFrame(t, layers, time.Second)

			if !tc.expectData && err == nil {
				t.Fatal("received unexpected packet, socket is not bound to device")
			}
			if err != nil && tc.expectData {
				t.Fatal(err)
			}
		},
	)
}

func (*udpTest) Recv(t *testing.T, dut testbench.DUT, tc testCase) {
	t.Helper()
	udpTestCase(
		t,
		dut,
		tc,
		func(t *testing.T, dut testbench.DUT, conn udpConn, socketFD int32, tc testCase, payload []byte, layers testbench.Layers) {
			conn.SendFrame(t, layers, &testbench.Payload{Bytes: payload})

			if tc.expectData {
				got, want := dut.Recv(t, socketFD, int32(len(payload)+1), 0), payload
				if diff := cmp.Diff(want, got); diff != "" {
					t.Errorf("received payload does not match sent payload, diff (-want, +got):\n%s", diff)
				}
			} else {
				// Expected receive error, set a short receive timeout.
				dut.SetSockOptTimeval(
					t,
					socketFD,
					unix.SOL_SOCKET,
					unix.SO_RCVTIMEO,
					&unix.Timeval{
						Sec:  1,
						Usec: 0,
					},
				)
				ret, recvPayload, errno := dut.RecvWithErrno(context.Background(), t, socketFD, 100, 0)
				if errno != unix.EAGAIN || errno != unix.EWOULDBLOCK {
					t.Errorf("Recv got unexpected result, ret=%d, payload=%q, errno=%s", ret, recvPayload, errno)
				}
			}
		},
	)
}

func udpTestCase(
	t *testing.T,
	dut testbench.DUT,
	tc testCase,
	runTc func(t *testing.T, dut testbench.DUT, conn udpConn, socketFD int32, tc testCase, payload []byte, layers testbench.Layers),
) {
	t.Helper()
	var (
		socketFD                 int32
		outgoingUDP, incomingUDP testbench.UDP
	)
	if tc.bindTo != nil {
		var remotePort uint16
		socketFD, remotePort = dut.CreateBoundSocket(t, unix.SOCK_DGRAM, unix.IPPROTO_UDP, tc.bindTo)
		outgoingUDP.DstPort = &remotePort
		incomingUDP.SrcPort = &remotePort
	} else {
		// An unbound socket will auto-bind to INNADDR_ANY and a random
		// port on sendto.
		socketFD = dut.Socket(t, unix.AF_INET6, unix.SOCK_DGRAM, unix.IPPROTO_UDP)
	}
	defer dut.Close(t, socketFD)
	if tc.bindToDevice {
		dut.SetSockOpt(t, socketFD, unix.SOL_SOCKET, unix.SO_BINDTODEVICE, []byte(dut.Net.RemoteDevName))
	}

	var conn udpConn
	var ipLayer testbench.Layer
	if addr := tc.sendTo.To4(); addr != nil {
		udpConn := dut.Net.NewUDPIPv4(t, outgoingUDP, incomingUDP)
		conn = &udpConn
		ipLayer = &testbench.IPv4{
			DstAddr: testbench.Address(tcpip.Address(addr)),
		}
	} else {
		udpConn := dut.Net.NewUDPIPv6(t, outgoingUDP, incomingUDP)
		conn = &udpConn
		ipLayer = &testbench.IPv6{
			DstAddr: testbench.Address(tcpip.Address(tc.sendTo.To16())),
		}
	}
	defer conn.Close(t)

	expectedLayers := testbench.Layers{
		expectedEthLayer(t, dut, tc, socketFD),
		ipLayer,
		&incomingUDP,
	}

	for name, payload := range map[string][]byte{
		"empty":    nil,
		"small":    []byte("hello world"),
		"random1k": testbench.GenerateRandomPayload(t, 1<<10),
		// Even though UDP allows larger datagrams we don't test it here as they
		// need to be fragmented and written out as individual frames.
	} {
		t.Run(name, func(t *testing.T) {
			runTc(t, dut, conn, socketFD, tc, payload, expectedLayers)
		})
	}
}

func expectedEthLayer(t *testing.T, dut testbench.DUT, tc testCase, socketFD int32) testbench.Layer {
	t.Helper()
	var dst *tcpip.LinkAddress
	if tc.sendToBroadcast {
		dut.SetSockOptInt(t, socketFD, unix.SOL_SOCKET, unix.SO_BROADCAST, 1)

		// When sending to broadcast (subnet or limited), the expected ethernet
		// address is also broadcast.
		ethernetBroadcastAddress := header.EthernetBroadcastAddress
		dst = &ethernetBroadcastAddress
	} else if tc.sendTo.IsMulticast() {
		ethernetMulticastAddress := header.EthernetAddressFromMulticastIPv4Address(tcpip.Address(tc.sendTo.To4()))
		dst = &ethernetMulticastAddress
	}
	return &testbench.Ether{
		DstAddr: dst,
	}
}

type ipConn interface {
	CreateFrame(*testing.T, testbench.Layers, ...testbench.Layer) testbench.Layers
	SendFrame(*testing.T, testbench.Layers)
	ExpectFrame(*testing.T, testbench.Layers, time.Duration) (testbench.Layers, error)
	Close(*testing.T)
}

type icmpTest struct{}

func (*icmpTest) Name() string { return "icmp" }

func (*icmpTest) Send(t *testing.T, dut testbench.DUT, tc testCase) {
	t.Helper()
	icmpTestCase(
		t,
		dut,
		tc,
		func(t *testing.T, dut testbench.DUT, conn ipConn, socketFD int32, tc testCase, layers testbench.Layers, ident uint16, payload []byte, protocol icmpProtocol) {
			var destSockaddr unix.Sockaddr
			if sendTo4 := tc.sendTo.To4(); sendTo4 != nil {
				addr := unix.SockaddrInet4{}
				copy(addr.Addr[:], sendTo4)
				destSockaddr = &addr
			} else {
				addr := unix.SockaddrInet6{
					ZoneId: dut.Net.RemoteDevID,
				}
				copy(addr.Addr[:], tc.sendTo.To16())
				destSockaddr = &addr
			}

			icmpLayer := protocol.icmpLayer(ident, payload, icmpEchoRequest)
			bytes, err := icmpLayer.ToBytes()
			if err != nil {
				t.Fatalf("icmpLayer.ToBytes() = %s", err)
			}
			if got, want := dut.SendTo(t, socketFD, bytes, 0, destSockaddr), len(bytes); int(got) != want {
				t.Fatalf("got dut.SendTo = %d, want %d", got, want)
			}

			_, err = conn.ExpectFrame(t, append(layers, icmpLayer), time.Second)
			if tc.expectData && err != nil {
				t.Fatal(err)
			}
			if !tc.expectData && err == nil {
				t.Fatal("received unexpected packet, socket is not bound to device")
			}
		},
	)
}

func (*icmpTest) Recv(t *testing.T, dut testbench.DUT, tc testCase) {
	t.Helper()
	icmpTestCase(
		t,
		dut,
		tc,
		func(t *testing.T, dut testbench.DUT, conn ipConn, socketFD int32, tc testCase, layers testbench.Layers, ident uint16, payload []byte, protocol icmpProtocol) {
			icmpLayer := protocol.icmpLayer(ident, payload, icmpEchoReply)
			frame := conn.CreateFrame(t, layers[:2], icmpLayer)
			conn.SendFrame(t, frame)

			if tc.expectData {
				payload, err := icmpLayer.ToBytes()
				if err != nil {
					t.Fatalf("icmpLayer.ToBytes() = %s", err)
				}

				got, want := dut.Recv(t, socketFD, int32(len(payload)+1), 0), payload
				if diff := cmp.Diff(want, got); diff != "" {
					t.Errorf("received payload does not match sent payload, diff (-want, +got):\n%s", diff)
				}
			} else {
				// Expected receive error, set a short receive timeout.
				dut.SetSockOptTimeval(
					t,
					socketFD,
					unix.SOL_SOCKET,
					unix.SO_RCVTIMEO,
					&unix.Timeval{
						Sec:  1,
						Usec: 0,
					},
				)
				ret, recvPayload, errno := dut.RecvWithErrno(context.Background(), t, socketFD, 100, 0)
				if errno != unix.EAGAIN || errno != unix.EWOULDBLOCK {
					t.Errorf("Recv got unexpected result, ret=%d, payload=%q, errno=%s", ret, recvPayload, errno)
				}
			}
		},
	)
}

type icmpProtocol struct {
	proto     int32
	domain    int32
	conn      func(t *testing.T, net *testbench.DUTTestNet) ipConn
	ipLayer   func() testbench.Layer
	icmpLayer func(ident uint16, payload []byte, t icmpType) testbench.Layer
}

type icmpType int

const (
	icmpEchoRequest icmpType = iota
	icmpEchoReply
)

func ipToProtocol(dst net.IP) icmpProtocol {
	if addr := dst.To4(); addr != nil {
		return icmpProtocol{
			proto:  unix.IPPROTO_ICMP,
			domain: unix.AF_INET,
			conn: func(t *testing.T, net *testbench.DUTTestNet) ipConn {
				conn := net.NewIPv4Conn(t, testbench.IPv4{}, testbench.IPv4{})
				return &conn
			},
			ipLayer: func() testbench.Layer {
				return &testbench.IPv4{
					DstAddr: testbench.Address(tcpip.Address(addr)),
				}
			},
			icmpLayer: func(ident uint16, payload []byte, t icmpType) testbench.Layer {
				var typ header.ICMPv4Type
				if t == icmpEchoRequest {
					typ = header.ICMPv4Echo
				} else {
					typ = header.ICMPv4EchoReply
				}
				icmp := testbench.ICMPv4{
					Type:    &typ,
					Payload: payload,
				}
				if ident != 0 {
					icmp.Ident = &ident
				}
				return &icmp
			},
		}
	}
	return icmpProtocol{
		proto:  unix.IPPROTO_ICMPV6,
		domain: unix.AF_INET6,
		conn: func(t *testing.T, net *testbench.DUTTestNet) ipConn {
			conn := net.NewIPv6Conn(t, testbench.IPv6{}, testbench.IPv6{})
			return &conn
		},
		ipLayer: func() testbench.Layer {
			return &testbench.IPv6{
				DstAddr: testbench.Address(tcpip.Address(dst.To16())),
			}
		},
		icmpLayer: func(ident uint16, payload []byte, t icmpType) testbench.Layer {
			var typ header.ICMPv6Type
			if t == icmpEchoRequest {
				typ = header.ICMPv6EchoRequest
			} else {
				typ = header.ICMPv6EchoReply
			}
			icmp := testbench.ICMPv6{
				Type:    &typ,
				Payload: payload,
			}
			if ident != 0 {
				icmp.Ident = &ident
			}
			return &icmp
		},
	}
}

func icmpTestCase(
	t *testing.T,
	dut testbench.DUT,
	tc testCase,
	runTc func(t *testing.T, dut testbench.DUT, conn ipConn, socketFD int32, tc testCase, layers testbench.Layers, ident uint16, payload []byte, protocol icmpProtocol),
) {
	t.Helper()

	protocol := ipToProtocol(tc.sendTo)

	var socketFD int32
	var port uint16
	if tc.bindTo != nil {
		socketFD, port = dut.CreateBoundSocket(t, unix.SOCK_DGRAM, protocol.proto, tc.bindTo)
		if port == 0 {
			// The socket's port is the ICMP identifier used in the payload for
			// echo requests and responses. This enables de-multiplexing for
			// ICMP sockets. It should be non-zero.
			t.Fatalf("got dut.CreateBoundSocket(...) = _, %d, want != 0", port)
		}
	} else {
		// An unbound socket will auto-bind to INNADDR_ANY.
		socketFD = dut.Socket(t, protocol.domain, unix.SOCK_DGRAM, protocol.proto)
	}
	defer dut.Close(t, socketFD)
	if tc.bindToDevice {
		dut.SetSockOpt(t, socketFD, unix.SOL_SOCKET, unix.SO_BINDTODEVICE, []byte(dut.Net.RemoteDevName))
	}

	layers := testbench.Layers{
		expectedEthLayer(t, dut, tc, socketFD),
		protocol.ipLayer(),
	}

	conn := protocol.conn(t, dut.Net)
	defer conn.Close(t)

	for name, payload := range map[string][]byte{
		"empty":    nil,
		"small":    []byte("hello world"),
		"random1k": testbench.GenerateRandomPayload(t, 1<<10),
		// Even though ICMP allows larger datagrams we don't test it here as
		// they need to be fragmented and written out as individual frames.
	} {
		t.Run(name, func(t *testing.T) {
			runTc(t, dut, conn, socketFD, tc, layers, port, payload, protocol)
		})
	}
}
