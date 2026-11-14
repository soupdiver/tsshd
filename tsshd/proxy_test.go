/*
MIT License

Copyright (c) 2024-2026 The Trzsz SSH Authors.

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.
*/

package tsshd

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"strconv"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

type kcpStartupFrontend struct {
	frontendConnection
	t *testing.T
}

func (c *kcpStartupFrontend) start(proxy *serverProxy) {
	// A frontend can authenticate a client as soon as start is called,
	// before initServer has created the KCP listener.
	require.NotNil(c.t, proxy.kcpCrypto)
	client, err := proxy.newClientState(1)
	require.NoError(c.t, err)
	crypto := client.kcpCrypto.Load()
	require.NotNil(c.t, crypto)
	require.Equal(c.t, proxy.kcpCrypto.keyPass, crypto.keyPass)
	require.Equal(c.t, proxy.kcpCrypto.keySalt, crypto.keySalt)
}

func TestKCP_CryptoReadyBeforeFrontendStart(t *testing.T) {
	info := &ServerInfo{}
	proxy, err := startServerProxy(&tsshdArgs{KCP: true, Attachable: true}, info, &kcpStartupFrontend{t: t})
	require.NoError(t, err)
	require.Equal(t, kUdpModeKCP, info.Mode)
	require.Equal(t, fmt.Sprintf("%x", proxy.kcpCrypto.keyPass), info.Pass)
	require.Equal(t, fmt.Sprintf("%x", proxy.kcpCrypto.keySalt), info.Salt)
}

type echoServer struct {
	t *testing.T
}

func (m *echoServer) handleStream(stream Stream) {
	buf := make([]byte, 4096)
	for {
		n, err := stream.Read(buf)
		if err != nil {
			if !IsClosedError(err) {
				m.t.Fatalf("server read failed: %v", err)
			}
			return
		}
		if _, err := stream.Write(buf[:n]); err != nil {
			m.t.Fatalf("server write failed: %v", err)
			return
		}
	}
}

func runStreamEchoTest(t *testing.T, stream Stream) {
	for size := 1; size <= 2000; size += 3 {

		send := make([]byte, size)
		for i := range send {
			send[i] = byte(i)
		}

		_, err := stream.Write(send)
		if err != nil {
			t.Fatalf("client write failed: %v", err)
		}

		recv := make([]byte, size)

		_, err = io.ReadFull(stream, recv)
		if err != nil {
			t.Fatalf("client read failed: %v", err)
		}

		if !bytes.Equal(send, recv) {
			t.Fatalf("echo mismatch size=%d", size)
		}
	}
}

// startProxyEchoServer starts an echo server for the test.
func startProxyEchoServer(t *testing.T, args *tsshdArgs) *ServerInfo {
	oriNew := newSshUdpServer
	t.Cleanup(func() {
		newSshUdpServer = oriNew
		cleanupOnExit()
	})

	server := &echoServer{t}
	newSshUdpServer = func(args *tsshdArgs, proxy *serverProxy, addr net.Addr, proto protocolServer) streamHandler {
		return server
	}

	_, output, err := initServer(args)
	if err != nil {
		t.Fatalf("init server failed: %v", err)
	}

	var info ServerInfo
	if err := json.Unmarshal([]byte(output), &info); err != nil {
		t.Fatalf("json unmarshal failed: %v", err)
	}
	return &info
}

func newProxyEchoOptions(args *tsshdArgs, info *ServerInfo, host string) *UdpClientOptions {
	return &UdpClientOptions{
		TsshdAddr:        net.JoinHostPort(host, strconv.Itoa(info.Port)),
		ServerInfo:       info,
		ConnectTimeout:   args.ConnectTimeout,
		HeartbeatTimeout: 3 * time.Second,
	}
}

func runProxyEchoTest(t *testing.T, args *tsshdArgs, host string) {
	info := startProxyEchoServer(t, args)
	runProxyEchoClients(t, args, newProxyEchoOptions(args, info, host), nil)
}

// runProxyEchoClients runs the echo test before and after a second renewTransportPath.
func runProxyEchoClients(t *testing.T, args *tsshdArgs, opts *UdpClientOptions, beforeRenew func(*clientProxy)) {
	clientCount := 1
	if args.Attachable {
		clientCount = 3
	}

	var wg sync.WaitGroup

	for range clientCount {
		wg.Go(func() {
			client := &SshUdpClient{activeChecker: newTimeoutChecker(0)}
			proxy, err := startClientProxy(client, opts)
			if err != nil {
				t.Fatalf("start client proxy failed: %v", err)
			}
			defer func() { _ = proxy.Close() }()

			ctx, cancel := context.WithTimeout(context.Background(), opts.ConnectTimeout)
			err = proxy.renewTransportPath(ctx, nil)
			cancel()
			if err != nil {
				t.Fatalf("renew transport path failed: %v", err)
			}

			client.clientProxy = proxy
			ctx, cancel = context.WithTimeout(context.Background(), opts.ConnectTimeout)
			proto, err := newProtoClient(ctx, opts, client)
			cancel()
			if err != nil {
				t.Fatalf("new proto client failed: %v", err)
			}
			defer func() { _ = proto.Close() }()

			ctx, cancel = context.WithTimeout(context.Background(), time.Second)
			stream, err := proto.newStream(ctx)
			cancel()
			if err != nil {
				t.Fatalf("proto new stream failed: %v", err)
			}
			defer func() { _ = stream.Close() }()

			runStreamEchoTest(t, stream)

			if beforeRenew != nil {
				beforeRenew(proxy)
			}
			ctx, cancel = context.WithTimeout(context.Background(), opts.ConnectTimeout)
			err = proxy.renewTransportPath(ctx, nil)
			cancel()
			if err != nil {
				t.Fatalf("renew transport path failed: %v", err)
			}

			runStreamEchoTest(t, stream)
		})
	}

	wg.Wait()
}

func TestProxy(t *testing.T) {
	tests := []struct {
		name       string
		kcp        bool
		tcp        bool
		attachable bool
	}{
		{"QUIC", false, false, false},
		{"QUIC_TCP", false, true, false},
		{"QUIC_Attachable", false, false, true},
		{"QUIC_TCP_Attachable", false, true, true},
		{"KCP", true, false, false},
		{"KCP_TCP", true, true, false},
		{"KCP_Attachable", true, false, true},
		{"KCP_TCP_Attachable", true, true, true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			args := &tsshdArgs{
				KCP:            tt.kcp,
				TCP:            tt.tcp,
				Attachable:     tt.attachable,
				Port:           "31000-65000",
				ConnectTimeout: 3 * time.Second,
			}

			for _, host := range []string{"127.0.0.1", "::1", "localhost"} {
				t.Run(host, func(t *testing.T) {
					skipUnlessUsableHost(t, host)
					runProxyEchoTest(t, args, host)
				})
			}

			// trzsz/trzsz-ssh#258: IPv6 SSH login, IPv4 client.
			t.Run("IPv6SshConnection", func(t *testing.T) {
				t.Setenv("SSH_CONNECTION", "::1 50818 ::1 22")
				info := startProxyEchoServer(t, args)
				opts := newProxyEchoOptions(args, info, "127.0.0.1")
				opts.IPv4 = true
				runProxyEchoClients(t, args, opts, nil)
			})

			t.Run("FirstContactAfterConnectTimeout", func(t *testing.T) {
				idleArgs := *args
				idleArgs.ConnectTimeout = 300 * time.Millisecond
				info := startProxyEchoServer(t, &idleArgs)
				time.Sleep(2 * idleArgs.ConnectTimeout)
				runProxyEchoClients(t, &idleArgs, newProxyEchoOptions(args, info, "127.0.0.1"), nil)
			})

			t.Run("MoveToOtherFamily", func(t *testing.T) {
				skipUnlessBindable(t, "::1")
				info := startProxyEchoServer(t, args)
				network := "udp6"
				if tt.tcp {
					network = "tcp6"
				}
				runProxyEchoClients(t, args, newProxyEchoOptions(args, info, "127.0.0.1"), func(proxy *clientProxy) {
					proxy.serverNet = network
					proxy.serverAddr = net.JoinHostPort("::1", strconv.Itoa(info.Port))
				})
			})
		})
	}
}

// skipUnlessUsableHost skips ::1 without IPv6 and localhost without both families.
func skipUnlessUsableHost(t *testing.T, host string) {
	t.Helper()
	if host == "127.0.0.1" {
		return
	}
	skipUnlessBindable(t, "::1")
	if host == "localhost" {
		ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
		defer cancel()
		ips, err := net.DefaultResolver.LookupNetIP(ctx, "ip", host)
		var has4, has6 bool
		for _, ip := range ips {
			has4 = has4 || ip.Unmap().Is4()
			has6 = has6 || !ip.Unmap().Is4()
		}
		if !has4 || !has6 {
			t.Skipf("%s is not dual-stack: %v, %v", host, ips, err)
		}
	}
}
