// Copyright 2026 Google LLC
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

package egress

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestAcceptConnect(t *testing.T) {
	tests := []struct {
		name    string
		request string
		// want is the destination, or "" when the request is refused.
		want string
		// wantStatus is the line a refused producer reads, if any.
		wantStatus string
	}{
		{
			name:    "hostname",
			request: "CONNECT API.Example.com.:443 HTTP/1.1\r\nHost: API.Example.com.:443\r\n\r\n",
			want:    "api.example.com:443",
		},
		{
			name:    "ipv6 literal",
			request: "CONNECT [2001:db8::1]:8443 HTTP/1.1\r\nHost: [2001:db8::1]:8443\r\n\r\n",
			want:    "[2001:db8::1]:8443",
		},
		{
			name:       "connect-udp",
			request:    "GET /.well-known/masque/udp/example.com/443/ HTTP/1.1\r\nHost: atunnel\r\nConnection: Upgrade\r\nUpgrade: connect-udp\r\n\r\n",
			wantStatus: "HTTP/1.1 405 Method Not Allowed",
		},
		{
			name:       "link-local address",
			request:    "CONNECT 169.254.169.254:80 HTTP/1.1\r\nHost: 169.254.169.254:80\r\n\r\n",
			wantStatus: "HTTP/1.1 403 Forbidden",
		},
		{
			name:       "ipv6 link-local address",
			request:    "CONNECT [fe80::1]:443 HTTP/1.1\r\nHost: [fe80::1]:443\r\n\r\n",
			wantStatus: "HTTP/1.1 403 Forbidden",
		},
		{
			name:       "loopback address",
			request:    "CONNECT 127.0.0.1:8080 HTTP/1.1\r\nHost: 127.0.0.1:8080\r\n\r\n",
			wantStatus: "HTTP/1.1 403 Forbidden",
		},
		{
			name:       "authority without a port",
			request:    "CONNECT example.com HTTP/1.1\r\nHost: example.com\r\n\r\n",
			wantStatus: "HTTP/1.1 400 Bad Request",
		},
		{
			name:       "head too large",
			request:    "CONNECT example.com:443 HTTP/1.1\r\nX-Padding: " + strings.Repeat("a", maxConnectHead) + "\r\n\r\n",
			wantStatus: "HTTP/1.1 431 Request Header Fields Too Large",
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			producer, proxy := net.Pipe()
			defer producer.Close()
			// The pipe has no buffer, and a head that is too large is never
			// read to the end, so write and read on their own.
			go func() { _, _ = io.WriteString(producer, tc.request+"early bytes") }()
			answer := make(chan string, 1)
			go func() {
				all, _ := io.ReadAll(producer)
				answer <- string(all)
			}()

			conn, destination, reply, err := acceptConnect(context.Background(), proxy)
			if tc.want == "" {
				if err == nil {
					t.Fatalf("acceptConnect() = %q, want a refusal", destination)
				}
				_ = proxy.Close()
				got := receiveWithin(t, answer, "the refusal")
				if !strings.HasPrefix(got, tc.wantStatus) {
					t.Errorf("producer read %q, want it to start with %q", got, tc.wantStatus)
				}
				return
			}
			if err != nil {
				t.Fatalf("acceptConnect() error = %v", err)
			}
			if destination != tc.want {
				t.Errorf("destination = %q, want %q", destination, tc.want)
			}
			early := make([]byte, len("early bytes"))
			if _, err := io.ReadFull(conn, early); err != nil || string(early) != "early bytes" {
				t.Errorf("tunnel data after the head = %q, %v, want %q", early, err, "early bytes")
			}
			if err := reply(nil); err != nil {
				t.Fatal(err)
			}
			_ = proxy.Close()
			if got := receiveWithin(t, answer, "the answer"); got != "HTTP/1.1 200 Connection Established\r\n\r\n" {
				t.Errorf("producer read %q, want the 200", got)
			}
		})
	}
}

func TestConnectStatus(t *testing.T) {
	tests := []struct {
		name       string
		err        error
		wantCode   int
		wantStatus string
	}{
		{
			name:       "gateway refusal",
			err:        fmt.Errorf("opening: %w", &ConnectRejectedError{StatusCode: http.StatusForbidden}),
			wantCode:   http.StatusForbidden,
			wantStatus: "atunnel; received-status=403",
		},
		{
			name:       "no answer in time",
			err:        fmt.Errorf("opening: %w", context.DeadlineExceeded),
			wantCode:   http.StatusGatewayTimeout,
			wantStatus: "atunnel; error=connection_timeout",
		},
		{
			name:       "anything else",
			err:        errors.New("connection reset"),
			wantCode:   http.StatusBadGateway,
			wantStatus: "atunnel; error=proxy_internal_error",
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			code, status := connectStatus(tc.err)
			if code != tc.wantCode || status != tc.wantStatus {
				t.Errorf("connectStatus() = %d, %q, want %d, %q", code, status, tc.wantCode, tc.wantStatus)
			}
		})
	}
}

// A producer's CONNECT names the destination, which goes to the gateway as is,
// and the producer reads the gateway's answer.
func TestEgressConnectEndToEnd(t *testing.T) {
	tests := []struct {
		name     string
		gateway  string
		wantLine string
	}{
		{name: "allowed", gateway: "HTTP/1.1 200 Connection Established\r\n\r\n", wantLine: "HTTP/1.1 200 Connection Established"},
		{name: "refused", gateway: "HTTP/1.1 403 Forbidden\r\nContent-Length: 13\r\n\r\negress denied", wantLine: "HTTP/1.1 403 Forbidden"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			ca := newTestCA(t)
			requests := make(chan *http.Request, 1)
			gatewayAddress := serveTestConnectGateway(t, ca, func(conn net.Conn, req *http.Request) {
				requests <- req
				if _, err := io.WriteString(conn, tc.gateway); err != nil {
					t.Errorf("writing CONNECT response: %v", err)
				}
			})
			client := newTestClient(t, ca, withDialer(dialFixedAddress(gatewayAddress)))
			egress, err := New(func(net.Conn) (string, error) {
				t.Error("a CONNECT stream asked for its original destination")
				return "", nil
			})
			if err != nil {
				t.Fatal(err)
			}
			if err := egress.Activate(testActorUID, client, fakeActorCertificateSource{expiresAt: time.Now().Add(time.Hour)}, time.Now().Add(time.Hour)); err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() { _ = egress.Deactivate(context.Background(), testActorUID) })

			producer, proxy := net.Pipe()
			defer producer.Close()
			if err := producer.SetDeadline(time.Now().Add(5 * time.Second)); err != nil {
				t.Fatal(err)
			}
			egress.mu.Lock()
			active := egress.active[testActorUID]
			egress.mu.Unlock()
			egress.handle(proxy, active, acceptConnect)

			if _, err := io.WriteString(producer, "CONNECT api.example.com:443 HTTP/1.1\r\nHost: api.example.com:443\r\n\r\n"); err != nil {
				t.Fatal(err)
			}
			req := receiveWithin(t, requests, "gateway CONNECT request")
			if req.Method != http.MethodConnect || req.Host != "api.example.com:443" {
				t.Errorf("gateway request = %s %s, want CONNECT api.example.com:443", req.Method, req.Host)
			}
			line, err := bufio.NewReader(producer).ReadString('\n')
			if err != nil {
				t.Fatal(err)
			}
			if got := strings.TrimSpace(line); got != tc.wantLine {
				t.Errorf("producer read %q, want %q", got, tc.wantLine)
			}
		})
	}
}

// A producer that never sends its CONNECT does not hold up Deactivate.
func TestEgressDeactivateClosesSilentConnectStream(t *testing.T) {
	egress, err := New(func(net.Conn) (string, error) { return "", errors.New("not redirected") })
	if err != nil {
		t.Fatal(err)
	}
	dialer := tunnelDialerFunc(func(context.Context, string) (net.Conn, error) {
		t.Error("a stream that named no destination was dialed")
		return nil, errors.New("unexpected dial")
	})
	if err := egress.Activate(testActorUID, dialer, fakeActorCertificateSource{expiresAt: time.Now().Add(time.Hour)}, time.Now().Add(time.Hour)); err != nil {
		t.Fatal(err)
	}
	producer, proxy := net.Pipe()
	defer producer.Close()
	egress.mu.Lock()
	active := egress.active[testActorUID]
	egress.mu.Unlock()
	egress.handle(proxy, active, acceptConnect)

	ctx, cancel := context.WithTimeout(context.Background(), connectHeadTimeout/2)
	defer cancel()
	if err := egress.Deactivate(ctx, testActorUID); err != nil {
		t.Errorf("Deactivate() = %v, want nil before the CONNECT head times out", err)
	}
	if _, err := producer.Read(make([]byte, 1)); !errors.Is(err, io.EOF) {
		t.Errorf("reading the producer's stream = %v, want it closed (EOF)", err)
	}
}

// Deactivating the actor's egress closes the CONNECT listener, and leaves its
// socket file, which may already be the next activation's.
func TestServeConnectStopsWithTheActivation(t *testing.T) {
	egress, err := New(func(net.Conn) (string, error) { return "", errors.New("not redirected") })
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), "clh.sock_1027")
	if err := egress.ServeConnect(context.Background(), testActorUID, path); err != nil {
		t.Fatalf("ServeConnect() error = %v", err)
	}
	conn, err := net.Dial("unix", path)
	if err != nil {
		t.Fatalf("dialing the listener: %v", err)
	}
	_ = conn.Close()

	if err := egress.Deactivate(context.Background(), testActorUID); err != nil {
		t.Fatal(err)
	}
	deadline := time.Now().Add(5 * time.Second)
	for {
		conn, err := net.Dial("unix", path)
		if err != nil {
			break
		}
		_ = conn.Close()
		if time.Now().After(deadline) {
			t.Fatal("the listener still accepts after the activation ended")
		}
		time.Sleep(10 * time.Millisecond)
	}
	if _, err := os.Stat(path); err != nil {
		t.Errorf("the socket file is gone after the listener closed: %v", err)
	}
}
