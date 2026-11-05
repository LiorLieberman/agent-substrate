//go:build linux

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

package kata

import (
	"bufio"
	"bytes"
	"context"
	"errors"
	"io"
	"net"
	"path/filepath"
	"testing"
	"time"

	"github.com/containerd/ttrpc"
	"go.ate.dev/substrate/cmd/ateworker-microvm/internal/third_party/kata/agentpb"
	"google.golang.org/protobuf/types/known/emptypb"
)

// startFakeAgent serves grpc.AgentService/ReseedRandomDev with handle and returns
// a client connected to it.
func startFakeAgent(t *testing.T, handle func(*agentpb.ReseedRandomDevRequest) error) *AgentClient {
	t.Helper()
	sock := filepath.Join(t.TempDir(), "agent.sock")
	l, err := net.Listen("unix", sock)
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	srv, err := ttrpc.NewServer()
	if err != nil {
		t.Fatalf("ttrpc.NewServer: %v", err)
	}
	srv.Register("grpc.AgentService", map[string]ttrpc.Method{
		"ReseedRandomDev": func(_ context.Context, unmarshal func(interface{}) error) (interface{}, error) {
			var req agentpb.ReseedRandomDevRequest
			if err := unmarshal(&req); err != nil {
				return nil, err
			}
			if err := handle(&req); err != nil {
				return nil, err
			}
			return &emptypb.Empty{}, nil
		},
	})
	go func() { _ = srv.Serve(context.Background(), l) }()
	t.Cleanup(func() { _ = srv.Close() })

	conn, err := net.Dial("unix", sock)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	ac := &AgentClient{conn: conn, client: ttrpc.NewClient(conn)}
	t.Cleanup(func() { _ = ac.Close() })
	return ac
}

// The restore path fails when this call fails, so a wrong service or method name
// here would fail every micro-VM restore.
func TestReseedRandomDevSendsData(t *testing.T) {
	got := make(chan []byte, 1)
	ac := startFakeAgent(t, func(req *agentpb.ReseedRandomDevRequest) error {
		got <- req.GetData()
		return nil
	})

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	want := []byte("per-restore nonce")
	if err := ac.ReseedRandomDev(ctx, want); err != nil {
		t.Fatalf("ReseedRandomDev: %v", err)
	}
	select {
	case data := <-got:
		if !bytes.Equal(data, want) {
			t.Errorf("agent got data %q, want %q", data, want)
		}
	default:
		t.Fatal("agent never received ReseedRandomDev")
	}
}

func TestReseedRandomDevReturnsAgentError(t *testing.T) {
	ac := startFakeAgent(t, func(*agentpb.ReseedRandomDevRequest) error {
		return errors.New("reseed refused")
	})

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := ac.ReseedRandomDev(ctx, []byte("nonce")); err == nil {
		t.Fatal("ReseedRandomDev returned nil for an agent error, want the error")
	}
}

// serveHybridVsock answers one hybrid-vsock CONNECT on a fresh socket with
// reply, then writes after, and returns the socket's path.
func serveHybridVsock(t *testing.T, reply, after string) string {
	t.Helper()
	sock := filepath.Join(t.TempDir(), "clh.sock")
	l, err := net.Listen("unix", sock)
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	t.Cleanup(func() { _ = l.Close() })
	go func() {
		conn, err := l.Accept()
		if err != nil {
			return
		}
		defer conn.Close()
		if _, err := bufio.NewReader(conn).ReadString('\n'); err != nil {
			return
		}
		_, _ = io.WriteString(conn, reply+after)
	}()
	return sock
}

// What the guest sends right after the VMM's reply is the caller's: the
// ingress answer from tun2connect can arrive in the same read as the OK.
func TestDialVsockKeepsTheStreamAfterTheReply(t *testing.T) {
	sock := serveHybridVsock(t, "OK 1073741825\n", "HTTP/1.1 200 OK\r\n\r\n")
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	conn, err := DialVsock(ctx, sock, 1028)
	if err != nil {
		t.Fatalf("DialVsock: %v", err)
	}
	defer conn.Close()
	got, err := io.ReadAll(conn)
	if err != nil || string(got) != "HTTP/1.1 200 OK\r\n\r\n" {
		t.Errorf("stream after the reply = %q, %v, want the guest's bytes", got, err)
	}
}
