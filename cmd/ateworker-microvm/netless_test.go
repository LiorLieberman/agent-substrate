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

package main

import (
	"bufio"
	"context"
	"io"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"go.ate.dev/substrate/internal/proto/ateworkerpb"
)

func probedContainer(port int32) *ateworkerpb.Container {
	return &ateworkerpb.Container{WakeupProbe: &ateworkerpb.WakeupProbe{HttpGet: &ateworkerpb.HttpGetAction{Port: port, Path: "/"}}}
}

// Ingress reaches the default port and every wakeup probe port, each once.
func TestTun2connectIngressPorts(t *testing.T) {
	got := tun2connectIngressPorts([]*ateworkerpb.Container{
		probedContainer(8080),
		{},
		probedContainer(80),
		probedContainer(8080),
		probedContainer(9090),
	})
	if want := []uint32{80, 8080, 9090}; !slices.Equal(got, want) {
		t.Errorf("tun2connectIngressPorts() = %v, want %v", got, want)
	}
}

func TestTun2connectArgs(t *testing.T) {
	got := strings.Join(tun2connectArgs([]uint32{80, 8080}), " ")
	want := "/tun2connect run -ingress-socket vsock://1028 -ingress-port 80,8080 vsock://2:1027"
	if got != want {
		t.Errorf("tun2connectArgs() = %q, want %q", got, want)
	}
}

// serveTun2connectIngress plays the VMM and tun2connect for one ingress stream,
// answering its CONNECT with answer. It returns the socket and the CONNECT read.
func serveTun2connectIngress(t *testing.T, answer string) (string, <-chan string) {
	t.Helper()
	sock := filepath.Join(t.TempDir(), "clh.sock")
	l, err := net.Listen("unix", sock)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = l.Close() })
	requests := make(chan string, 1)
	go func() {
		conn, err := l.Accept()
		if err != nil {
			return
		}
		defer conn.Close()
		reader := bufio.NewReader(conn)
		if line, err := reader.ReadString('\n'); err != nil || line != "CONNECT 1028\n" {
			return
		}
		if _, err := io.WriteString(conn, "OK 1073741825\n"); err != nil {
			return
		}
		req, err := http.ReadRequest(reader)
		if err != nil {
			return
		}
		requests <- req.Method + " " + req.Host
		_, _ = io.WriteString(conn, answer)
	}()
	return sock, requests
}

func receiveRequest(t *testing.T, requests <-chan string) string {
	t.Helper()
	select {
	case req := <-requests:
		return req
	case <-time.After(5 * time.Second):
		t.Fatal("tun2connect never got the CONNECT")
		return ""
	}
}

// The stream to the actor's port carries what came with tun2connect's answer.
func TestDialTun2connectIngress(t *testing.T) {
	sock, requests := serveTun2connectIngress(t, "HTTP/1.1 200 OK\r\n\r\nfrom the actor")
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	conn, resp, err := dialTun2connectIngress(ctx, sock, 8080)
	if err != nil {
		t.Fatalf("dialTun2connectIngress() error = %v", err)
	}
	defer conn.Close()
	if resp.StatusCode != http.StatusOK {
		t.Errorf("status = %d, want 200", resp.StatusCode)
	}
	if got := receiveRequest(t, requests); got != "CONNECT 127.0.0.1:8080" {
		t.Errorf("tun2connect got %q, want CONNECT 127.0.0.1:8080", got)
	}
	if got, err := io.ReadAll(conn); err != nil || string(got) != "from the actor" {
		t.Errorf("stream = %q, %v, want what came with the answer", got, err)
	}
}

// Any answer means tun2connect is up, including a 502 for a port nothing
// listens on yet.
func TestWaitTun2connectTakesAnyAnswer(t *testing.T) {
	sock, _ := serveTun2connectIngress(t, "HTTP/1.1 502 Bad Gateway\r\nContent-Length: 0\r\n\r\n")
	if err := waitTun2connect(context.Background(), sock, 80, 5*time.Second); err != nil {
		t.Errorf("waitTun2connect() error = %v, want nil", err)
	}
}

func TestCheckSnapshotNetwork(t *testing.T) {
	tests := []struct {
		name    string
		netless bool
		devices int
		wantErr bool
	}{
		{name: "netless worker, netless snapshot", netless: true},
		{name: "netless worker, snapshot with a network device", netless: true, devices: 1, wantErr: true},
		{name: "worker with network devices", devices: 1},
		{name: "worker with network devices, netless snapshot", wantErr: true},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			s := &AteWorkerService{netless: tc.netless}
			if err := s.checkSnapshotNetwork(tc.devices); (err != nil) != tc.wantErr {
				t.Errorf("checkSnapshotNetwork(%d) error = %v, want error %v", tc.devices, err, tc.wantErr)
			}
		})
	}
}

func TestCheckTun2connectAsset(t *testing.T) {
	tests := []struct {
		name    string
		netless bool
		asset   string
		wantErr bool
	}{
		{name: "netless worker with the asset", netless: true, asset: "/assets/tun2connect"},
		{name: "netless worker without it", netless: true, wantErr: true},
		{name: "worker with network devices"},
		{name: "worker with network devices, given the asset", asset: "/assets/tun2connect", wantErr: true},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			s := &AteWorkerService{netless: tc.netless}
			if err := s.checkTun2connectAsset(resolvedRuntime{tun2connect: tc.asset}); (err != nil) != tc.wantErr {
				t.Errorf("checkTun2connectAsset() error = %v, want error %v", err, tc.wantErr)
			}
		})
	}
}

// The guest gets its own copy of tun2connect: the staged file links into the
// node's asset cache.
func TestCopyFile(t *testing.T) {
	dir := t.TempDir()
	src := filepath.Join(dir, "staged")
	if err := os.WriteFile(src, []byte("binary"), 0o644); err != nil {
		t.Fatal(err)
	}
	dst := filepath.Join(dir, "tun2connect")
	if err := copyFile(src, dst); err != nil {
		t.Fatalf("copyFile() error = %v", err)
	}
	srcInfo, err := os.Stat(src)
	if err != nil {
		t.Fatal(err)
	}
	dstInfo, err := os.Stat(dst)
	if err != nil {
		t.Fatal(err)
	}
	if os.SameFile(srcInfo, dstInfo) {
		t.Error("the copy is the staged file itself")
	}
	if got := dstInfo.Mode().Perm(); got&0o100 == 0 {
		t.Errorf("copy mode = %v, want it executable", got)
	}
	if got, err := os.ReadFile(dst); err != nil || string(got) != "binary" {
		t.Errorf("copy holds %q, %v, want the staged bytes", got, err)
	}
	if err := copyFile(src, dst); err == nil {
		t.Error("copyFile() over an existing file succeeded, want an error")
	}
}
