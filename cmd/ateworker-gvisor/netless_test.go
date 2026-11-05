//go:build linux

// Copyright 2026 The Agent Substrate Authors
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
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"os"
	"path/filepath"
	"reflect"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/opencontainers/runtime-spec/specs-go"
	"google.golang.org/grpc/codes"

	"go.ate.dev/substrate/internal/apierror"
	"go.ate.dev/substrate/internal/nodepath"
	"go.ate.dev/substrate/internal/ocispec"
	"go.ate.dev/substrate/internal/proto/ateworkerpb"
)

// fakeRunscEnv makes this test binary stand in for runsc port-forward. See
// fakeRunscPortForward.
const fakeRunscEnv = "ATEWORKER_GVISOR_FAKE_RUNSC"

func TestMain(m *testing.M) {
	if os.Getenv(fakeRunscEnv) != "" {
		os.Exit(fakeRunscPortForward(os.Args[1:]))
	}
	os.Exit(m.Run())
}

// fakeRunscPortForward connects to the --stream socket as runsc does, and
// writes the container and port it was given where the sandbox would answer.
// Nothing listens on port 80, which runsc reports by exiting non-zero.
func fakeRunscPortForward(args []string) int {
	i := slices.Index(args, "--stream")
	if i < 0 || len(args) != i+4 {
		fmt.Fprintf(os.Stderr, "unexpected args %q\n", args)
		return 2
	}
	sock, container, port := args[i+1], args[i+2], args[i+3]
	if port == "80" {
		fmt.Fprintln(os.Stderr, "doStream: PortForward: connection was refused")
		return 128
	}
	conn, err := net.Dial("unix", sock)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 1
	}
	defer conn.Close()
	fmt.Fprintf(conn, "%s:%s", container, port)
	return 0
}

// The stream goes to the sandbox through tun2connect's container, with only
// the port of the dialed address, and no host socket access of its own.
func TestPortForwardArgs(t *testing.T) {
	r := &runsc{actorDirs: testActorDirs, flags: mustFlagStore(t)}
	got := r.portForwardArgs("/tmp/pf/stream.sock", 8080)
	want := []string{
		"-global1",
		"-global2",
		"-root", "/node/actors/test-actor-123/runsc-state",
		"port-forward",
		"--stream", "/tmp/pf/stream.sock",
		tun2connectContainerName,
		"8080",
	}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("portForwardArgs() = %v, want %v", got, want)
	}
}

// The dial returns the stream runsc handed to the sandbox, and fails when
// runsc does. Ingress reaches only 80 and the wakeup probe ports, since a
// port on the actor's loopback may be meant for the actor alone.
func TestDialPortForward(t *testing.T) {
	t.Setenv(fakeRunscEnv, "1")
	r := &runsc{
		path:       os.Args[0],
		actorDirs:  &ateworkerpb.ActorDirs{RootDir: t.TempDir()},
		containers: []*ateworkerpb.Container{{Name: "app", WakeupProbe: &ateworkerpb.WakeupProbe{HttpGet: &ateworkerpb.HttpGetAction{Port: 8080, Path: "/"}}}},
		flags:      mustFlagStore(t),
	}
	for _, tc := range []struct {
		name    string
		address string
		want    string
		wantErr string
	}{
		{name: "a wakeup probe port", address: "169.254.17.2:8080", want: tun2connectContainerName + ":8080"},
		{name: "nothing listening", address: "169.254.17.2:80", wantErr: "connection was refused"},
		{name: "a port only the actor reaches", address: "169.254.17.2:9090", wantErr: "cannot reach port 9090"},
		{name: "no port", address: "169.254.17.2", wantErr: "missing port"},
		{name: "port zero", address: "169.254.17.2:0", wantErr: "invalid port"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
			defer cancel()
			conn, err := r.dialPortForward(ctx, "tcp", tc.address)
			if tc.wantErr != "" {
				if err == nil {
					_ = conn.Close()
					t.Fatalf("dialPortForward(%q) succeeded, want an error containing %q", tc.address, tc.wantErr)
				}
				if !strings.Contains(err.Error(), tc.wantErr) {
					t.Errorf("dialPortForward(%q) = %v, want an error containing %q", tc.address, err, tc.wantErr)
				}
				return
			}
			if err != nil {
				t.Fatalf("dialPortForward(%q) = %v", tc.address, err)
			}
			defer conn.Close()
			// gVisor drops the whole stream when the worker's side stops sending.
			if _, ok := conn.(interface{ CloseWrite() error }); ok {
				t.Error("the stream can be half-closed")
			}
			if got, err := io.ReadAll(conn); err != nil || string(got) != tc.want {
				t.Errorf("stream = %q, %v, want %q", got, err, tc.want)
			}
		})
	}
}

func TestWaitTun2connect(t *testing.T) {
	canceled, cancel := context.WithCancel(context.Background())
	cancel()
	for _, tc := range []struct {
		name    string
		ctx     context.Context
		written bool
		timeout time.Duration
		wantErr bool
	}{
		{name: "written", ctx: context.Background(), written: true, timeout: time.Minute},
		{name: "never written", ctx: context.Background(), wantErr: true},
		{name: "canceled", ctx: canceled, timeout: time.Minute, wantErr: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			resolvConf := filepath.Join(t.TempDir(), "resolv.conf")
			if tc.written {
				if err := os.WriteFile(resolvConf, []byte("nameserver 100.127.255.253\n"), 0o644); err != nil {
					t.Fatal(err)
				}
			}
			if err := waitTun2connect(tc.ctx, resolvConf, tc.timeout); (err != nil) != tc.wantErr {
				t.Errorf("waitTun2connect() = %v, want error %v", err, tc.wantErr)
			}
		})
	}
}

// tun2connect's bundle holds a copy of the binary, never the staged asset
// itself, and no resolv.conf from an earlier activation.
func TestStageTun2connect(t *testing.T) {
	t.Setenv("TMPDIR", t.TempDir())
	root := t.TempDir()
	actorDirs := &ateworkerpb.ActorDirs{RootDir: root, OciBundleDir: filepath.Join(root, "bundles")}
	asset := filepath.Join(root, "sandbox-assets", "tun2connect")
	if err := os.MkdirAll(filepath.Dir(asset), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(asset, []byte("tun2connect binary"), 0o555); err != nil {
		t.Fatal(err)
	}
	stale := filepath.Join(tun2connectEtcDir("uid-a"), "resolv.conf")
	if err := os.MkdirAll(filepath.Dir(stale), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(stale, nil, 0o644); err != nil {
		t.Fatal(err)
	}

	// Twice, as a second activation on this worker does.
	for range 2 {
		if err := stageTun2connect("uid-a", actorDirs, asset); err != nil {
			t.Fatalf("stageTun2connect() = %v", err)
		}
	}

	rootfs := filepath.Join(ociBundlePath(actorDirs, tun2connectContainerName), "rootfs")
	binary := filepath.Join(rootfs, "tun2connect")
	if got, err := os.ReadFile(binary); err != nil || string(got) != "tun2connect binary" {
		t.Errorf("rootfs binary = %q, %v, want the asset's content", got, err)
	}
	assetInfo, err := os.Stat(asset)
	if err != nil {
		t.Fatal(err)
	}
	binaryInfo, err := os.Stat(binary)
	if err != nil {
		t.Fatal(err)
	}
	if os.SameFile(assetInfo, binaryInfo) {
		t.Error("the rootfs binary is the staged asset itself, which the node's asset cache shares")
	}
	if binaryInfo.Mode()&0o111 == 0 {
		t.Errorf("rootfs binary mode = %v, want it executable", binaryInfo.Mode())
	}
	for _, d := range []string{"proc", "sys", "dev", "tmp", "etc", "run/tun2connect"} {
		if fi, err := os.Stat(filepath.Join(rootfs, d)); err != nil || !fi.IsDir() {
			t.Errorf("mountpoint %s: %v", d, err)
		}
	}
	if _, err := os.Stat(stale); !os.IsNotExist(err) {
		t.Errorf("stale resolv.conf survived: %v", err)
	}
}

// Unhosting a netless actor drops the egress socket and resolv.conf it kept
// outside the actor dirs.
func TestRemoveTun2connectDir(t *testing.T) {
	t.Setenv("TMPDIR", t.TempDir())
	for _, dir := range []string{tun2connectRunDir("uid-a"), tun2connectEtcDir("uid-a"), tun2connectRunDir("uid-b")} {
		if err := os.MkdirAll(dir, 0o700); err != nil {
			t.Fatal(err)
		}
	}
	removeTun2connectDir(context.Background(), "uid-a")
	if _, err := os.Stat(tun2connectDir("uid-a")); !os.IsNotExist(err) {
		t.Errorf("uid-a's directory survived: %v", err)
	}
	if _, err := os.Stat(tun2connectDir("uid-b")); err != nil {
		t.Errorf("another actor's directory is gone: %v", err)
	}
}

// tun2connect gets a read-only rootfs, the two host directories it needs, and
// the capabilities to set up tun0. runsc supplies /dev/net/tun itself.
func TestWriteTun2connectSpec(t *testing.T) {
	t.Setenv("TMPDIR", t.TempDir())
	root := t.TempDir()
	actorDirs := &ateworkerpb.ActorDirs{RootDir: root, OciBundleDir: filepath.Join(root, "bundles")}
	if err := os.MkdirAll(ociBundlePath(actorDirs, tun2connectContainerName), 0o700); err != nil {
		t.Fatal(err)
	}
	r := &runsc{actorUID: "uid-a", actorDirs: actorDirs}
	if err := r.writeSpec(tun2connectContainerName); err != nil {
		t.Fatalf("writeSpec() = %v", err)
	}
	b, err := os.ReadFile(filepath.Join(ociBundlePath(actorDirs, tun2connectContainerName), "config.json"))
	if err != nil {
		t.Fatal(err)
	}
	var spec specs.Spec
	if err := json.Unmarshal(b, &spec); err != nil {
		t.Fatal(err)
	}
	if want := []string{"/tun2connect", "run", "unix:///run/tun2connect/egress.sock"}; !slices.Equal(spec.Process.Args, want) {
		t.Errorf("args = %q, want %q", spec.Process.Args, want)
	}
	if !spec.Root.Readonly {
		t.Error("tun2connect's rootfs is writable")
	}
	if got := spec.Annotations["io.kubernetes.cri.sandbox-id"]; got != ocispec.SandboxID {
		t.Errorf("sandbox-id annotation = %q, want %q", got, ocispec.SandboxID)
	}
	if got := spec.Process.Capabilities.Bounding; !slices.Equal(got, []string{"CAP_NET_ADMIN", "CAP_SETPCAP"}) {
		t.Errorf("bounding capabilities = %v, want CAP_NET_ADMIN and CAP_SETPCAP", got)
	}
	binds := map[string]string{}
	for _, m := range spec.Mounts {
		if m.Type == "bind" {
			binds[m.Destination] = m.Source
		}
	}
	if want := map[string]string{"/run/tun2connect": tun2connectRunDir("uid-a"), "/etc": tun2connectEtcDir("uid-a")}; !reflect.DeepEqual(binds, want) {
		t.Errorf("bind mounts = %v, want %v", binds, want)
	}
	// Every worker on the node shares the actor dirs, and the egress socket
	// carries the actor's egress identity.
	for dest, src := range binds {
		if strings.HasPrefix(src, root) {
			t.Errorf("%s is bound from %s, in the actor dirs other workers share", dest, src)
		}
	}
}

// Only a netless pool's SandboxConfig has tun2connect, so a worker refuses a
// request whose assets do not match its --netless.
func TestTun2connectBinary(t *testing.T) {
	orig := nodepath.ActorsDir
	nodepath.ActorsDir = t.TempDir()
	t.Cleanup(func() { nodepath.ActorsDir = orig })
	dir := nodepath.ActorSandboxAssetsDir("actor-a")
	if err := os.MkdirAll(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	staged := filepath.Join(dir, "tun2connect")
	if err := os.WriteFile(staged, nil, 0o555); err != nil {
		t.Fatal(err)
	}
	actorDirs := &ateworkerpb.ActorDirs{SandboxAssetsDir: dir}
	for _, tc := range []struct {
		name     string
		netless  bool
		assets   map[string]string
		want     string
		wantCode codes.Code
	}{
		{name: "netless with the asset", netless: true, assets: map[string]string{"tun2connect": staged}, want: staged},
		{name: "netless without the asset", netless: true, wantCode: codes.FailedPrecondition},
		{name: "netless with an asset outside the actor's dir", netless: true, assets: map[string]string{"tun2connect": "/bin/sh"}, wantCode: codes.InvalidArgument},
		{name: "with a network card", assets: map[string]string{"gvisor": filepath.Join(dir, "runsc")}},
		{name: "with a network card and the asset", assets: map[string]string{"tun2connect": staged}, wantCode: codes.FailedPrecondition},
	} {
		t.Run(tc.name, func(t *testing.T) {
			s := &AteWorkerService{netless: tc.netless}
			got, err := s.tun2connectBinary("actor-a", actorDirs, tc.assets)
			if apierror.Code(err) != tc.wantCode || got != tc.want {
				t.Errorf("tun2connectBinary() = %q, %v; want %q, code %v", got, err, tc.want, tc.wantCode)
			}
		})
	}
}

// A netless actor's containers ask tun2connect for every name.
func TestWriteRootfsEtcFiles(t *testing.T) {
	for _, tc := range []struct {
		name    string
		netless bool
		want    string
	}{
		{name: "netless", netless: true, want: "nameserver 100.127.255.253\n"},
		{name: "with a network card", want: "nameserver 169.254.17.1\n"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			rootfs := t.TempDir()
			if err := writeRootfsEtcFiles(rootfs, tc.netless); err != nil {
				t.Fatalf("writeRootfsEtcFiles() = %v", err)
			}
			got, err := os.ReadFile(filepath.Join(rootfs, "etc", "resolv.conf"))
			if err != nil {
				t.Fatal(err)
			}
			if !strings.HasPrefix(string(got), tc.want) {
				t.Errorf("resolv.conf = %q, want it to start with %q", got, tc.want)
			}
		})
	}
}
