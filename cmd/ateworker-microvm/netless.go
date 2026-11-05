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
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"time"

	specs "github.com/opencontainers/runtime-spec/specs-go"

	"go.ate.dev/substrate/cmd/ateworker-microvm/internal/kata"
	"go.ate.dev/substrate/internal/ocispec"
	"go.ate.dev/substrate/internal/proto/ateworkerpb"
)

// A guest restored from a MEMORY snapshot keeps the ports, container ID and
// rootfs layout it booted with, so they cannot change between releases.
const (
	// tun2connectEgressPort is the host vsock port tun2connect, the in-guest
	// producer of a netless actor, sends each of the actor's connections to.
	tun2connectEgressPort = 1027
	// tun2connectIngressPort is the guest vsock port tun2connect serves ingress
	// on. Guest ports 1024 and 1026 are the kata-agent's.
	tun2connectIngressPort = 1028
	// tun2connectContainerID is tun2connect's container in the guest. It cannot
	// collide with an actor container's, which GuestContainerID prefixes.
	tun2connectContainerID = "tun2connect"
	// tun2connectLogName names tun2connect in the actor's logs. '_' cannot
	// appear in a container name, so it cannot be one of the actor's.
	tun2connectLogName = "_tun2connect"
	// defaultIngressPort is the actor port ingress reaches when a request
	// names none.
	defaultIngressPort = 80
)

// tun2connectEgressSocketPath is where Cloud Hypervisor delivers the guest's
// connections to tun2connectEgressPort.
func tun2connectEgressSocketPath(actorUID string) string {
	return fmt.Sprintf("%s_%d", kata.VsockSocketPath(actorUID), tun2connectEgressPort)
}

// serveTun2connectEgress serves tun2connect's connections through the actor's
// egress until it is deactivated. Call it once the VM dir is recreated.
func (s *AteWorkerService) serveTun2connectEgress(ctx context.Context, actorUID string) error {
	return s.tunnel.Egress.ServeConnect(ctx, actorUID, tun2connectEgressSocketPath(actorUID))
}

// tun2connectIngressPorts are the ports ingress may reach: the default one and
// each wakeup probe's. tun2connect takes no range, so others are out of reach.
func tun2connectIngressPorts(containers []*ateworkerpb.Container) []uint32 {
	ports := []uint32{defaultIngressPort}
	for _, c := range containers {
		if port := c.GetWakeupProbe().GetHttpGet().GetPort(); port > 0 && !slices.Contains(ports, uint32(port)) {
			ports = append(ports, uint32(port))
		}
	}
	return ports
}

// tun2connectArgs are tun2connect's arguments as a sidecar to the actor.
func tun2connectArgs(ingressPorts []uint32) []string {
	ports := make([]string, len(ingressPorts))
	for i, port := range ingressPorts {
		ports[i] = strconv.Itoa(int(port))
	}
	return []string{
		"/tun2connect", "run",
		"-ingress-socket", fmt.Sprintf("vsock://%d", tun2connectIngressPort),
		"-ingress-port", strings.Join(ports, ","),
		fmt.Sprintf("vsock://2:%d", tun2connectEgressPort),
	}
}

// stageTun2connectRootfs lays out tun2connect's rootfs and binds it read-only
// into the share. Like every bind, it must come before virtiofsd starts.
func stageTun2connectRootfs(ctx context.Context, binary, id string, actorDirs *ateworkerpb.ActorDirs) error {
	dir := tun2connectRootfsDir(actorDirs)
	if err := os.RemoveAll(dir); err != nil {
		return fmt.Errorf("while clearing tun2connect's rootfs: %w", err)
	}
	for _, d := range []string{"proc", "sys", "dev", "tmp", "etc"} {
		if err := os.MkdirAll(filepath.Join(dir, d), 0o755); err != nil {
			return fmt.Errorf("while creating tun2connect's rootfs: %w", err)
		}
	}
	// Copied: the staged binary is a link into the node's asset cache, which
	// every actor on the node runs from.
	if err := copyFile(binary, filepath.Join(dir, "tun2connect")); err != nil {
		return fmt.Errorf("while staging the tun2connect binary: %w", err)
	}
	rel := filepath.Join(tun2connectContainerID, "rootfs")
	if err := kata.BindIntoShare(ctx, dir, id, rel); err != nil {
		return err
	}
	return kata.RemountReadOnly(filepath.Join(kata.SharedDir(id), rel))
}

// removeTun2connectRootfs drops tun2connect's rootfs once its bind is gone.
func removeTun2connectRootfs(ctx context.Context, actorDirs *ateworkerpb.ActorDirs) {
	if err := os.RemoveAll(tun2connectRootfsDir(actorDirs)); err != nil {
		slog.WarnContext(ctx, "Failed to remove tun2connect's rootfs", slog.Any("err", err))
	}
}

// copyFile copies src to a new executable file at dst.
func copyFile(src, dst string) error {
	in, err := os.Open(src)
	if err != nil {
		return err
	}
	defer in.Close()
	out, err := os.OpenFile(dst, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o755)
	if err != nil {
		return err
	}
	_, err = io.Copy(out, in)
	return errors.Join(err, out.Close())
}

// startTun2connect starts tun2connect in the guest and waits until it serves,
// so the actor's containers that start next have a network.
func (s *AteWorkerService) startTun2connect(ctx context.Context, ac *kata.AgentClient, actorUID, vsockPath string, ingressPorts []uint32) error {
	spec := ocispec.Tun2connect(actorUID, tun2connectArgs(ingressPorts))
	// Its rootfs is read-only, and it writes its own resolv.conf.
	spec.Mounts = append(spec.Mounts, specs.Mount{Destination: "/etc", Type: "tmpfs", Source: "tmpfs", Options: []string{"nosuid", "nodev", "noexec", "mode=755"}})
	if err := ocispec.ShapeMicroVM(spec, ocispec.MicroVMOptions{}); err != nil {
		return fmt.Errorf("while shaping tun2connect's spec: %w", err)
	}
	ocispec.AddTUNDevice(spec)
	cCtx, cancel := context.WithTimeout(ctx, 30*time.Second)
	err := ac.StartRootfsContainer(cCtx, tun2connectContainerID, spec)
	cancel()
	if err != nil {
		return fmt.Errorf("while starting tun2connect: %w", err)
	}
	return waitTun2connect(ctx, vsockPath, ingressPorts[0], 20*time.Second)
}

// waitTun2connect waits until tun2connect answers on its ingress. It serves
// there only once its device, routes and DNS are up.
func waitTun2connect(ctx context.Context, vsockPath string, port uint32, timeout time.Duration) error {
	deadline := time.Now().Add(timeout)
	for {
		conn, _, err := dialTun2connectIngress(ctx, vsockPath, port)
		if err == nil {
			// Any answer will do: a 502 only says nothing listens on port yet.
			_ = conn.Close()
			return nil
		}
		if time.Now().After(deadline) {
			return fmt.Errorf("tun2connect did not come up within %v: %w", timeout, err)
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(20 * time.Millisecond):
		}
	}
}

// dialTun2connectIngress asks tun2connect for a stream to port on the guest's
// loopback. The stream carries data only if the answer is a 2xx.
func dialTun2connectIngress(ctx context.Context, vsockPath string, port uint32) (net.Conn, *http.Response, error) {
	dialCtx, cancel := context.WithTimeout(ctx, 2*time.Second)
	defer cancel()
	conn, err := kata.DialVsock(dialCtx, vsockPath, tun2connectIngressPort)
	if err != nil {
		return nil, nil, err
	}
	if deadline, ok := dialCtx.Deadline(); ok {
		_ = conn.SetDeadline(deadline)
	}
	target := net.JoinHostPort("127.0.0.1", strconv.Itoa(int(port)))
	if _, err := fmt.Fprintf(conn, "CONNECT %s HTTP/1.1\r\nHost: %s\r\n\r\n", target, target); err != nil {
		_ = conn.Close()
		return nil, nil, err
	}
	reader := bufio.NewReader(conn)
	resp, err := http.ReadResponse(reader, &http.Request{Method: http.MethodConnect})
	if err != nil {
		_ = conn.Close()
		return nil, nil, fmt.Errorf("reading tun2connect's ingress answer: %w", err)
	}
	_ = conn.SetDeadline(time.Time{})
	return &readerConn{Conn: conn, reader: reader}, resp, nil
}

// readerConn reads through the buffer that held the answer's head, so stream
// bytes that arrived with it are not lost.
type readerConn struct {
	net.Conn
	reader *bufio.Reader
}

func (c *readerConn) Read(p []byte) (int, error) { return c.reader.Read(p) }

func (c *readerConn) CloseWrite() error {
	if conn, ok := c.Conn.(interface{ CloseWrite() error }); ok {
		return conn.CloseWrite()
	}
	return nil
}

// checkTun2connectAsset refuses a SandboxConfig that does not match --netless,
// so a bundle with tun2connect only ever boots netless actors.
func (s *AteWorkerService) checkTun2connectAsset(rr resolvedRuntime) error {
	switch {
	case s.netless && rr.tun2connect == "":
		return fmt.Errorf("--netless requires the %q asset in the pool's SandboxConfig", assetTun2connect)
	case !s.netless && rr.tun2connect != "":
		return fmt.Errorf("the pool's SandboxConfig has the %q asset, which only a --netless worker runs", assetTun2connect)
	}
	return nil
}

// checkSnapshotNetwork refuses a MEMORY snapshot taken with the other network
// setup: a netless worker has no tap, and others do not serve tun2connect.
func (s *AteWorkerService) checkSnapshotNetwork(devices int) error {
	switch {
	case s.netless && devices > 0:
		return fmt.Errorf("the snapshot has %d network devices, and this worker boots actors with none", devices)
	case !s.netless && devices == 0:
		return errors.New("the snapshot has no network device, so it needs a netless worker")
	}
	return nil
}
