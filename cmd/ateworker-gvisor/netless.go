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
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"log/slog"
	"net"
	"os"
	"os/exec"
	"path"
	"path/filepath"
	"slices"
	"strconv"
	"time"

	"github.com/opencontainers/runtime-spec/specs-go"
	"k8s.io/apimachinery/pkg/util/validation/field"

	"go.ate.dev/substrate/internal/apierror"
	"go.ate.dev/substrate/internal/ateworker/actornet"
	"go.ate.dev/substrate/internal/ocispec"
	"go.ate.dev/substrate/internal/proto/ateworkerpb"
	"go.ate.dev/substrate/internal/resources"
)

const (
	// tun2connectContainerName is tun2connect's runsc container. '_' cannot
	// appear in an actor container's name, as with ocispec.SandboxID.
	tun2connectContainerName = "_tun2connect"
	// assetTun2connect is the static tun2connect binary. Only a netless pool's
	// SandboxConfig has it.
	assetTun2connect        = "tun2connect"
	tun2connectRunMount     = "/run/tun2connect"
	tun2connectEgressSocket = "egress.sock"
	// tun2connectStartTimeout bounds how long tun2connect takes to bring up tun0.
	tun2connectStartTimeout = 20 * time.Second
	// defaultIngressPort is the actor port ingress reaches when a request names
	// none.
	defaultIngressPort = 80
)

// tun2connectDir holds the host side of tun2connect's mounts. It is in the
// worker's own filesystem, out of reach of the node's other workers.
func tun2connectDir(actorUID string) string {
	return filepath.Join(os.TempDir(), "tun2connect", actorUID)
}

// tun2connectRunDir is mounted at tun2connectRunMount, and holds the egress
// socket.
func tun2connectRunDir(actorUID string) string {
	return filepath.Join(tun2connectDir(actorUID), "run")
}

// tun2connectEtcDir is mounted at /etc, where tun2connect writes resolv.conf.
func tun2connectEtcDir(actorUID string) string {
	return filepath.Join(tun2connectDir(actorUID), "etc")
}

// tun2connectBinary returns the tun2connect binary atelet staged, checked like
// runsc. Only a netless pool's SandboxConfig has the asset, so it must match.
func (s *AteWorkerService) tun2connectBinary(actorUID string, actorDirs *ateworkerpb.ActorDirs, paths map[string]string) (string, error) {
	p, ok := paths[assetTun2connect]
	if !s.netless {
		if ok {
			return "", apierror.FailedPrecondition("the pool's SandboxConfig has the %q asset, which only a --netless worker runs", assetTun2connect)
		}
		return "", nil
	}
	if !ok {
		return "", apierror.FailedPrecondition("--netless requires the %q asset in the pool's SandboxConfig", assetTun2connect)
	}
	root := actorDirs.GetSandboxAssetsDir()
	errs := resources.ValidateSandboxAssetsDir(actorUID, root, field.NewPath("actor_dirs", "sandbox_assets_dir"))
	if len(errs) == 0 {
		errs = resources.ValidateRuntimeAssetPath(root, p, field.NewPath("runtime_asset_paths").Key(assetTun2connect))
	}
	if len(errs) > 0 {
		return "", resources.ToAPIError(errs)
	}
	return p, nil
}

// hostNetless gives a netless actor a namespace with only lo, since runsc
// port-forward refuses --network=none, and serves tun2connect's egress socket.
func (s *AteWorkerService) hostNetless(ctx context.Context, hosted *hostedActor) error {
	uid := hosted.attribution.UID
	session, err := actornet.SetupLoopbackSandbox(ctx, uid)
	if err != nil {
		return fmt.Errorf("while setting up the sandbox network: %w", err)
	}
	if err := s.serveTun2connectEgress(ctx, uid); err != nil {
		return errors.Join(err, session.Close(ctx))
	}
	s.actorsMu.Lock()
	hosted.network = session
	s.actorsMu.Unlock()
	return nil
}

// serveTun2connectEgress serves the actor's connections from tun2connect
// through the actor's egress until it is deactivated.
func (s *AteWorkerService) serveTun2connectEgress(ctx context.Context, actorUID string) error {
	dir := tun2connectRunDir(actorUID)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return fmt.Errorf("while creating %q: %w", dir, err)
	}
	socket := filepath.Join(dir, tun2connectEgressSocket)
	if err := os.Remove(socket); err != nil && !errors.Is(err, fs.ErrNotExist) {
		return fmt.Errorf("while removing a stale tun2connect socket: %w", err)
	}
	return s.tunnel.Egress.ServeConnect(ctx, actorUID, socket)
}

// removeTun2connectDir drops the host side of tun2connect's mounts once its
// sandbox is gone.
func removeTun2connectDir(ctx context.Context, actorUID string) {
	if err := os.RemoveAll(tun2connectDir(actorUID)); err != nil {
		slog.WarnContext(ctx, "Failed to remove tun2connect's directory", slog.String("actorUID", actorUID), slog.Any("err", err))
	}
}

// tun2connectSpec is tun2connect's OCI spec. Besides its rootfs, it sees the
// egress socket's directory and the /etc it writes resolv.conf to.
func tun2connectSpec(actorUID string) *specs.Spec {
	spec := ocispec.Tun2connect(actorUID, []string{"/tun2connect", "run", "unix://" + path.Join(tun2connectRunMount, tun2connectEgressSocket)})
	// Read-only, so nothing in the sandbox can change the binary.
	spec.Root.Readonly = true
	bind := func(dest, src string) specs.Mount {
		return specs.Mount{Destination: dest, Type: "bind", Source: src, Options: []string{"bind", "rw", "nodev"}}
	}
	spec.Mounts = append(spec.Mounts, bind(tun2connectRunMount, tun2connectRunDir(actorUID)), bind("/etc", tun2connectEtcDir(actorUID)))
	return spec
}

// stageTun2connect makes tun2connect's bundle, which atelet does not, and
// clears the resolv.conf waitTun2connect waits for.
func stageTun2connect(actorUID string, actorDirs *ateworkerpb.ActorDirs, binary string) error {
	rootfs := filepath.Join(ociBundlePath(actorDirs, tun2connectContainerName), "rootfs")
	if err := os.RemoveAll(rootfs); err != nil {
		return fmt.Errorf("while clearing tun2connect's rootfs: %w", err)
	}
	for _, d := range []string{"proc", "sys", "dev", "tmp", "etc", tun2connectRunMount} {
		if err := os.MkdirAll(filepath.Join(rootfs, d), 0o755); err != nil {
			return fmt.Errorf("while creating tun2connect's rootfs: %w", err)
		}
	}
	// A copy: the staged asset is a hard link into the node's asset cache,
	// which every actor on the node runs from.
	if err := copyFile(binary, filepath.Join(rootfs, "tun2connect"), 0o755); err != nil {
		return fmt.Errorf("while copying the tun2connect binary: %w", err)
	}
	etc := tun2connectEtcDir(actorUID)
	if err := os.MkdirAll(etc, 0o700); err != nil {
		return fmt.Errorf("while creating %q: %w", etc, err)
	}
	if err := os.Remove(filepath.Join(etc, "resolv.conf")); err != nil && !errors.Is(err, fs.ErrNotExist) {
		return fmt.Errorf("while removing tun2connect's stale resolv.conf: %w", err)
	}
	return nil
}

func copyFile(src, dst string, perm os.FileMode) error {
	in, err := os.Open(src)
	if err != nil {
		return err
	}
	defer in.Close()
	out, err := os.OpenFile(dst, os.O_WRONLY|os.O_CREATE|os.O_EXCL, perm)
	if err != nil {
		return err
	}
	_, err = io.Copy(out, in)
	return errors.Join(err, out.Close())
}

// startTun2connect starts tun2connect, or restores it from a MEMORY
// checkpointDir, before the actor's containers, which need its network.
func (s *AteWorkerService) startTun2connect(ctx context.Context, rcmd *runsc, attribution resources.ActorAttribution, binary, checkpointDir string) error {
	if err := stageTun2connect(rcmd.actorUID, rcmd.actorDirs, binary); err != nil {
		return err
	}
	pw, err := s.actorLogger.StartJSONLogPipe(attribution, tun2connectContainerName)
	if err != nil {
		return fmt.Errorf("while starting json log pipe for %q: %w", tun2connectContainerName, err)
	}
	defer pw.Close()
	if err := rcmd.cmdCreate(ctx, pw, tun2connectContainerName, nil); err != nil {
		return fmt.Errorf("while creating tun2connect: %w", err)
	}
	if checkpointDir != "" {
		if err := rcmd.cmdRestore(ctx, pw, tun2connectContainerName, checkpointDir); err != nil {
			return fmt.Errorf("while restoring tun2connect: %w", err)
		}
		return nil
	}
	if err := rcmd.cmdStart(ctx, pw, tun2connectContainerName); err != nil {
		return fmt.Errorf("while starting tun2connect: %w", err)
	}
	return waitTun2connect(ctx, filepath.Join(tun2connectEtcDir(rcmd.actorUID), "resolv.conf"), tun2connectStartTimeout)
}

// watchTun2connect reports how a netless actor's tun2connect exits, which
// leaves the actor with no network and no ingress. A failed wait means the
// sandbox itself is gone, which watchSandbox already handles.
func (s *AteWorkerService) watchTun2connect(rcmd *runsc) <-chan string {
	if !s.netless {
		return nil
	}
	exited := make(chan string, 1)
	go func() {
		out, err := exec.Command(rcmd.path, rcmd.buildArgs("wait", tun2connectContainerName)...).Output()
		if err != nil {
			return
		}
		var status struct {
			ExitStatus int `json:"exitStatus"`
		}
		if json.Unmarshal(out, &status) != nil {
			exited <- "unknown status"
			return
		}
		exited <- fmt.Sprintf("exit status %d", status.ExitStatus)
	}()
	return exited
}

// waitTun2connect waits for tun2connect to write resolvConf, which it does
// once tun0 and its routes are up.
func waitTun2connect(ctx context.Context, resolvConf string, timeout time.Duration) error {
	deadline := time.Now().Add(timeout)
	for {
		_, err := os.Stat(resolvConf)
		if err == nil {
			return nil
		}
		if !errors.Is(err, fs.ErrNotExist) {
			return err
		}
		if time.Now().After(deadline) {
			return fmt.Errorf("tun2connect did not come up within %v; see the %s container's logs", timeout, tun2connectContainerName)
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(10 * time.Millisecond):
		}
	}
}

// ingressPortAllowed reports whether ingress may reach port: it lands on the
// actor's loopback, so only 80 and the wakeup probe ports, as on a microVM.
func ingressPortAllowed(containers []*ateworkerpb.Container, port uint64) bool {
	return port == defaultIngressPort || slices.ContainsFunc(containers, func(c *ateworkerpb.Container) bool {
		return uint64(c.GetWakeupProbe().GetHttpGet().GetPort()) == port
	})
}

// portForwardArgs builds the argv for `runsc port-forward --stream`. runsc
// finds the sandbox through a running container, and tun2connect's runs.
func (r *runsc) portForwardArgs(sock string, port uint64) []string {
	return r.buildArgs("port-forward", "", "--stream", sock, tun2connectContainerName, strconv.FormatUint(port, 10))
}

// dialPortForward reaches a port on a netless actor's loopback. Only the port
// of address counts: the sandbox has no address of its own.
func (r *runsc) dialPortForward(ctx context.Context, _, address string) (net.Conn, error) {
	_, portText, err := net.SplitHostPort(address)
	if err != nil {
		return nil, err
	}
	port, err := strconv.ParseUint(portText, 10, 16)
	if err != nil || port == 0 {
		return nil, fmt.Errorf("invalid port in %q", address)
	}
	if !ingressPortAllowed(r.containers, port) {
		return nil, fmt.Errorf("ingress cannot reach port %d of a netless actor", port)
	}
	dir, err := os.MkdirTemp("", "port-forward-")
	if err != nil {
		return nil, err
	}
	defer func() { _ = os.RemoveAll(dir) }()
	sock := filepath.Join(dir, "stream.sock")
	listener, err := net.ListenUnix("unix", &net.UnixAddr{Name: sock, Net: "unix"})
	if err != nil {
		return nil, err
	}
	defer listener.Close()
	cmd := exec.CommandContext(ctx, r.path, r.portForwardArgs(sock, port)...)
	var out bytes.Buffer
	cmd.Stdout, cmd.Stderr = &out, &out
	if err := cmd.Run(); err != nil {
		return nil, fmt.Errorf("while running `runsc port-forward` to port %d: %w: %s", port, err, lastLine(out.Bytes()))
	}
	// runsc connects before it hands the connection over, so it is waiting.
	if deadline, ok := ctx.Deadline(); ok {
		_ = listener.SetDeadline(deadline)
	}
	conn, err := listener.Accept()
	if err != nil {
		return nil, err
	}
	return noHalfClose{conn}, nil
}

// noHalfClose hides CloseWrite: gVisor drops a forwarded stream, reply and
// all, as soon as the worker's side stops sending.
type noHalfClose struct{ net.Conn }

// lastLine is the last line of b, where runsc writes its error.
func lastLine(b []byte) []byte {
	b = bytes.TrimSpace(b)
	if i := bytes.LastIndexByte(b, '\n'); i >= 0 {
		return b[i+1:]
	}
	return b
}
