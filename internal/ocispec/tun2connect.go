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

package ocispec

import (
	"os"

	specs "github.com/opencontainers/runtime-spec/specs-go"
)

// tun2connectCapabilities let tun2connect set up its TUN device and then drop
// CAP_NET_ADMIN, which takes CAP_SETPCAP.
var tun2connectCapabilities = []string{"CAP_NET_ADMIN", "CAP_SETPCAP"}

// Tun2connect returns the OCI spec of tun2connect, a netless actor's in-sandbox
// producer. It joins the actor's network namespace, and its rootfs holds only it.
func Tun2connect(actorUID string, args []string) *specs.Spec {
	return &specs.Spec{
		Version: specs.Version,
		Process: &specs.Process{
			Args:            args,
			Env:             []string{"PATH=/"},
			Cwd:             "/",
			NoNewPrivileges: true,
			Capabilities: &specs.LinuxCapabilities{
				Bounding:  tun2connectCapabilities,
				Effective: tun2connectCapabilities,
				Permitted: tun2connectCapabilities,
			},
			// It holds a vsock stream for every connection the actor has open.
			Rlimits: rlimits(),
		},
		Root: &specs.Root{
			Path: "rootfs",
		},
		Hostname: Hostname,
		Mounts:   systemMounts(),
		Linux: &specs.Linux{
			Namespaces: namespaces(actorUID),
		},
	}
}

// AddTUNDevice adds /dev/net/tun, which kata allows but does not create. The
// actor's containers get no such node, and neither CAP_MKNOD nor CAP_NET_ADMIN.
func AddTUNDevice(spec *specs.Spec) {
	mode := os.FileMode(0o666)
	var root uint32
	spec.Linux.Devices = append(spec.Linux.Devices, specs.LinuxDevice{
		Path:     "/dev/net/tun",
		Type:     "c",
		Major:    10,
		Minor:    200,
		FileMode: &mode,
		UID:      &root,
		GID:      &root,
	})
}
