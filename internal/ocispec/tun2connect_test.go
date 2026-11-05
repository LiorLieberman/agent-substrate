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
	"slices"
	"testing"

	specs "github.com/opencontainers/runtime-spec/specs-go"

	"go.ate.dev/substrate/internal/proto/ateworkerpb"
)

// tun2connect alone gets the TUN device node and the capabilities to set it
// up.
func TestTun2connectAloneGetsTheTUNDevice(t *testing.T) {
	hasTUN := func(spec *specs.Spec) bool {
		return slices.ContainsFunc(spec.Linux.Devices, func(d specs.LinuxDevice) bool { return d.Path == "/dev/net/tun" && d.Major == 10 && d.Minor == 200 })
	}
	spec := Tun2connect("actor-uid", []string{"/tun2connect", "run", "vsock://2:1027"})
	if err := ShapeMicroVM(spec, MicroVMOptions{}); err != nil {
		t.Fatal(err)
	}
	AddTUNDevice(spec)
	if !hasTUN(spec) {
		t.Errorf("devices = %+v, want /dev/net/tun", spec.Linux.Devices)
	}
	if got := spec.Process.Capabilities.Bounding; !slices.Equal(got, []string{"CAP_NET_ADMIN", "CAP_SETPCAP"}) {
		t.Errorf("bounding capabilities = %v, want CAP_NET_ADMIN and CAP_SETPCAP", got)
	}
	if !spec.Process.NoNewPrivileges {
		t.Error("tun2connect may gain privileges")
	}

	actor := Build(Options{ActorUID: "actor-uid", Container: &ateworkerpb.Container{ContainerSpec: &ateworkerpb.ContainerSpec{Args: []string{"/app"}}}})
	if err := ShapeMicroVM(actor, MicroVMOptions{}); err != nil {
		t.Fatal(err)
	}
	if hasTUN(actor) || slices.Contains(actor.Process.Capabilities.Bounding, "CAP_NET_ADMIN") {
		t.Error("an actor container gets the TUN device or CAP_NET_ADMIN")
	}
}
