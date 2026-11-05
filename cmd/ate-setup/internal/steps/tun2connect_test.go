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

package steps

import (
	"path/filepath"
	"testing"

	"sigs.k8s.io/yaml"

	atev1 "go.ate.dev/substrate/api/infra/k8s/ate/v1"
	"go.ate.dev/substrate/cmd/ate-setup/internal/render"
)

// The netless SandboxConfig is the microvm one plus tun2connect: same assets,
// its own name, and no class default for every other pool to pick up.
func TestNetlessSandboxConfig(t *testing.T) {
	rendered, err := render.Template(filepath.Join(repoRoot(t), microvmSandboxConfigTemplate),
		map[string]string{"BUCKET_SCHEME": "s3", "ASSET_BUCKET_NAME": "assets"}, nil)
	if err != nil {
		t.Fatal(err)
	}
	var microvm atev1.SandboxConfig
	if err := yaml.Unmarshal(rendered, &microvm); err != nil {
		t.Fatal(err)
	}

	out, err := netlessSandboxConfig(rendered, "s3", "assets")
	if err != nil {
		t.Fatalf("netlessSandboxConfig() error = %v", err)
	}
	var netless atev1.SandboxConfig
	if err := yaml.Unmarshal(out, &netless); err != nil {
		t.Fatal(err)
	}
	if netless.Name != microvmNetlessSandboxConfigName {
		t.Errorf("name = %q, want %q", netless.Name, microvmNetlessSandboxConfigName)
	}
	if _, ok := netless.Annotations[atev1.SandboxConfigClassDefaultAnnotation]; ok {
		t.Error("the netless SandboxConfig is a class default")
	}
	if netless.Spec.SandboxClass != atev1.SandboxClassMicroVM || netless.Spec.DefaultVersion != microvm.Spec.DefaultVersion {
		t.Errorf("class and default version = %q, %q, want the microvm one's", netless.Spec.SandboxClass, netless.Spec.DefaultVersion)
	}
	if len(netless.Spec.Versions) != len(microvm.Spec.Versions) {
		t.Fatalf("%d versions, want %d", len(netless.Spec.Versions), len(microvm.Spec.Versions))
	}
	for i, version := range microvm.Spec.Versions {
		for arch, assets := range version.Assets {
			got := netless.Spec.Versions[i].Assets[arch]
			if len(got) != len(assets)+1 {
				t.Errorf("version %s %s has %d assets, want the %d microvm ones plus tun2connect", version.Name, arch, len(got), len(assets))
			}
			for name, asset := range assets {
				if got[name] != asset {
					t.Errorf("version %s %s asset %s = %+v, want %+v", version.Name, arch, name, got[name], asset)
				}
			}
			want := atev1.AssetFile{
				URL:    "s3://assets/microvm-assets/" + arch + "/" + tun2connectSHA256[arch],
				SHA256: tun2connectSHA256[arch],
			}
			if got[tun2connectAsset] != want {
				t.Errorf("version %s %s tun2connect = %+v, want %+v", version.Name, arch, got[tun2connectAsset], want)
			}
		}
	}
}
