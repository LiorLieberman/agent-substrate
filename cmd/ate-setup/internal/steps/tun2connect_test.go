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

package steps

import (
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"sigs.k8s.io/yaml"

	atev1 "go.ate.dev/substrate/api/infra/k8s/ate/v1"
	"go.ate.dev/substrate/cmd/ate-setup/internal/config"
	"go.ate.dev/substrate/cmd/ate-setup/internal/render"
)

// A gvisor-only install stages tun2connect alone, without the microVM assets
// it never built.
func TestStageTun2connectAlone(t *testing.T) {
	silenceStepLog(t)

	root := t.TempDir()
	binDir := t.TempDir()
	callsFile := filepath.Join(t.TempDir(), "gcloud-calls.txt")
	if err := os.WriteFile(filepath.Join(binDir, "gcloud"), []byte("#!/bin/sh\necho \"$*\" >> "+callsFile+"\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PATH", binDir+string(os.PathListSeparator)+os.Getenv("PATH"))

	env := &Env{Cfg: &config.Config{Root: root, BucketName: "test-bucket"}}
	if err := env.stageMicroVMAssetsToGCS(t.Context(), "test-bucket-assets", tun2connectDigests(env.microVMArches())); err != nil {
		t.Fatalf("stageMicroVMAssetsToGCS() = %v", err)
	}

	calls, err := os.ReadFile(callsFile)
	if err != nil {
		t.Fatal(err)
	}
	var uploads, want []string
	for _, call := range strings.Split(string(calls), "\n") {
		if strings.HasPrefix(call, "storage cp ") {
			uploads = append(uploads, call)
		}
	}
	for _, arch := range microvmArches {
		want = append(want, "storage cp "+filepath.Join(root, "bin", microvmAssetsPrefix, arch, tun2connectAsset)+
			" gs://test-bucket-assets/"+microvmAssetsPrefix+"/"+arch+"/"+tun2connectSHA256[arch])
	}
	if !slices.Equal(uploads, want) {
		t.Errorf("uploads = %q, want %q", uploads, want)
	}
}

// A netless SandboxConfig is its class's one plus tun2connect: same assets,
// its own name, and no class default for every other pool to pick up.
func TestNetlessSandboxConfig(t *testing.T) {
	microvm, err := render.Template(filepath.Join(repoRoot(t), microvmSandboxConfigTemplate),
		map[string]string{"BUCKET_SCHEME": "s3", "ASSET_BUCKET_NAME": "assets"}, nil)
	if err != nil {
		t.Fatal(err)
	}
	gvisor, err := os.ReadFile(filepath.Join(repoRoot(t), "manifests", "ate-install", "sandboxconfig-gvisor.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		name     string
		rendered []byte
		wantName string
	}{
		{name: "microvm", rendered: microvm, wantName: microvmNetlessSandboxConfigName},
		{name: "gvisor", rendered: gvisor, wantName: gvisorNetlessSandboxConfigName},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var base atev1.SandboxConfig
			if err := yaml.Unmarshal(tc.rendered, &base); err != nil {
				t.Fatal(err)
			}

			out, err := netlessSandboxConfig(tc.rendered, tc.wantName, "s3", "assets")
			if err != nil {
				t.Fatalf("netlessSandboxConfig() error = %v", err)
			}
			var netless atev1.SandboxConfig
			if err := yaml.Unmarshal(out, &netless); err != nil {
				t.Fatal(err)
			}
			if netless.Name != tc.wantName {
				t.Errorf("name = %q, want %q", netless.Name, tc.wantName)
			}
			if _, ok := netless.Annotations[atev1.SandboxConfigClassDefaultAnnotation]; ok {
				t.Error("the netless SandboxConfig is a class default")
			}
			if netless.Spec.SandboxClass != base.Spec.SandboxClass || netless.Spec.DefaultVersion != base.Spec.DefaultVersion {
				t.Errorf("class and default version = %q, %q, want %q, %q", netless.Spec.SandboxClass, netless.Spec.DefaultVersion, base.Spec.SandboxClass, base.Spec.DefaultVersion)
			}
			if len(netless.Spec.Versions) != len(base.Spec.Versions) {
				t.Fatalf("%d versions, want %d", len(netless.Spec.Versions), len(base.Spec.Versions))
			}
			for i, version := range base.Spec.Versions {
				for arch, assets := range version.Assets {
					got := netless.Spec.Versions[i].Assets[arch]
					if len(got) != len(assets)+1 {
						t.Errorf("version %s %s has %d assets, want the %d of %s plus tun2connect", version.Name, arch, len(got), len(assets), base.Name)
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
		})
	}
}
