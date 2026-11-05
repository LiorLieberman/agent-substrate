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
	"context"
	"fmt"
	"os"
	"os/exec"
	"slices"

	k8sruntime "k8s.io/apimachinery/pkg/runtime"
	"sigs.k8s.io/yaml"

	atev1 "go.ate.dev/substrate/api/infra/k8s/ate/v1"
	"go.ate.dev/substrate/cmd/ate-setup/internal/kube"
	"go.ate.dev/substrate/cmd/ate-setup/internal/log"
)

const (
	// tun2connectAsset names the tun2connect binary: its SandboxConfig asset,
	// and its file under bin/microvm-assets/<arch>/.
	tun2connectAsset   = "tun2connect"
	tun2connectPackage = "github.com/aojea/agents.net/sdk/cmd/tun2connect"
	// tun2connectToolchain is the Go toolchain tun2connectSHA256 was built with.
	tun2connectToolchain = "go1.27.3"

	// microvmNetlessSandboxConfigName is the SandboxConfig a netless microVM
	// WorkerPool names in configRef.
	microvmNetlessSandboxConfigName = "microvm-netless"
)

// tun2connectSHA256 pins the reproducible build of hack/tools/tun2connect. A
// mismatch means the module or the toolchain changed, and these need updating.
var tun2connectSHA256 = map[string]string{
	"amd64": "41a1d7d8b915ab33b94bfa1f5d25e095b09f8bdc90d0e5a307a69e113b028967",
	"arm64": "02f55eb1213c8eb804db4bcb77274f588f39851b82857b6d21ff098d6e9f59c0",
}

// buildTun2connect builds tun2connect for arch into the arch's asset dir,
// unless the pinned build is already there.
func (e *Env) buildTun2connect(ctx context.Context, arch string) error {
	out := e.Cfg.Path("bin", microvmAssetsPrefix, arch, tun2connectAsset)
	want, ok := tun2connectSHA256[arch]
	if !ok {
		return fmt.Errorf("no pinned tun2connect build for %s", arch)
	}
	if got, err := fileSHA256(out); err == nil && got == want {
		log.Infof("tun2connect for %s already in %s; skipping build.", arch, out)
		return nil
	}
	log.Infof("Building tun2connect for %s into %s...", arch, out)
	cmd := exec.CommandContext(ctx, "go", "build", "-C", e.Cfg.Path("hack", "tools", "tun2connect"),
		"-trimpath", "-buildvcs=false", "-o", out, tun2connectPackage)
	// Pin everything the sha depends on, whatever the shell sets.
	cmd.Env = append(e.Cfg.ScriptEnv(), "CGO_ENABLED=0", "GOOS=linux", "GOARCH="+arch, "GOTOOLCHAIN="+tun2connectToolchain,
		"GOFLAGS=", "GOAMD64=v1", "GOARM64=v8.0")
	cmd.Stdout, cmd.Stderr = os.Stdout, os.Stderr
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("while building tun2connect for %s: %w", arch, err)
	}
	got, err := fileSHA256(out)
	if err != nil {
		return err
	}
	if got != want {
		return fmt.Errorf("tun2connect for %s has sha256 %s, want %s: update tun2connectSHA256 if hack/tools/tun2connect changed", arch, got, want)
	}
	return nil
}

// netlessSandboxConfig is the rendered microvm SandboxConfig, renamed, with
// tun2connect in every version. Its bundle hash keeps netless snapshots apart.
func netlessSandboxConfig(rendered []byte, scheme, bucket string) ([]byte, error) {
	objs, err := kube.DecodeManifestBytes(rendered)
	if err != nil {
		return nil, err
	}
	if len(objs) != 1 {
		return nil, fmt.Errorf("the microvm SandboxConfig decoded to %d objects, want 1", len(objs))
	}
	var sc atev1.SandboxConfig
	if err := k8sruntime.DefaultUnstructuredConverter.FromUnstructured(objs[0].Object, &sc); err != nil {
		return nil, fmt.Errorf("decoding the microvm SandboxConfig: %w", err)
	}
	sc.Name = microvmNetlessSandboxConfigName
	delete(sc.Annotations, atev1.SandboxConfigClassDefaultAnnotation)
	for i := range sc.Spec.Versions {
		for arch, assets := range sc.Spec.Versions[i].Assets {
			sha, ok := tun2connectSHA256[arch]
			if !ok {
				return nil, fmt.Errorf("no pinned tun2connect build for %s", arch)
			}
			assets[tun2connectAsset] = atev1.AssetFile{
				URL:    fmt.Sprintf("%s://%s/%s/%s/%s", scheme, bucket, microvmAssetsPrefix, arch, sha),
				SHA256: sha,
			}
		}
	}
	return yaml.Marshal(&sc)
}

// stagedMicroVMFiles are the files under bin/microvm-assets/<arch>/ to stage
// for one arch: the microvm assets, and tun2connect once it is built.
func stagedMicroVMFiles(digests map[string]string) []string {
	files := microvmAssets
	if _, ok := digests[tun2connectAsset]; ok {
		files = append(slices.Clone(files), tun2connectAsset)
	}
	return files
}
