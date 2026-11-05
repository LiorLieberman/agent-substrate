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
	"context"
	"fmt"
	"os"
	"os/exec"

	k8sruntime "k8s.io/apimachinery/pkg/runtime"
	"sigs.k8s.io/yaml"

	atev1 "go.ate.dev/substrate/api/infra/k8s/ate/v1"
	"go.ate.dev/substrate/cmd/ate-setup/internal/kube"
	"go.ate.dev/substrate/cmd/ate-setup/internal/log"
	"go.ate.dev/substrate/internal/preview"
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
	// gvisorNetlessSandboxConfigName is the SandboxConfig a netless gVisor
	// WorkerPool names in configRef.
	gvisorNetlessSandboxConfigName = "gvisor-netless"
)

// tun2connectSHA256 pins the reproducible build of hack/tools/tun2connect. A
// mismatch means the module or the toolchain changed, and these need updating.
var tun2connectSHA256 = map[string]string{
	"amd64": "6e6273e7bc567b3f70082d6cf8231b292e90f6dec9810641929421affd3ef747",
	"arm64": "bbfbd9a93d08823beb793d86a49dba1e95097299289fbb3ec49699fcb8f17617",
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

// netlessSandboxConfig is the SandboxConfig in rendered, named name, with
// tun2connect in every version and no class default for other pools to take.
func netlessSandboxConfig(rendered []byte, name, scheme, bucket string) ([]byte, error) {
	objs, err := kube.DecodeManifestBytes(rendered)
	if err != nil {
		return nil, err
	}
	if len(objs) != 1 {
		return nil, fmt.Errorf("the SandboxConfig for %s decoded to %d objects, want 1", name, len(objs))
	}
	var sc atev1.SandboxConfig
	if err := k8sruntime.DefaultUnstructuredConverter.FromUnstructured(objs[0].Object, &sc); err != nil {
		return nil, fmt.Errorf("decoding the SandboxConfig for %s: %w", name, err)
	}
	sc.Name = name
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

// tun2connectDigests is the asset digests of tun2connect alone, by arch, for
// staging it without the microVM assets.
func tun2connectDigests(arches []string) map[string]map[string]string {
	digests := make(map[string]map[string]string, len(arches))
	for _, arch := range arches {
		digests[arch] = map[string]string{tun2connectAsset: tun2connectSHA256[arch]}
	}
	return digests
}

// prepareGVisorNetless builds tun2connect and, off Kind, uploads it to the
// microVM assets' bucket, which it returns, before the cluster is touched.
func (e *Env) prepareGVisorNetless(ctx context.Context) (string, error) {
	if err := ctx.Err(); err != nil {
		return "", err
	}
	log.Step("prepare_gvisor_netless")

	bucket, err := e.checkMicroVMDeps()
	if err != nil {
		return "", fmt.Errorf("the %s preview stages tun2connect with the microVM assets: %w", preview.GateNetlessGVisor, err)
	}
	for _, arch := range e.microVMArches() {
		if err := e.buildTun2connect(ctx, arch); err != nil {
			return "", err
		}
	}
	if !e.Cfg.Kind {
		log.Infof("Uploading tun2connect to gs://%s/%s/ ...", bucket, microvmAssetsPrefix)
		if err := e.stageMicroVMAssetsToGCS(ctx, bucket, tun2connectDigests(e.microVMArches())); err != nil {
			return "", err
		}
	}
	return bucket, nil
}

// applyGVisorNetlessSandboxConfig stages tun2connect into in-cluster rustfs on
// Kind and applies the gvisor-netless SandboxConfig.
func (e *Env) applyGVisorNetlessSandboxConfig(ctx context.Context, bucket string) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	log.Step("deploy_gvisor_netless_sandboxconfig")

	if e.Cfg.Kind {
		log.Infof("Staging tun2connect to in-cluster rustfs bucket %s (%s/)...", bucket, microvmAssetsPrefix)
		if err := e.stageMicroVMAssetsToRustfs(ctx, bucket, tun2connectDigests(e.microVMArches())); err != nil {
			return err
		}
	}
	gvisor, err := os.ReadFile(e.Cfg.Manifest("sandboxconfig-gvisor.yaml"))
	if err != nil {
		return err
	}
	netless, err := netlessSandboxConfig(gvisor, gvisorNetlessSandboxConfigName, e.microVMBucketScheme(), bucket)
	if err != nil {
		return err
	}
	if err := e.Kube.ApplyBytes(ctx, netless); err != nil {
		return err
	}
	log.Infof("Installed the %s SandboxConfig for netless gVisor WorkerPools.", gvisorNetlessSandboxConfigName)
	return nil
}
