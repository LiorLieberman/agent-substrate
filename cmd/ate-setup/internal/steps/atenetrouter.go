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
	"bytes"
	"context"
	"fmt"
	"strings"

	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"sigs.k8s.io/kustomize/kyaml/kio"

	"go.ate.dev/substrate/cmd/ate-setup/internal/kube"
	"go.ate.dev/substrate/cmd/ate-setup/internal/log"
)

// atenetRouterDeployment is the ingress router's Deployment. Every object
// that belongs to the router is named atenet-router or atenet-router-*.
const atenetRouterDeployment = "atenet-router"

// atenetRouterManifests hold the router's objects for both dataplanes and both
// cluster shapes. Some of them also hold other components' objects, which
// atenetRouterObjects leaves out.
var atenetRouterManifests = [][]string{
	{"atenet-router.yaml"},
	{"atenet-router-monitoring.yaml"},
	{"ate-system-networkpolicies.yaml"},
	{"components", "agentgateway", "configmap.yaml"},
}

// isAtenetRouterObject reports whether the object named name belongs to the
// router.
func isAtenetRouterObject(name string) bool {
	return name == atenetRouterDeployment || strings.HasPrefix(name, atenetRouterDeployment+"-")
}

// withoutAtenetRouter drops the router's objects from a rendered manifest.
func withoutAtenetRouter(manifest []byte) ([]byte, error) {
	nodes, err := (&kio.ByteReader{
		Reader:                bytes.NewReader(manifest),
		OmitReaderAnnotations: true,
	}).Read()
	if err != nil {
		return nil, fmt.Errorf("while parsing manifest: %w", err)
	}
	kept := nodes[:0]
	for _, node := range nodes {
		if !isAtenetRouterObject(node.GetName()) {
			kept = append(kept, node)
		}
	}
	var out bytes.Buffer
	if err := (kio.ByteWriter{Writer: &out}).Write(kept); err != nil {
		return nil, fmt.Errorf("while writing manifest: %w", err)
	}
	return out.Bytes(), nil
}

// atenetRouterObjects returns the router's objects from atenetRouterManifests.
func (e *Env) atenetRouterObjects() ([]*unstructured.Unstructured, error) {
	var objs []*unstructured.Unstructured
	for _, path := range atenetRouterManifests {
		loaded, err := kube.LoadPath(e.Cfg.Manifest(path...))
		if err != nil {
			return nil, err
		}
		for _, obj := range loaded {
			if isAtenetRouterObject(obj.GetName()) {
				objs = append(objs, obj)
			}
		}
	}
	return objs, nil
}

// applyAtenetRouter renders and applies the router for the selected dataplane.
func (e *Env) applyAtenetRouter(ctx context.Context) error {
	manifest, err := e.renderAtenetRouterManifest(ctx)
	if err != nil {
		return err
	}
	return e.Kube.ApplyBytes(ctx, manifest)
}

// removeAtenetRouter deletes whatever an earlier install left of the router,
// so that under --skip-atenet-router nothing is left serving actors. Objects
// already gone are skipped, so it runs on every such install.
func (e *Env) removeAtenetRouter(ctx context.Context) error {
	objs, err := e.atenetRouterObjects()
	if err != nil {
		return err
	}
	log.Step("remove_atenet_router")
	return e.Kube.Delete(ctx, objs)
}
