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
	"slices"
	"testing"

	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"

	"go.ate.dev/substrate/cmd/ate-setup/internal/config"
	"go.ate.dev/substrate/cmd/ate-setup/internal/images"
	"go.ate.dev/substrate/cmd/ate-setup/internal/kube"
)

// prebuiltResolver resolves every image without building or pulling one.
func prebuiltResolver() (images.Source, *images.Prebuilt) {
	src := images.Source{Repo: "example.com/substrate", Tag: "v1.2.3"}
	return src, images.NewPrebuilt(src, func(context.Context, string) (string, error) {
		return "sha256:2222222222222222222222222222222222222222222222222222222222222222", nil
	})
}

// objectIDs lists a rendered manifest's objects as kind/name, sorted.
func objectIDs(t *testing.T, manifest []byte) []string {
	t.Helper()
	objs, err := kube.DecodeManifestBytes(manifest)
	if err != nil {
		t.Fatalf("decoding the rendered manifest: %v", err)
	}
	ids := make([]string, 0, len(objs))
	for _, obj := range objs {
		ids = append(ids, obj.GetKind()+"/"+obj.GetName())
	}
	slices.Sort(ids)
	return ids
}

// The name is all --skip-atenet-router goes by, so a router object named
// otherwise would still be applied.
func TestAtenetRouterObjectsAreNamedForIt(t *testing.T) {
	cfg := &config.Config{Root: repoRoot(t)}
	for _, manifest := range []string{"atenet-router.yaml", "atenet-router-monitoring.yaml"} {
		objs, err := kube.LoadPath(cfg.Manifest(manifest))
		if err != nil {
			t.Fatal(err)
		}
		for _, obj := range objs {
			if !isAtenetRouterObject(obj.GetName()) {
				t.Errorf("%s in %s is not named atenet-router or atenet-router-*", kube.Describe(obj), manifest)
			}
		}
	}
}

// Every system bundle loses exactly the router's objects under
// --skip-atenet-router, and removeAtenetRouter reaches each of them.
func TestRenderSystemManifestsSkipAtenetRouter(t *testing.T) {
	src, resolver := prebuiltResolver()
	for _, tc := range []struct {
		name string
		cfg  config.Config
	}{
		{name: "base", cfg: config.Config{Router: config.RouterEnvoy}},
		{name: "kind", cfg: config.Config{Router: config.RouterEnvoy, Kind: true}},
		{name: "agentgateway", cfg: config.Config{Router: config.RouterAgentgateway}},
		{name: "kind agentgateway", cfg: config.Config{Router: config.RouterAgentgateway, Kind: true}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			cfg := tc.cfg
			cfg.Root = repoRoot(t)
			cfg.Images = src
			cfg.IngressAllowedSPIFFEIDs = []string{"spiffe://cluster.local/ns/a/sa/a"}
			full, err := (&Env{Cfg: &cfg, resolver: resolver}).renderSystemManifests(t.Context())
			if err != nil {
				t.Fatalf("render: %v", err)
			}

			skipCfg := cfg
			skipCfg.SkipAtenetRouter = true
			skipCfg.IngressAllowedSPIFFEIDs = nil
			e := &Env{Cfg: &skipCfg, resolver: resolver}
			skipped, err := e.renderSystemManifests(t.Context())
			if err != nil {
				t.Fatalf("render under --skip-atenet-router: %v", err)
			}
			removable, err := e.atenetRouterObjects()
			if err != nil {
				t.Fatal(err)
			}
			var removed []string
			for _, obj := range removable {
				removed = append(removed, obj.GetKind()+"/"+obj.GetName())
			}

			var rest, router []string
			for _, id := range objectIDs(t, full) {
				if slices.Contains(removed, id) {
					router = append(router, id)
				} else {
					rest = append(rest, id)
				}
			}
			if !slices.Contains(router, "Deployment/"+atenetRouterDeployment) {
				t.Fatalf("the full bundle's router objects %q lack its Deployment", router)
			}
			if got := objectIDs(t, skipped); !slices.Equal(got, rest) {
				t.Errorf("bundle under --skip-atenet-router = %q, want the full bundle without the router's %q: %q", got, router, rest)
			}
		})
	}
}

// The agentgateway egress gateway shares a component with the router, so its
// render must leave the router's config out under --skip-atenet-router and
// keep its own.
func TestRenderAgentgatewayEgressSkipAtenetRouter(t *testing.T) {
	const routerConfig = "ConfigMap/atenet-router-agentgateway-config"
	const egressConfig = "ConfigMap/atenet-egress-agentgateway-substrate-config"
	src, resolver := prebuiltResolver()
	for _, skip := range []bool{false, true} {
		cfg := &config.Config{Root: repoRoot(t), Router: config.RouterAgentgateway, Images: src, SkipAtenetRouter: skip}
		rendered, err := (&Env{Cfg: cfg, resolver: resolver}).renderAtenetEgressManifest(t.Context(), config.CredentialProvider{})
		if err != nil {
			t.Fatalf("render with skip %v: %v", skip, err)
		}
		ids := objectIDs(t, rendered)
		if got := slices.Contains(ids, routerConfig); got == skip {
			t.Errorf("with skip %v, the egress render carries %s = %v", skip, routerConfig, got)
		}
		if !slices.Contains(ids, egressConfig) {
			t.Errorf("with skip %v, the egress render lacks %s", skip, egressConfig)
		}
	}
}

// removeAtenetRouter deletes what an earlier install left of the router and
// nothing that shares a manifest with it. The PodMonitoring kind is not
// served here, as on a cluster without its CRD, and is skipped.
func TestRemoveAtenetRouter(t *testing.T) {
	gvk := func(group, version, kind string) schema.GroupVersionKind {
		return schema.GroupVersionKind{Group: group, Version: version, Kind: kind}
	}
	type object struct {
		gvk  schema.GroupVersionKind
		name string
	}
	router := []object{
		{gvk("", "v1", "ServiceAccount"), "atenet-router"},
		{gvk("rbac.authorization.k8s.io", "v1", "Role"), "atenet-router-endpointslices"},
		{gvk("rbac.authorization.k8s.io", "v1", "RoleBinding"), "atenet-router-endpointslices"},
		{gvk("", "v1", "ConfigMap"), "atenet-router-envoy-config"},
		{gvk("", "v1", "ConfigMap"), "atenet-router-agentgateway-config"},
		{gvk("apps", "v1", "Deployment"), "atenet-router"},
		{gvk("", "v1", "Service"), "atenet-router"},
		{gvk("networking.k8s.io", "v1", "NetworkPolicy"), "atenet-router"},
	}
	others := []object{
		{gvk("", "v1", "ConfigMap"), "atenet-egress-agentgateway-substrate-config"},
		{gvk("networking.k8s.io", "v1", "NetworkPolicy"), "atenet-egress"},
	}
	var seeds []runtime.Object
	for _, o := range append(slices.Clone(router), others...) {
		u := &unstructured.Unstructured{}
		u.SetGroupVersionKind(o.gvk)
		u.SetNamespace(NamespaceAteSystem)
		u.SetName(o.name)
		seeds = append(seeds, u)
	}
	k, _ := fakeDeleteKube(t, nil, seeds)
	e := &Env{Cfg: &config.Config{Root: repoRoot(t)}, Kube: k}
	if err := e.removeAtenetRouter(t.Context()); err != nil {
		t.Fatalf("removeAtenetRouter() = %v", err)
	}
	for _, o := range router {
		if exists, err := k.Exists(t.Context(), o.gvk, NamespaceAteSystem, o.name); err != nil || exists {
			t.Errorf("%s %s exists = %v (err %v) after removeAtenetRouter", o.gvk.Kind, o.name, exists, err)
		}
	}
	for _, o := range others {
		if exists, err := k.Exists(t.Context(), o.gvk, NamespaceAteSystem, o.name); err != nil || !exists {
			t.Errorf("%s %s exists = %v (err %v) after removeAtenetRouter, want it kept", o.gvk.Kind, o.name, exists, err)
		}
	}

	// Nothing left to remove is not an error.
	if err := e.removeAtenetRouter(t.Context()); err != nil {
		t.Errorf("removeAtenetRouter() on a cluster without a router = %v", err)
	}
}
