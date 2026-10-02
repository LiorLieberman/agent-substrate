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
	"testing"

	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"

	"github.com/agent-substrate/substrate/cmd/ate-setup/internal/config"
	"github.com/agent-substrate/substrate/cmd/ate-setup/internal/kube"
)

// The deploy steps refer to the provider's objects by name. This checks those
// names against the manifests, so a rename fails here rather than in the next
// install.
func TestK8sCredentialProviderManifestsAgree(t *testing.T) {
	e := &Env{Cfg: &config.Config{Root: repoRoot(t)}}

	provider, err := kube.LoadPath(e.k8sCredentialProviderPath(k8sCredentialProviderManifest))
	if err != nil {
		t.Fatalf("loading the provider manifest: %v", err)
	}
	dep := findObject(provider, "Deployment", k8sCredentialProviderDeployment)
	if dep == nil {
		t.Fatalf("provider manifest has no deployment/%s", k8sCredentialProviderDeployment)
	}
	if ns := dep.GetNamespace(); ns != NamespaceAteSystem {
		t.Errorf("deployment/%s is in namespace %q, want %q", k8sCredentialProviderDeployment, ns, NamespaceAteSystem)
	}
	if findObject(provider, "ConfigMap", k8sCredentialProviderPolicyConfigMap) != nil {
		t.Errorf("provider manifest carries configmap/%s itself; the deploy step must own whether it is applied", k8sCredentialProviderPolicyConfigMap)
	}
	if got := mountedConfigMaps(dep); len(got) != 1 || got[0] != k8sCredentialProviderPolicyConfigMap {
		t.Errorf("deployment/%s mounts ConfigMaps %v, want only %q", k8sCredentialProviderDeployment, got, k8sCredentialProviderPolicyConfigMap)
	}
	svc := findObject(provider, "Service", k8sCredentialProviderDeployment)
	if svc == nil {
		t.Fatalf("provider manifest has no service/%s", k8sCredentialProviderDeployment)
	}
	if want := svc.GetName() + "." + svc.GetNamespace() + ".svc:50051"; want != config.K8sCredentialProviderAddress {
		t.Errorf("config.K8sCredentialProviderAddress = %q, but the Service resolves to %q", config.K8sCredentialProviderAddress, want)
	}

	policy, err := kube.LoadPath(e.k8sCredentialProviderPath(k8sCredentialProviderPolicyManifest))
	if err != nil {
		t.Fatalf("loading the policy manifest: %v", err)
	}
	cm := findObject(policy, "ConfigMap", k8sCredentialProviderPolicyConfigMap)
	if cm == nil {
		t.Fatalf("policy manifest has no configmap/%s", k8sCredentialProviderPolicyConfigMap)
	}
	if ns := cm.GetNamespace(); ns != NamespaceAteSystem {
		t.Errorf("configmap/%s is in namespace %q, want %q", k8sCredentialProviderPolicyConfigMap, ns, NamespaceAteSystem)
	}
}

// mountedConfigMaps returns the names of the ConfigMaps a Deployment's pod
// mounts as volumes.
func mountedConfigMaps(dep *unstructured.Unstructured) []string {
	volumes, _, _ := unstructured.NestedSlice(dep.Object, "spec", "template", "spec", "volumes")
	var names []string
	for _, v := range volumes {
		name, found, _ := unstructured.NestedString(v.(map[string]any), "configMap", "name")
		if found {
			names = append(names, name)
		}
	}
	return names
}
