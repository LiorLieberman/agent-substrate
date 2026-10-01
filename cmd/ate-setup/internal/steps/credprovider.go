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

	"github.com/agent-substrate/substrate/cmd/ate-setup/internal/config"
	"github.com/agent-substrate/substrate/cmd/ate-setup/internal/log"
)

// The bundled Kubernetes Secrets credential provider's manifests. They live
// outside the ate-install tree because an install carries the provider only
// when --credential-provider-name selects it. sample-secret.yaml in the same
// directory is documentation and is never applied.
const (
	k8sCredentialProviderDir            = "manifests/egress-credential-injection"
	k8sCredentialProviderManifest       = "k8s-credential-provider.yaml"
	k8sCredentialProviderPolicyManifest = "namespace-policy.yaml"

	// Names the manifests above declare; credprovider_test.go keeps them in step.
	k8sCredentialProviderDeployment      = "k8s-credential-provider"
	k8sCredentialProviderPolicyConfigMap = "k8s-credential-provider-namespace-policy"
)

func (e *Env) k8sCredentialProviderPath(manifest string) string {
	return e.Cfg.Path(k8sCredentialProviderDir, manifest)
}

// reconcileK8sCredentialProvider deploys the bundled Kubernetes Secrets
// credential provider when provider selects it, and removes one left by an
// earlier install otherwise: the gateway fronts one provider, and a provider
// nothing points at should not keep its cluster-wide Secret read.
//
// The namespace policy ConfigMap is created only when absent. The provider
// mounts it, so it has to exist before the first pod starts, but it is the
// operator's atespace allow-list and a redeploy must not reset it.
func (e *Env) reconcileK8sCredentialProvider(ctx context.Context, provider config.CredentialProvider) error {
	manifest := e.k8sCredentialProviderPath(k8sCredentialProviderManifest)
	if !provider.Kubernetes() {
		running, err := e.Kube.DeploymentExists(ctx, e.Namespace(), k8sCredentialProviderDeployment)
		if err != nil || !running {
			return err
		}
		log.Step("remove_k8s_credential_provider")
		return e.Kube.DeletePath(ctx, manifest)
	}

	log.Step("deploy_k8s_credential_provider")
	exists, err := e.Kube.ConfigMapExists(ctx, e.Namespace(), k8sCredentialProviderPolicyConfigMap)
	if err != nil {
		return err
	}
	if !exists {
		if err := e.Kube.ApplyPath(ctx, e.k8sCredentialProviderPath(k8sCredentialProviderPolicyManifest)); err != nil {
			return err
		}
	}
	return e.renderResolveApply(ctx, manifest)
}
