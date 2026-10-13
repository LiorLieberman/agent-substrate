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

package networking

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/agent-substrate/substrate/internal/e2e"
	"github.com/agent-substrate/substrate/internal/resources"
)

// The EgressPolicy half of egress: the other TestActorEgress* tests give their
// actors an allow-everything policy and prove traffic flows; these give theirs
// a narrow one and prove what does not. A request the gateway can read is
// decided per request on its Host, by the http rules in the clear and the
// https rules once decrypted.

// notTransient stops the retry loop on anything but the 503 a request sees
// while the actor's route is still propagating; a denial is a final answer.
func notTransient(status int, _ []byte) bool { return status != http.StatusServiceUnavailable }

// reached stops the retry loop only on success. A lane expecting the fetch to
// work sees more transients than the 503 above (the minted leaf fails
// verification until kubelet has propagated the CA pool), all of them 502s
// the actor cannot tell from a denial.
func reached(status int, _ []byte) bool { return status == http.StatusOK }

// TestActorEgressPolicyDeniesUnlistedHost: the policy names one hostname, so
// the origin is reachable by that name and refused by its address, which is
// the same server.
func TestActorEgressPolicyDeniesUnlistedHost(t *testing.T) {
	ctx := context.Background()
	dataplane := e2e.CurrentAtenetDataplane()
	origin := egressHTTPTarget()
	target := e2e.DeployServerPod(t, ctx, origin)
	allowed := fmt.Sprintf("%s.%s.svc.cluster.local", origin.Name, target.Namespace)

	_, actorName, _ := createAndResumeActorWithEgress(t, ctx, "egress-policy", e2e.EgressFixture(), e2e.EgressAllowHTTP(allowed))
	router := mustRouterClient(t, ctx)
	defer router.Close()
	actorRef := resources.ActorRef{Atespace: networkingAtespace, Name: actorName}

	url := "http://" + allowed + "/healthz"
	status, body := fetchThroughEgressActor(t, ctx, router, actorRef, url)
	if status != http.StatusOK {
		t.Fatalf("fetch of the allowed host %s returned HTTP %d, want 200; body: %s", url, status, body)
	}

	url = fmt.Sprintf("http://%s/healthz", target.Address())
	status, body = fetchThroughEgressActorUntil(t, ctx, router, actorRef, url, notTransient)
	if !dataplane.IsEgressPolicyDenied(status, string(body)) {
		t.Fatalf("fetch of the same origin by address %s returned HTTP %d, want an egress-policy denial; body: %s", url, status, body)
	}
	t.Logf("fetch by address was denied as expected: %s", body)
}

// TestActorEgressRequiresPolicy: an actor with no EgressPolicy is denied.
func TestActorEgressRequiresPolicy(t *testing.T) {
	ctx := context.Background()
	dataplane := e2e.CurrentAtenetDataplane()
	target := e2e.DeployServerPod(t, ctx, egressHTTPTarget())

	_, actorName, _ := createAndResumeActorWithEgress(t, ctx, "egress-nopolicy", e2e.EgressFixture())
	router := mustRouterClient(t, ctx)
	defer router.Close()
	actorRef := resources.ActorRef{Atespace: networkingAtespace, Name: actorName}

	// There is no allowed fetch to prove the route is up, so wait on the
	// demo's readiness endpoint; otherwise a 503 from a route not yet
	// propagated would look like the answer we want.
	waitForActorRoute(t, ctx, router, actorRef)

	url := fmt.Sprintf("http://%s/healthz", target.Address())
	status, body := fetchThroughEgressActorUntil(t, ctx, router, actorRef, url, notTransient)
	if !dataplane.IsEgressPolicyDenied(status, string(body)) {
		t.Fatalf("fetch by an actor with no policy returned HTTP %d, want an egress-policy denial; body: %s", status, body)
	}
	t.Logf("egress was denied as expected: %s", body)
}

// hostnameOrigins are the URLs of the in-cluster HTTPS origins the
// hostname-policy actor reaches.
type hostnameOrigins struct {
	// intercepted is allowed by an https rule, so the gateway terminates its TLS.
	intercepted string
	// relayed is allowed by a tls_passthrough rule. relayedRootCA is the only
	// CA that signs its certificate.
	relayed, relayedRootCA string
	// unlisted is the intercepted origin under a shorter name that no rule
	// lists. A gateway that wrongly let it through would reach the origin, so
	// a refusal is the policy's doing and not a failed lookup.
	unlisted string
}

// hostnamePolicyActor creates an actor whose policy intercepts HTTPS to one
// in-cluster origin, relays TLS to another and allows nothing else, and waits
// until it is routable.
func hostnamePolicyActor(t *testing.T, ctx context.Context) (*e2e.RouterClient, resources.ActorRef, hostnameOrigins) {
	t.Helper()
	interceptedHost, _ := hostnameOrigin(t, ctx, "intercepted")
	relayedHost, relayedRootCA := hostnameOrigin(t, ctx, "relayed")
	_, actorName, _ := createAndResumeActorWithEgress(t, ctx, "egress-sni", e2e.EgressFixture(), e2e.EgressAllowHTTPS(interceptedHost), e2e.EgressAllowPassthrough(relayedHost))
	router := mustRouterClient(t, ctx)
	t.Cleanup(func() { router.Close() })
	actorRef := resources.ActorRef{Atespace: networkingAtespace, Name: actorName}
	waitForActorRoute(t, ctx, router, actorRef)
	return router, actorRef, hostnameOrigins{
		intercepted:   "https://" + interceptedHost + "/healthz",
		relayed:       "https://" + relayedHost + "/healthz",
		relayedRootCA: relayedRootCA,
		unlisted:      "https://" + strings.TrimSuffix(interceptedHost, ".cluster.local") + "/healthz",
	}
}

// hostnameOrigin deploys an HTTPS origin on port 443 and returns the DNS name
// its certificate covers and the CA that signed it.
func hostnameOrigin(t *testing.T, ctx context.Context, name string) (string, string) {
	t.Helper()
	_, address, rootCA := prepareProtocolOrigin(t, ctx, e2e.ServerPod{
		Name:       name,
		ImportPath: "github.com/agent-substrate/substrate/internal/e2e/fixtures/testserver",
		Args:       []string{"http"},
		Port:       443,
		TargetPort: 8443,
	}, true)
	host, _, err := net.SplitHostPort(address)
	if err != nil {
		t.Fatalf("splitting origin address %q: %v", address, err)
	}
	return host, rootCA
}

// TestActorEgressHTTPSByHostnameMITM: the gateway terminates the TLS and decides
// each request by name: the listed origin 200, the unlisted name denied. The
// actor trusts the gateway's CA and public roots but not the origin's signer,
// so the 200 also proves the gateway minted the certificate.
func TestActorEgressHTTPSByHostnameMITM(t *testing.T) {
	ctx := context.Background()
	dataplane := e2e.CurrentAtenetDataplane()
	router, actorRef, origins := hostnamePolicyActor(t, ctx)

	status, body := fetchThroughEgressActorUntil(t, ctx, router, actorRef, origins.intercepted, reached)
	if status != http.StatusOK {
		t.Fatalf("fetch of the allowed host returned HTTP %d, want 200; body: %s", status, body)
	}
	status, body = fetchThroughEgressActorUntil(t, ctx, router, actorRef, origins.unlisted, notTransient)
	assertUnlistedDenied(t, dataplane, status, body)
	t.Logf("denied on the decrypted request: %s", body)
}

// TestActorEgressHTTPSByHostnamePassthrough: the gateway relays the TLS of the
// allowed SNI unread. The fetch trusts only the origin's signer, which the
// gateway holds no key for, so the 200 proves the certificate is the origin's.
func TestActorEgressHTTPSByHostnamePassthrough(t *testing.T) {
	ctx := context.Background()
	dataplane := e2e.CurrentAtenetDataplane()
	router, actorRef, origins := hostnamePolicyActor(t, ctx)

	payload, err := json.Marshal(map[string]string{"url": origins.relayed, "rootCA": origins.relayedRootCA})
	if err != nil {
		t.Fatalf("marshaling the fetch request for %s: %v", origins.relayed, err)
	}
	status, body := postThroughEgressActorUntil(t, ctx, router, actorRef, "/", payload, reached)
	if status != http.StatusOK {
		t.Fatalf("fetch of the allowed host trusting only its own CA returned HTTP %d, want 200; body: %s", status, body)
	}
	status, body = fetchThroughEgressActorUntil(t, ctx, router, actorRef, origins.unlisted, notTransient)
	assertUnlistedDenied(t, dataplane, status, body)
}

// assertUnlistedDenied fails unless the fetch of the unlisted name was refused
// by egress policy. On Envoy a refusal looks like any failed request, so a
// certificate error is ruled out by name: it means the gateway relayed the
// connection to the origin, whose signer the actor does not trust.
func assertUnlistedDenied(t *testing.T, dataplane e2e.AtenetDataplane, status int, body []byte) {
	t.Helper()
	if !dataplane.IsEgressPolicyDenied(status, string(body)) || strings.Contains(string(body), "x509") {
		t.Fatalf("fetch of a host outside the policy returned HTTP %d, want an egress-policy denial; body: %s", status, body)
	}
}

// fetchThroughEgressActorUntil is fetchThroughEgressActor with the caller
// deciding which answer is final.
func fetchThroughEgressActorUntil(t *testing.T, ctx context.Context, router *e2e.RouterClient, actorRef resources.ActorRef, url string, done func(status int, body []byte) bool) (int, []byte) {
	t.Helper()
	payload := []byte(fmt.Sprintf(`{"url":%q}`, url))
	return postThroughEgressActorUntil(t, ctx, router, actorRef, "/", payload, done)
}

// waitForActorRoute polls the demo app's readiness endpoint through the router
// until it answers, which is when the actor's route has reached the ingress
// dataplane.
func waitForActorRoute(t *testing.T, ctx context.Context, router *e2e.RouterClient, actorRef resources.ActorRef) {
	t.Helper()
	deadline := time.Now().Add(30 * time.Second)
	for {
		response, err := router.Get(ctx, actorRef, "/readyz")
		if err != nil {
			t.Fatalf("GET /readyz on the egress Actor through ingress: %v", err)
		}
		response.Body.Close()
		if response.StatusCode == http.StatusOK {
			return
		}
		if time.Now().After(deadline) {
			t.Fatalf("the egress Actor's route did not come up: GET /readyz returned HTTP %d", response.StatusCode)
		}
		time.Sleep(time.Second)
	}
}
