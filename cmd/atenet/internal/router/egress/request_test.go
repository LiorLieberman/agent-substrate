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

package egress

import (
	"context"
	"maps"
	"net"
	"strconv"
	"testing"
	"time"

	corev3 "github.com/envoyproxy/go-control-plane/envoy/config/core/v3"
	envoy_type "github.com/envoyproxy/go-control-plane/envoy/type/v3"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/types/known/structpb"

	"github.com/agent-substrate/substrate/cmd/atenet/internal/router/extproc"
	"github.com/agent-substrate/substrate/pkg/proto/ateapipb"
)

// testActorSPIFFEID is the identity filter state the CONNECT chain shares.
const testActorSPIFFEID = "spiffe://substrate-actor.local/ateom-for-actor/default/my-actor"

// testDialed is the IP:port the test actor's kernel dialed for a callout on
// leg: the default port of the protocol that leg carries.
func testDialed(leg string) string {
	if leg == extproc.EgressTLSMITMFilterChainName {
		return "93.184.216.34:443"
	}
	return "93.184.216.34:80"
}

func sampleEffects() *ateapipb.HttpRuleEffects {
	return &ateapipb.HttpRuleEffects{ReplaceHeaders: []*ateapipb.CredentialHeaderInjection{{
		Header: "authorization", Prefix: "Bearer ", CredentialUri: "ate-secret://k8s/default/token",
	}}}
}

// credentialInjectionPolicySample is an https rule for pattern that replaces
// the authorization header, which only the MITM leg can honor.
func credentialInjectionPolicySample(pattern string) *ateapipb.EgressPolicy {
	return &ateapipb.EgressPolicy{Rules: []*ateapipb.EgressRule{{
		Https: &ateapipb.HTTPSRule{HostPatterns: []string{pattern}, Effects: sampleEffects()},
	}}}
}

// cleartextInjectionPolicy is the same replacement on an http rule.
func cleartextInjectionPolicy(pattern string) *ateapipb.EgressPolicy {
	return &ateapipb.EgressPolicy{Rules: []*ateapipb.EgressRule{{
		Http: &ateapipb.HTTPRule{HostPatterns: []string{pattern}, Effects: sampleEffects()},
	}}}
}

// policyHandler builds a Handler for an actor whose policy is policy (nil
// means none) with the cache disabled, so each callout sees the mock as is.
func policyHandler(policy *ateapipb.EgressPolicy) *Handler {
	return New(&egressMockClient{actor: runningActor(), policy: policy}, nil, 0, nil, "")
}

// innerMetadata builds an inner chain's callout: pseudo-headers plus the
// attributes that chain requests, as after a CONNECT to testDialed(leg) that a
// passthrough rule allowed. attrs overrides the defaults; an empty value
// deletes one.
func innerMetadata(leg, method, authority string, attrs map[string]string) *extproc.RequestMetadata {
	fields := map[string]string{
		extproc.FilterChainNameAttribute:          leg,
		extproc.ActorIdentityFilterStateAttribute: testActorSPIFFEID,
	}
	maps.Copy(fields, dialedAttributes(testDialed(leg)))
	for k, v := range attrs {
		if v == "" {
			delete(fields, k)
			continue
		}
		fields[k] = v
	}
	values := map[string]*structpb.Value{}
	for k, v := range fields {
		// Envoy sends the port field as a number.
		if n, err := strconv.Atoi(v); err == nil && k == extproc.OriginalDstPortAttribute {
			values[k] = structpb.NewNumberValue(float64(n))
			continue
		}
		values[k] = structpb.NewStringValue(v)
	}
	return extproc.NewRequestMetadata([]*corev3.HeaderValue{
		{Key: ":method", RawValue: []byte(method)},
		{Key: ":authority", RawValue: []byte(authority)},
		{Key: ":path", RawValue: []byte("/v1/things?secret=1")},
	}, map[string]*structpb.Struct{"envoy.filters.http.ext_proc": {Fields: values}})
}

// dialedAttributes is what Envoy sends after a CONNECT to hostport that a
// passthrough rule allowed: the CONNECT authority the outer chain shares, and
// the ORIGINAL_DST filter state the answer set, as address and port fields.
// Something that is not host:port at all goes in the address field as is.
func dialedAttributes(hostport string) map[string]string {
	ip, port, err := net.SplitHostPort(hostport)
	if err != nil {
		ip, port = hostport, ""
	}
	return map[string]string{
		extproc.ConnectAuthorityFilterStateAttribute: hostport,
		extproc.OriginalDstIPAttribute:               ip,
		extproc.OriginalDstPortAttribute:             port,
	}
}

// noDialed removes the ORIGINAL_DST filter state: the CONNECT leg allowed
// nothing, so the tunnel opened with nothing to dial. The CONNECT authority is
// still there; the outer chain sets it whatever the decision.
var noDialed = map[string]string{extproc.OriginalDstIPAttribute: "", extproc.OriginalDstPortAttribute: ""}

func requestMetadata(authority string) *extproc.RequestMetadata {
	return innerMetadata(extproc.EgressCleartextFilterChainName, "GET", authority, nil)
}

func wantAllowed(t *testing.T, res extproc.Result, err error) {
	t.Helper()
	if err != nil {
		t.Fatalf("HandleRequestHeaders() error = %v, want an allow", err)
	}
	if res.Response == nil {
		t.Fatal("HandleRequestHeaders() allowed without a response")
	}
}

func TestHandleRequestHeadersRefusesUnknownFilterChain(t *testing.T) {
	h := policyHandler(allowAllPolicy())
	_, err := h.HandleRequestHeaders(context.Background(), innerMetadata("some_other_chain", "GET", "example.com", nil))
	wantStatus(t, err, envoy_type.StatusCode_NotFound)
}

// combined is one policy with the rules of policies, in order.
func combined(policies ...*ateapipb.EgressPolicy) *ateapipb.EgressPolicy {
	out := &ateapipb.EgressPolicy{}
	for _, p := range policies {
		out.Rules = append(out.Rules, p.Rules...)
	}
	return out
}

// dialOf reads where an allowed request was sent, or "" when the answer said
// nothing.
func dialOf(res extproc.Result) string {
	return res.DynamicMetadata.GetFields()[extproc.EgressMetadataNamespace].GetStructValue().GetFields()[extproc.EgressDialKey].GetStringValue()
}

// wantDial checks an allowed request's answer: the dial the routes match on,
// with the route cache cleared so Envoy matches again.
func wantDial(t *testing.T, res extproc.Result, err error, want string) {
	t.Helper()
	wantAllowed(t, res, err)
	if !res.Response.GetResponse().GetClearRouteCache() {
		t.Error("allowed without clearing the route cache; Envoy would keep the route it picked before ext_proc ran")
	}
	if res.Response.GetResponse().GetHeaderMutation() == nil {
		t.Error("allowed without a header mutation; ext_proc ignores clear_route_cache without one")
	}
	if got := dialOf(res); got != want {
		t.Errorf("dial = %q, want %q", got, want)
	}
}

// The cleartext leg decides on the Host the request named and the port the
// actor dialed (80 unless a case says otherwise), by the http rules, unless
// the address the actor dialed is one a passthrough rule allowed, in which
// case the request goes there unread. The answer says which of the two gets
// dialed.
func TestRequestLegDecidesHostAndDialedAddress(t *testing.T) {
	nameAndPassthrough := combined(httpPolicyOnPorts([]string{"*"}, "api.example.com"), passthroughPolicy([]string{"80"}, "*"))
	passthroughAndName := combined(passthroughPolicy([]string{"80"}, "*"), httpPolicyOnPorts([]string{"*"}, "api.example.com"))
	tests := []struct {
		name        string
		policy      *ateapipb.EgressPolicy
		authority   string
		dialed      string                // overrides the default 93.184.216.34:80
		noDialed    bool                  // the CONNECT leg allowed nothing, so there is no address
		noAuthority bool                  // a dataplane that does not share the CONNECT authority
		want        envoy_type.StatusCode // 0 means allowed
		dial        string
	}{
		{name: "exact hostname", policy: httpPolicy("api.example.com"), authority: "api.example.com", dial: extproc.EgressDialName},
		{name: "hostname case folded", policy: httpPolicy("api.example.com"), authority: "API.Example.com", dial: extproc.EgressDialName},
		{name: "hostname with trailing dot", policy: httpPolicy("api.example.com"), authority: "api.example.com.", dial: extproc.EgressDialName},
		{name: "wildcard hostname", policy: httpPolicy("*.example.com"), authority: "api.example.com", dial: extproc.EgressDialName},
		{name: "star hostname", policy: httpPolicy("*"), authority: "anything.example", noDialed: true, dial: extproc.EgressDialName},
		{name: "hostname with no dialed address", policy: httpPolicy("api.example.com"), authority: "api.example.com", noDialed: true, dial: extproc.EgressDialName},
		// The port in the Host is neither matched nor dialed; the dialed port is.
		{name: "host port is ignored, dialed port matches", policy: httpPolicy("api.example.com"), authority: "api.example.com:8443", dial: extproc.EgressDialName},
		{name: "host port is ignored, dialed port does not match", policy: httpPolicy("api.example.com"), authority: "api.example.com:80", dialed: "93.184.216.34:8080", noDialed: true, want: envoy_type.StatusCode_Forbidden},
		{name: "dialed port in the http rule", policy: httpPolicyOnPorts([]string{"8080"}, "api.example.com"), authority: "api.example.com", dialed: "93.184.216.34:8080", noDialed: true, dial: extproc.EgressDialName},
		{name: "dialed port outside the http rule", policy: httpPolicy("api.example.com"), authority: "api.example.com", dialed: "93.184.216.34:8080", noDialed: true, want: envoy_type.StatusCode_Forbidden},
		{name: "any port in the http rule", policy: httpPolicyOnPorts([]string{"*"}, "api.example.com"), authority: "api.example.com", dialed: "93.184.216.34:8080", noDialed: true, dial: extproc.EgressDialName},
		{name: "no CONNECT authority leaves ports unenforced", policy: httpPolicyOnPorts([]string{"8080"}, "api.example.com"), authority: "api.example.com", noDialed: true, noAuthority: true, dial: extproc.EgressDialName},
		{name: "allow-all policy goes to the dialed address", policy: allowAllPolicy(), authority: "anything.example", dial: extproc.EgressDialAddress},
		{name: "dialed port in a passthrough rule, request by name", policy: passthroughPolicy([]string{"80"}, "*"), authority: "evil.example", dial: extproc.EgressDialAddress},
		{name: "dialed port in a passthrough rule, request by ip literal", policy: passthroughPolicy([]string{"80"}, "*"), authority: "203.0.113.9:8080", dial: extproc.EgressDialAddress},
		{name: "ipv6 dialed address", policy: passthroughPolicy([]string{"443"}, "*"), authority: "api.example.com", dialed: "[2001:db8::7]:443", dial: extproc.EgressDialAddress},
		{name: "passthrough rule wins over a matching http rule", policy: nameAndPassthrough, authority: "api.example.com", dial: extproc.EgressDialAddress},
		{name: "passthrough rule wins whatever the order", policy: passthroughAndName, authority: "api.example.com", dial: extproc.EgressDialAddress},
		{name: "passthrough rule on another port falls through to the name", policy: passthroughAndName, authority: "api.example.com", dialed: "198.51.100.1:8443", dial: extproc.EgressDialName},
		{name: "other hostname", policy: httpPolicy("api.example.com"), authority: "evil.example", want: envoy_type.StatusCode_Forbidden},
		{name: "wildcard does not match the apex", policy: httpPolicy("*.example.com"), authority: "example.com", want: envoy_type.StatusCode_Forbidden},
		{name: "wildcard does not match two labels", policy: httpPolicy("*.example.com"), authority: "a.b.example.com", want: envoy_type.StatusCode_Forbidden},
		{name: "ip literal host with http policy", policy: httpPolicy("api.example.com"), authority: "93.184.216.34", want: envoy_type.StatusCode_Forbidden},
		{name: "ip literal host with star", policy: httpPolicy("*"), authority: "93.184.216.34", noDialed: true, want: envoy_type.StatusCode_Forbidden},
		{name: "https rule does not decide the cleartext leg", policy: httpsPolicy("api.example.com"), authority: "api.example.com", noDialed: true, want: envoy_type.StatusCode_Forbidden},
		// The Host literal names a port a passthrough rule allows but the actor
		// dialed another; the dialed port is what the rule checks.
		{name: "host literal port is not the dialed port", policy: passthroughPolicy([]string{"8080"}, "*"), authority: "203.0.113.9:8080", want: envoy_type.StatusCode_Forbidden},
		{name: "dialed port outside the passthrough rule", policy: passthroughPolicy([]string{"8080"}, "*"), authority: "api.example.com", want: envoy_type.StatusCode_Forbidden},
		{name: "named SNI in a passthrough rule cannot be checked", policy: passthroughPolicy([]string{"80"}, "api.example.com"), authority: "api.example.com", want: envoy_type.StatusCode_Forbidden},
		{name: "no dialed address with a passthrough-only policy", policy: passthroughPolicy([]string{"*"}, "*"), authority: "api.example.com", noDialed: true, want: envoy_type.StatusCode_Forbidden},
		{name: "unparseable dialed address", policy: allowAllPolicy(), authority: "api.example.com", dialed: "not an address:443", want: envoy_type.StatusCode_Forbidden},
		{name: "name in the dialed address field", policy: allowAllPolicy(), authority: "api.example.com", dialed: "example.com:443", want: envoy_type.StatusCode_Forbidden},
		{name: "dialed address without a port", policy: allowAllPolicy(), authority: "api.example.com", dialed: "93.184.216.34", want: envoy_type.StatusCode_Forbidden},
		{name: "unparseable host", policy: allowAllPolicy(), authority: "exa mple.com", want: envoy_type.StatusCode_Forbidden},
		{name: "empty host", policy: allowAllPolicy(), authority: "", want: envoy_type.StatusCode_Forbidden},
		// On the cleartext leg a rule that requires injection is let through
		// without the credential, not denied: the secret is never re-originated in
		// the clear, and blocking allowed egress is worse than an unauthenticated
		// request. See the dedicated injection tests for the TLS leg.
		{name: "cleartext rule requires injection passes through uninjected", policy: cleartextInjectionPolicy("api.example.com"), authority: "api.example.com", dial: extproc.EgressDialName},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			attrs := map[string]string{}
			if tc.dialed != "" {
				maps.Copy(attrs, dialedAttributes(tc.dialed))
			}
			if tc.noDialed {
				maps.Copy(attrs, noDialed)
			}
			if tc.noAuthority {
				attrs[extproc.ConnectAuthorityFilterStateAttribute] = ""
			}
			h := policyHandler(tc.policy)
			res, err := h.HandleRequestHeaders(context.Background(), innerMetadata(extproc.EgressCleartextFilterChainName, "GET", tc.authority, attrs))
			if tc.want == 0 {
				wantDial(t, res, err, tc.dial)
				return
			}
			wantStatus(t, err, tc.want)
		})
	}
}

func TestRequestLegServesBothDecryptedChains(t *testing.T) {
	h := policyHandler(combined(httpPolicy("api.example.com"), httpsPolicy("api.example.com"), passthroughPolicy([]string{"*"}, "*")))
	for _, leg := range []string{extproc.EgressCleartextFilterChainName, extproc.EgressTLSMITMFilterChainName} {
		res, err := h.HandleRequestHeaders(context.Background(), innerMetadata(leg, "POST", "api.example.com", noDialed))
		wantDial(t, res, err, extproc.EgressDialName)
		_, err = h.HandleRequestHeaders(context.Background(), innerMetadata(leg, "POST", "other.example", noDialed))
		wantStatus(t, err, envoy_type.StatusCode_Forbidden)
		// Inside a connection the passthrough rule allowed, the name no longer
		// matters.
		res, err = h.HandleRequestHeaders(context.Background(), innerMetadata(leg, "POST", "other.example", nil))
		wantDial(t, res, err, extproc.EgressDialAddress)
	}
}

// The leg says what the actor sent: the cleartext chain is decided by the
// http rules and the MITM chain by the https rules, never the other way.
func TestRequestLegPicksRulesByLeg(t *testing.T) {
	for _, tc := range []struct {
		policy *ateapipb.EgressPolicy
		leg    string
		want   envoy_type.StatusCode // 0 means allowed
	}{
		{policy: httpPolicy("api.example.com"), leg: extproc.EgressCleartextFilterChainName},
		{policy: httpPolicy("api.example.com"), leg: extproc.EgressTLSMITMFilterChainName, want: envoy_type.StatusCode_Forbidden},
		{policy: httpsPolicy("api.example.com"), leg: extproc.EgressTLSMITMFilterChainName},
		{policy: httpsPolicy("api.example.com"), leg: extproc.EgressCleartextFilterChainName, want: envoy_type.StatusCode_Forbidden},
	} {
		h := policyHandler(tc.policy)
		res, err := h.HandleRequestHeaders(context.Background(), innerMetadata(tc.leg, "GET", "api.example.com", noDialed))
		if tc.want == 0 {
			wantDial(t, res, err, extproc.EgressDialName)
			continue
		}
		wantStatus(t, err, tc.want)
	}
}

// Without the identity the outer chain shares, a request cannot be attributed
// to any actor and is refused.
func TestRequestLegRequiresIdentity(t *testing.T) {
	h := policyHandler(allowAllPolicy())
	for name, identity := range map[string]string{
		"absent":               "",
		"not a spiffe id":      "api.example.com",
		"another trust domain": "spiffe://cluster.local/ns/default/sa/thing",
		"truncated":            "spiffe://substrate-actor.local/atespace/default",
	} {
		t.Run(name, func(t *testing.T) {
			md := innerMetadata(extproc.EgressCleartextFilterChainName, "GET", "api.example.com",
				map[string]string{extproc.ActorIdentityFilterStateAttribute: identity})
			_, err := h.HandleRequestHeaders(context.Background(), md)
			wantStatus(t, err, envoy_type.StatusCode_Forbidden)
		})
	}
}

func TestRequestLegPolicyLookup(t *testing.T) {
	tests := []struct {
		name   string
		client *egressMockClient
		want   envoy_type.StatusCode
	}{
		{name: "no policy", client: &egressMockClient{}, want: envoy_type.StatusCode_Forbidden},
		{name: "policy with no rules", client: &egressMockClient{policy: &ateapipb.EgressPolicy{}}, want: envoy_type.StatusCode_Forbidden},
		{name: "control plane unavailable", client: &egressMockClient{policyErr: status.Error(codes.Unavailable, "down")}, want: envoy_type.StatusCode_ServiceUnavailable},
		{name: "control plane refuses", client: &egressMockClient{policyErr: status.Error(codes.PermissionDenied, "no")}, want: envoy_type.StatusCode_ServiceUnavailable},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			h := New(tc.client, nil, 0, nil, "")
			_, err := h.HandleRequestHeaders(context.Background(), requestMetadata("api.example.com"))
			wantStatus(t, err, tc.want)
		})
	}
}

// The CONNECT leg refuses to open a tunnel for an actor with nothing that
// could be allowed through it, and warms the cache for the requests inside.
func TestConnectLegRequiresAPolicy(t *testing.T) {
	ca := newTestCA(t, "actor-identity-ca")
	leaf := ca.issueActorCert(t, "spiffe://substrate-actor.local/ateom-for-actor/default/my-actor", actorCertOptions{})

	tests := []struct {
		name   string
		client *egressMockClient
		want   envoy_type.StatusCode // 0 means allowed
	}{
		{name: "policy present", client: &egressMockClient{actor: runningActor(), policy: allowAllPolicy()}},
		{name: "http-only policy still opens the tunnel", client: &egressMockClient{actor: runningActor(), policy: httpPolicy("api.example.com")}},
		{name: "no policy", client: &egressMockClient{actor: runningActor()}, want: envoy_type.StatusCode_Forbidden},
		{name: "policy with no rules", client: &egressMockClient{actor: runningActor(), policy: &ateapipb.EgressPolicy{Rules: []*ateapipb.EgressRule{}}}, want: envoy_type.StatusCode_Forbidden},
		{name: "control plane unavailable", client: &egressMockClient{actor: runningActor(), policyErr: status.Error(codes.Unavailable, "down")}, want: envoy_type.StatusCode_ServiceUnavailable},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			h := New(tc.client, ca.roots(), DefaultPolicyCacheTTL, nil, "")
			res, err := h.HandleRequestHeaders(context.Background(), egressMetadata(xfccHeader(leaf)))
			if tc.want == 0 {
				wantAllowed(t, res, err)
				if calls := tc.client.policyCalls.Load(); calls != 1 {
					t.Errorf("GetActorEgressPolicy calls = %d, want 1", calls)
				}
				// The CONNECT warmed the cache: the first request inside the
				// tunnel costs no control-plane call.
				if _, err := h.HandleRequestHeaders(context.Background(), requestMetadata("api.example.com")); err != nil {
					t.Fatalf("request inside the tunnel: %v", err)
				}
				if calls := tc.client.policyCalls.Load(); calls != 1 {
					t.Errorf("GetActorEgressPolicy calls after the first request = %d, want 1", calls)
				}
				return
			}
			wantStatus(t, err, tc.want)
		})
	}
}

// The request legs police :authority because that is what a by-name dial
// resolves; a Host header that disagrees with it is refused rather than
// trusted either way.
func TestRequestLegRefusesAuthorityHostMismatch(t *testing.T) {
	h := policyHandler(httpPolicy("api.example.com"))
	md := requestMetadata("api.example.com")
	md.Headers["host"] = "evil.example"
	_, err := h.HandleRequestHeaders(context.Background(), md)
	wantStatus(t, err, envoy_type.StatusCode_Forbidden)

	// The same name spelled differently is not a disagreement.
	md = requestMetadata("api.example.com")
	md.Headers["host"] = "API.example.com."
	res, err := h.HandleRequestHeaders(context.Background(), md)
	wantAllowed(t, res, err)
}

// A denial's body is fixed; the reason stays in the log.
func TestDenialBodyIsUniform(t *testing.T) {
	h := policyHandler(httpPolicy("api.example.com"))
	for _, md := range []*extproc.RequestMetadata{
		requestMetadata("evil.example"),
		requestMetadata("exa mple.com"),
		innerMetadata(extproc.EgressTLSMITMFilterChainName, "GET", "evil.example", nil),
	} {
		_, err := h.HandleRequestHeaders(context.Background(), md)
		if err == nil || err.Error() != deniedBody {
			t.Errorf("denial body = %v, want %q", err, deniedBody)
		}
	}
}

// A caller that gives up mid-fetch is neither a denial nor an outage.
func TestCanceledCallerIsNotAPolicyFailure(t *testing.T) {
	client := &egressMockClient{policy: allowAllPolicy(), policyGate: make(chan struct{})}
	h := New(client, nil, 0, nil, "")
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() {
		_, err := h.HandleRequestHeaders(ctx, requestMetadata("example.com"))
		done <- err
	}()
	deadline := time.Now().Add(5 * time.Second)
	for client.policyCalls.Load() == 0 {
		if time.Now().After(deadline) {
			t.Fatal("no fetch started")
		}
		time.Sleep(time.Millisecond)
	}
	cancel()
	err := <-done
	close(client.policyGate)
	wantStatus(t, err, envoy_type.StatusCode_RequestTimeout)
}
