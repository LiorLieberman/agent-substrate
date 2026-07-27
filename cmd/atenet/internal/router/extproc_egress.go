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

package router

import (
	"context"
	"log/slog"
	"strconv"
	"strings"

	extprocv3 "github.com/envoyproxy/go-control-plane/envoy/service/ext_proc/v3"
	envoy_type "github.com/envoyproxy/go-control-plane/envoy/type/v3"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/agent-substrate/substrate/internal/atunnel"
	"github.com/agent-substrate/substrate/internal/resources"
	"github.com/agent-substrate/substrate/pkg/proto/ateapipb"
)

const (
	// EgressListenerName is the Envoy listener that terminates actor egress
	// CONNECTs. It must stay in sync with the listener name in
	// manifests/ate-install/ateway-egress.yaml.
	EgressListenerName = "egress"
	// ListenerNameAttribute is the CEL attribute carrying the name of the
	// listener that accepted the request. The egress Envoy asks for it via
	// request_attributes on its ext_proc filter.
	ListenerNameAttribute = "xds.listener_name"
)

// isEgressRequest reports whether an ext_proc RequestHeaders callback arrived on
// the egress gateway's listener rather than on an ingress listener. This lets
// one ext_proc server handle both directions off the same stream.
//
// Dispatch is by listener, not by :method, because the two handlers apply
// opposite trust models: on egress the X-Ate-* identity headers are asserted by
// atunnel over mTLS, while on ingress the same headers are unauthenticated
// client input. Keying on :method would let any external client sending CONNECT
// select the egress handler and use its denial messages as an actor-existence
// and status oracle. Envoy asserts the listener name; the request cannot
// influence it.
//
// An unrecognised or absent attribute means ingress, the fail-safe direction: an
// egress request misrouted to the ingress handler fails to parse as an actor DNS
// name and 404s, whereas the reverse leaks control-plane state.
func isEgressRequest(req *extprocv3.ProcessingRequest) bool {
	return listenerName(req) == EgressListenerName
}

// listenerName returns the xds.listener_name attribute Envoy attached to the
// request, or "" when the listener did not request the attribute. The
// attributes map is keyed by the ext_proc filter's name within the HCM chain,
// which we do not want to hardcode here, so scan every entry.
func listenerName(req *extprocv3.ProcessingRequest) string {
	for _, attrs := range req.GetAttributes() {
		if v, ok := attrs.GetFields()[ListenerNameAttribute]; ok {
			return v.GetStringValue()
		}
	}
	return ""
}

// handleEgressRequestHeaders authenticates the actor identity that atunnel
// asserts on an egress CONNECT, before the gateway tunnels it out. This turns the
// worker-asserted X-Ate-* headers into a control-plane-verified identity.
//
// Authorization by destination and credential/token injection are deliberately
// a TODO once we have SessionIdentity RPC service figured out.
//
// The signature mirrors handleRequestHeaders so Process can dispatch to either
// with a single branch. The (target, tmplNs, tmplName) results are unused for
// egress and returned empty.
func (s *ExtProcServer) handleEgressRequestHeaders(
	ctx context.Context,
	reqHeaders *extprocv3.HttpHeaders,
) (*extprocv3.HeadersResponse, *requestMetadata, string, string, string, error) {
	metadata := newRequestMetadata(reqHeaders.Headers.GetHeaders())

	// Dispatch is by listener, so reaching here means the egress listener
	// accepted the request. That listener only routes CONNECT (its sole route
	// is a connect_matcher), so anything else is a config drift rather than a
	// client the gateway should tunnel for.
	if !strings.EqualFold(metadata.method, "CONNECT") {
		return nil, metadata, "", "", "", newReqError(envoy_type.StatusCode_MethodNotAllowed,
			"egress denied: expected CONNECT, got %q", metadata.method)
	}

	atespace := metadata.headers[strings.ToLower(atunnel.ActorAtespaceHeader)]
	actorName := metadata.headers[strings.ToLower(atunnel.ActorNameHeader)]
	assertedVersion := metadata.headers[strings.ToLower(atunnel.ActorVersionHeader)]
	// For a CONNECT the :authority is the actor's original destination (IP:port).
	destination := metadata.host

	if atespace == "" || actorName == "" {
		return nil, metadata, "", "", "", newReqError(envoy_type.StatusCode_Forbidden,
			"egress denied: missing actor identity headers")
	}
	if !resources.IsValidResourceName(atespace) || !resources.IsValidResourceName(actorName) {
		return nil, metadata, "", "", "", newReqError(envoy_type.StatusCode_Forbidden,
			"egress denied: invalid actor identity %q/%q", atespace, actorName)
	}

	// Authenticate the worker-asserted identity against the control plane. A
	// claimed-but-nonexistent actor (a spoofed identity) surfaces as NotFound.
	actor, err := s.apiClient.GetActor(ctx, &ateapipb.GetActorRequest{
		Actor: &ateapipb.ObjectRef{Atespace: atespace, Name: actorName},
	})
	if err != nil {
		return nil, metadata, "", "", "", mapEgressIdentityError(atespace, actorName, err)
	}

	// The actor performing egress must actually be running.
	if actor.GetStatus() != ateapipb.Actor_STATUS_RUNNING {
		return nil, metadata, "", "", "", newReqError(envoy_type.StatusCode_Forbidden,
			"egress denied: actor %q/%q is %s, not running", atespace, actorName, actor.GetStatus())
	}

	// X-Ate-Actor-Version is the Actor version the worker observed when it was
	// assigned, and atunnel documents it as a lower bound on trustworthy actor
	// metadata. If our authoritative view is older than what the worker asserts,
	// we cannot yet vouch for the identity, so reject rather than allow blindly.
	if assertedVersion != "" {
		if want, perr := strconv.ParseInt(assertedVersion, 10, 64); perr == nil && actor.GetMetadata().GetVersion() < want {
			return nil, metadata, "", "", "", newReqError(envoy_type.StatusCode_Forbidden,
				"egress denied: actor %q/%q metadata stale (known v%d < asserted v%d)",
				atespace, actorName, actor.GetMetadata().GetVersion(), want)
		}
	}

	slog.InfoContext(ctx, "egress identity authenticated",
		slog.String("atespace", atespace),
		slog.String("actor", actorName),
		slog.String("destination", destination),
		slog.String("status", actor.GetStatus().String()))

	// Identity is authenticated; let the CONNECT proceed unchanged. Milestone 2
	// would additionally authorize `destination` and inject upstream credentials
	// here by returning a HeaderMutation.
	return &extprocv3.HeadersResponse{
		Response: &extprocv3.CommonResponse{},
	}, metadata, "", "", "", nil
}

// mapEgressIdentityError converts a GetActor failure into a client-facing
// ext_proc denial. An unknown actor is treated as a forbidden (spoofed)
// identity; transient control-plane failures fail closed with 503.
func mapEgressIdentityError(atespace, actorName string, err error) error {
	switch status.Code(err) {
	case codes.NotFound:
		return newReqError(envoy_type.StatusCode_Forbidden,
			"egress denied: unknown actor %q/%q", atespace, actorName)
	case codes.Unavailable, codes.DeadlineExceeded:
		return newReqError(envoy_type.StatusCode_ServiceUnavailable,
			"egress identity check unavailable for %q/%q: %v", atespace, actorName, err)
	default:
		return newReqError(envoy_type.StatusCode_Forbidden,
			"egress denied for %q/%q: %v", atespace, actorName, err)
	}
}
