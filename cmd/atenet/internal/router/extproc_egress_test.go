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
	"testing"

	corev3 "github.com/envoyproxy/go-control-plane/envoy/config/core/v3"
	extprocv3 "github.com/envoyproxy/go-control-plane/envoy/service/ext_proc/v3"
	"google.golang.org/protobuf/types/known/structpb"
)

// connectRequest builds a RequestHeaders ProcessingRequest for a CONNECT
// carrying worker-asserted actor identity, optionally attributed to a listener.
// filterKey is the ext_proc filter name Envoy keys the attributes map by.
func connectRequest(filterKey, listener string) *extprocv3.ProcessingRequest {
	req := &extprocv3.ProcessingRequest{
		Request: &extprocv3.ProcessingRequest_RequestHeaders{
			RequestHeaders: &extprocv3.HttpHeaders{
				Headers: &corev3.HeaderMap{
					Headers: []*corev3.HeaderValue{
						{Key: ":method", RawValue: []byte("CONNECT")},
						{Key: ":authority", RawValue: []byte("10.0.0.9:443")},
						{Key: "x-ate-atespace", RawValue: []byte("default")},
						{Key: "x-ate-actor", RawValue: []byte("my-actor")},
					},
				},
			},
		},
	}
	if listener != "" {
		req.Attributes = map[string]*structpb.Struct{
			filterKey: {
				Fields: map[string]*structpb.Value{
					ListenerNameAttribute: structpb.NewStringValue(listener),
				},
			},
		}
	}
	return req
}

func TestIsEgressRequest(t *testing.T) {
	tests := []struct {
		name      string
		filterKey string
		listener  string
		want      bool
	}{
		{
			name:      "egress listener",
			filterKey: "envoy.filters.http.ext_proc",
			listener:  EgressListenerName,
			want:      true,
		},
		{
			name:      "egress listener under a renamed filter",
			filterKey: "some.custom.ext_proc.name",
			listener:  EgressListenerName,
			want:      true,
		},
		{
			// The pre-listener-dispatch hole: an external client sending
			// CONNECT to the ingress gateway must not reach the egress handler,
			// whose denials would otherwise report whether an arbitrary actor
			// exists and is running.
			name:      "CONNECT on the ingress HTTP listener",
			filterKey: "envoy.filters.http.ext_proc",
			listener:  IngressHTTPListener,
			want:      false,
		},
		{
			name:      "CONNECT on the ingress HTTPS listener",
			filterKey: "envoy.filters.http.ext_proc",
			listener:  IngressHTTPSListener,
			want:      false,
		},
		{
			// A listener that never requested the attribute falls back to
			// ingress, the fail-safe direction.
			name:     "no attributes at all",
			listener: "",
			want:     false,
		},
		{
			name:      "unrecognised listener",
			filterKey: "envoy.filters.http.ext_proc",
			listener:  "some-other-listener",
			want:      false,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if got := isEgressRequest(connectRequest(tc.filterKey, tc.listener)); got != tc.want {
				t.Errorf("isEgressRequest() = %v, want %v", got, tc.want)
			}
		})
	}
}

// A request the client dresses up to look like egress must not be enough: only
// the Envoy-asserted listener name selects the egress handler.
func TestIsEgressRequestIgnoresClientSuppliedAttributeHeader(t *testing.T) {
	req := connectRequest("envoy.filters.http.ext_proc", IngressHTTPListener)
	rh := req.GetRequestHeaders().GetHeaders()
	rh.Headers = append(rh.Headers,
		&corev3.HeaderValue{Key: ListenerNameAttribute, RawValue: []byte(EgressListenerName)},
		&corev3.HeaderValue{Key: "x-envoy-listener-name", RawValue: []byte(EgressListenerName)},
	)

	if isEgressRequest(req) {
		t.Error("isEgressRequest() = true for a client-forged listener header, want false")
	}
}
