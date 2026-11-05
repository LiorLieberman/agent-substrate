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
	"bufio"
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"math"
	"net"
	"net/http"
	"strconv"
	"time"

	"go.ate.dev/substrate/internal/egresspolicy"
)

const (
	// connectHeadTimeout bounds how long a producer takes to send its CONNECT.
	connectHeadTimeout = 10 * time.Second
	// maxConnectHead bounds the CONNECT head read from a producer.
	maxConnectHead = 8 << 10
)

// acceptConnect reads the CONNECT an in-guest producer sends first on each
// stream. It takes a host or an IP, and leaves the decision to the gateway.
func acceptConnect(ctx context.Context, downstream net.Conn) (net.Conn, string, func(error) error, error) {
	conn, destination, reply, err := readConnect(downstream)
	if err != nil {
		// The guest decides how often this happens, so it stays out of the
		// default log level.
		slog.DebugContext(ctx, "atunnel refused an egress CONNECT", slog.Any("err", err))
	}
	return conn, destination, reply, err
}

func readConnect(downstream net.Conn) (net.Conn, string, func(error) error, error) {
	if err := downstream.SetReadDeadline(time.Now().Add(connectHeadTimeout)); err != nil {
		return nil, "", nil, err
	}
	head := &io.LimitedReader{R: downstream, N: maxConnectHead}
	reader := bufio.NewReader(head)
	req, err := http.ReadRequest(reader)
	if err != nil {
		if head.N == 0 {
			_ = writeConnectStatus(downstream, http.StatusRequestHeaderFieldsTooLarge, "atunnel; error=http_request_error")
		}
		return nil, "", nil, fmt.Errorf("reading the CONNECT request: %w", err)
	}
	// Whatever follows the head is tunnel data.
	head.N = math.MaxInt64
	if err := downstream.SetReadDeadline(time.Time{}); err != nil {
		return nil, "", nil, err
	}

	if req.Method != http.MethodConnect {
		_ = writeConnectStatus(downstream, http.StatusMethodNotAllowed, "atunnel; error=http_request_denied")
		return nil, "", nil, fmt.Errorf("method %q is not CONNECT", req.Method)
	}
	dest, err := egresspolicy.NormalizeAuthority(req.Host)
	if err != nil || dest.Port == 0 {
		_ = writeConnectStatus(downstream, http.StatusBadRequest, "atunnel; error=http_request_error")
		return nil, "", nil, fmt.Errorf("CONNECT authority %q is not a host:port", req.Host)
	}
	// Matches a networked actor: nftables drop its link-local connections,
	// and its loopback ones stay in the guest.
	if ip := dest.IP; ip.IsValid() && (ip.IsLoopback() || ip.IsLinkLocalUnicast() || ip.IsLinkLocalMulticast() || ip.IsMulticast() || ip.IsUnspecified()) {
		_ = writeConnectStatus(downstream, http.StatusForbidden, "atunnel; error=destination_ip_prohibited")
		return nil, "", nil, fmt.Errorf("CONNECT to %s is not allowed", ip)
	}
	host := dest.Hostname
	if dest.IP.IsValid() {
		host = dest.IP.String()
	}
	reply := func(dialErr error) error {
		if dialErr == nil {
			_, err := io.WriteString(downstream, "HTTP/1.1 200 Connection Established\r\n\r\n")
			return err
		}
		code, proxyStatus := connectStatus(dialErr)
		return writeConnectStatus(downstream, code, proxyStatus)
	}
	return &bufferedConn{Conn: downstream, reader: reader}, net.JoinHostPort(host, strconv.Itoa(int(dest.Port))), reply, nil
}

// connectStatus is the status a producer sees when the tunnel failed to open,
// with an RFC 9209 Proxy-Status that names atunnel.
func connectStatus(err error) (int, string) {
	var rejected *ConnectRejectedError
	switch {
	case errors.As(err, &rejected):
		return rejected.StatusCode, fmt.Sprintf("atunnel; received-status=%d", rejected.StatusCode)
	case errors.Is(err, context.DeadlineExceeded):
		return http.StatusGatewayTimeout, "atunnel; error=connection_timeout"
	default:
		return http.StatusBadGateway, "atunnel; error=proxy_internal_error"
	}
}

func writeConnectStatus(w io.Writer, code int, proxyStatus string) error {
	_, err := fmt.Fprintf(w, "HTTP/1.1 %d %s\r\nProxy-Status: %s\r\nContent-Length: 0\r\n\r\n", code, http.StatusText(code), proxyStatus)
	return err
}
