// Copyright 2026 Alibaba Group Holding Ltd.
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

package apiproxy

import (
	"context"
	"errors"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/alibaba/opensandbox/egress/pkg/log"
	"github.com/alibaba/opensandbox/egress/pkg/policy"
	"github.com/alibaba/opensandbox/internal/safego"
	"github.com/alibaba/opensandbox/internal/version"
)

var hopByHopResponseHeaders = map[string]struct{}{
	"connection":          {},
	"keep-alive":          {},
	"proxy-authenticate":  {},
	"proxy-authorization": {},
	"te":                  {},
	"trailer":             {},
	"transfer-encoding":   {},
	"upgrade":             {},
}

var strippedRequestHeaders = map[string]struct{}{
	"authorization":       {},
	"proxy-authorization": {},
	"cookie":              {},
	"forwarded":           {},
	"via":                 {},
	"x-forwarded-for":     {},
	"x-forwarded-host":    {},
	"x-forwarded-proto":   {},
	"x-forwarded-port":    {},
	"x-real-ip":           {},
	"client-ip":           {},
	"true-client-ip":      {},
	"connection":          {},
	"proxy-connection":    {},
	"keep-alive":          {},
	"te":                  {},
	"trailer":             {},
	"transfer-encoding":   {},
	"upgrade":             {},
}

type PolicyReader interface {
	CurrentPolicy() *policy.NetworkPolicy
}

type Handler struct {
	policyReader PolicyReader
	client       *http.Client
	userAgent    string
}

func NewHandler(policyReader PolicyReader) *Handler {
	return &Handler{
		policyReader: policyReader,
		client: &http.Client{
			Timeout: 30 * time.Second,
		},
		userAgent: "opensandbox-egress-apiproxy/" + version.GitCommit,
	}
}

func StartServer(policyReader PolicyReader, addr string) (*http.Server, error) {
	handler := NewHandler(policyReader)
	srv := &http.Server{Addr: addr, Handler: handler}
	errCh := make(chan error, 1)

	safego.Go(func() {
		if err := srv.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
			errCh <- err
		}
	})

	select {
	case err := <-errCh:
		return nil, err
	case <-time.After(200 * time.Millisecond):
		safego.Go(func() {
			if err := <-errCh; err != nil {
				log.Errorf("api proxy server error: %v", err)
			}
		})
		return srv, nil
	}
}

func (h *Handler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	current := h.policyReader.CurrentPolicy()
	if current == nil || current.APIProxy == nil || !current.APIProxy.Enabled {
		http.Error(w, "api proxy disabled", http.StatusServiceUnavailable)
		return
	}
	if !current.APIProxy.Identity.IsReady() {
		http.Error(w, "identity_not_ready", http.StatusServiceUnavailable)
		return
	}

	path := r.URL.EscapedPath()
	if !isCanonicalPath(path) {
		http.Error(w, "path_not_canonical", http.StatusForbidden)
		return
	}

	route := longestPrefixMatch(current.APIProxy.Routes, path)
	if route == nil {
		http.Error(w, "path_not_allowed", http.StatusForbidden)
		return
	}

	upstreamURL := route.UpstreamURL + path
	if r.URL.RawQuery != "" {
		upstreamURL += "?" + r.URL.RawQuery
	}

	upstreamReq, err := http.NewRequestWithContext(r.Context(), r.Method, upstreamURL, r.Body)
	if err != nil {
		http.Error(w, "bad_upstream_request", http.StatusBadGateway)
		return
	}
	copyHeaders(upstreamReq.Header, r.Header, current.APIProxy, h.userAgent)

	resp, err := h.client.Do(upstreamReq)
	if err != nil {
		http.Error(w, "upstream_unreachable", http.StatusBadGateway)
		return
	}
	defer resp.Body.Close()

	copyResponseHeaders(w.Header(), resp.Header)
	w.WriteHeader(resp.StatusCode)
	_, _ = io.Copy(w, resp.Body)
}

func longestPrefixMatch(routes []policy.APIProxyRoute, path string) *policy.APIProxyRoute {
	var matched *policy.APIProxyRoute
	for i := range routes {
		route := &routes[i]
		if strings.HasPrefix(path, route.PathPrefix) {
			if matched == nil || len(route.PathPrefix) > len(matched.PathPrefix) {
				matched = route
			}
		}
	}
	return matched
}

func isCanonicalPath(path string) bool {
	if !strings.HasPrefix(path, "/") {
		return false
	}
	lower := strings.ToLower(path)
	for _, fragment := range []string{"//", "/./", "/../", "%2f", "%5c", "%2e"} {
		if strings.Contains(lower, fragment) {
			return false
		}
	}
	return true
}

func copyHeaders(dst, src http.Header, proxy *policy.APIProxy, userAgent string) {
	for key, values := range src {
		lower := strings.ToLower(key)
		if _, blocked := strippedRequestHeaders[lower]; blocked {
			continue
		}
		if strings.HasPrefix(lower, "cipherowl-") {
			continue
		}
		for _, value := range values {
			dst.Add(key, value)
		}
	}

	dst.Set("CipherOwl-Organization", proxy.Identity.Organization)
	dst.Set("CipherOwl-Organization-Id", proxy.Identity.OrganizationID)
	dst.Set("CipherOwl-User-Email", proxy.Identity.UserEmail)
	if proxy.AuthToken != "" {
		dst.Set("Authorization", "Bearer "+proxy.AuthToken)
	}
	dst.Set("User-Agent", userAgent)
}

func copyResponseHeaders(dst, src http.Header) {
	for key, values := range src {
		if _, blocked := hopByHopResponseHeaders[strings.ToLower(key)]; blocked {
			continue
		}
		for _, value := range values {
			dst.Add(key, value)
		}
	}
}

func Shutdown(ctx context.Context, srv *http.Server) error {
	if srv == nil {
		return nil
	}
	return srv.Shutdown(ctx)
}
