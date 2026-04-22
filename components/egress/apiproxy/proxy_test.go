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
	"io"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/alibaba/opensandbox/egress/pkg/policy"
	"github.com/stretchr/testify/require"
)

type stubPolicyReader struct {
	current *policy.NetworkPolicy
}

func (s *stubPolicyReader) CurrentPolicy() *policy.NetworkPolicy {
	return s.current
}

func TestHandlerRejectsNonCanonicalPath(t *testing.T) {
	reader := &stubPolicyReader{
		current: &policy.NetworkPolicy{
			APIProxy: &policy.APIProxy{
				Enabled: true,
				Identity: policy.APIProxyIdentity{
					Organization:   "acme",
					OrganizationID: "org-123",
					UserEmail:      "alice@example.com",
				},
				Routes: []policy.APIProxyRoute{{
					PathPrefix:  "/api/reason/",
					UpstreamURL: "http://reason.reason-dev.svc.cluster.local:8080",
				}},
			},
		},
	}

	req := httptest.NewRequest(http.MethodGet, "http://localhost/api/reason/%2e%2e/v1/x", nil)
	w := httptest.NewRecorder()

	NewHandler(reader).ServeHTTP(w, req)

	require.Equal(t, http.StatusForbidden, w.Code)
	require.Contains(t, w.Body.String(), "path_not_canonical")
}

func TestHandlerRejectsMissingRoute(t *testing.T) {
	reader := &stubPolicyReader{
		current: &policy.NetworkPolicy{
			APIProxy: &policy.APIProxy{
				Enabled: true,
				Identity: policy.APIProxyIdentity{
					Organization:   "acme",
					OrganizationID: "org-123",
					UserEmail:      "alice@example.com",
				},
				Routes: []policy.APIProxyRoute{{
					PathPrefix:  "/api/reason/",
					UpstreamURL: "http://reason.reason-dev.svc.cluster.local:8080",
				}},
			},
		},
	}

	req := httptest.NewRequest(http.MethodGet, "http://localhost/api/admin/users", nil)
	w := httptest.NewRecorder()

	NewHandler(reader).ServeHTTP(w, req)

	require.Equal(t, http.StatusForbidden, w.Code)
	require.Contains(t, w.Body.String(), "path_not_allowed")
}

func TestHandlerStripsForgedHeadersAndInjectsTrustedIdentity(t *testing.T) {
	var seenHeaders http.Header
	var seenPath string
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		seenHeaders = r.Header.Clone()
		seenPath = r.URL.EscapedPath()
		_, _ = io.WriteString(w, "ok")
	}))
	defer upstream.Close()

	reader := &stubPolicyReader{
		current: &policy.NetworkPolicy{
			APIProxy: &policy.APIProxy{
				Enabled: true,
				Identity: policy.APIProxyIdentity{
					Organization:   "acme",
					OrganizationID: "org-123",
					UserEmail:      "alice@example.com",
				},
				Routes: []policy.APIProxyRoute{{
					PathPrefix:  "/api/reason/",
					UpstreamURL: upstream.URL,
				}},
			},
		},
	}

	req := httptest.NewRequest(http.MethodGet, "http://localhost/api/reason/v2/chains/evm/addresses/0x1/detail", nil)
	req.Header.Set("CipherOwl-Organization", "evil")
	req.Header.Set("CipherOwl-Organization-Id", "evil-id")
	req.Header.Set("CipherOwl-User-Email", "evil@example.com")
	req.Header.Set("Authorization", "Bearer fake")
	req.Header.Set("X-Forwarded-For", "1.2.3.4")
	w := httptest.NewRecorder()

	NewHandler(reader).ServeHTTP(w, req)

	require.Equal(t, http.StatusOK, w.Code)
	require.Equal(t, "/api/reason/v2/chains/evm/addresses/0x1/detail", seenPath)
	require.Equal(t, "acme", seenHeaders.Get("CipherOwl-Organization"))
	require.Equal(t, "org-123", seenHeaders.Get("CipherOwl-Organization-Id"))
	require.Equal(t, "alice@example.com", seenHeaders.Get("CipherOwl-User-Email"))
	require.Empty(t, seenHeaders.Get("Authorization"))
	require.Empty(t, seenHeaders.Get("X-Forwarded-For"))
}

func TestHandlerInjectsAuthTokenWhenPresent(t *testing.T) {
	var seenHeaders http.Header
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		seenHeaders = r.Header.Clone()
		_, _ = io.WriteString(w, "ok")
	}))
	defer upstream.Close()

	reader := &stubPolicyReader{
		current: &policy.NetworkPolicy{
			APIProxy: &policy.APIProxy{
				Enabled: true,
				Identity: policy.APIProxyIdentity{
					Organization:   "acme",
					OrganizationID: "org-123",
					UserEmail:      "alice@example.com",
				},
				AuthToken: "trusted-service-token",
				Routes: []policy.APIProxyRoute{{
					PathPrefix:  "/api/reason/",
					UpstreamURL: upstream.URL,
				}},
			},
		},
	}

	req := httptest.NewRequest(http.MethodGet, "http://localhost/api/reason/v2/detail", nil)
	req.Header.Set("Authorization", "Bearer sandbox-forged")
	w := httptest.NewRecorder()

	NewHandler(reader).ServeHTTP(w, req)

	require.Equal(t, http.StatusOK, w.Code)
	require.Equal(t, "Bearer trusted-service-token", seenHeaders.Get("Authorization"))
	require.Equal(t, "acme", seenHeaders.Get("CipherOwl-Organization"))
}

func TestHandlerOmitsAuthorizationWhenNoToken(t *testing.T) {
	var seenHeaders http.Header
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		seenHeaders = r.Header.Clone()
		_, _ = io.WriteString(w, "ok")
	}))
	defer upstream.Close()

	reader := &stubPolicyReader{
		current: &policy.NetworkPolicy{
			APIProxy: &policy.APIProxy{
				Enabled: true,
				Identity: policy.APIProxyIdentity{
					Organization:   "acme",
					OrganizationID: "org-123",
					UserEmail:      "alice@example.com",
				},
				Routes: []policy.APIProxyRoute{{
					PathPrefix:  "/api/reason/",
					UpstreamURL: upstream.URL,
				}},
			},
		},
	}

	req := httptest.NewRequest(http.MethodGet, "http://localhost/api/reason/v2/detail", nil)
	w := httptest.NewRecorder()

	NewHandler(reader).ServeHTTP(w, req)

	require.Equal(t, http.StatusOK, w.Code)
	require.Empty(t, seenHeaders.Get("Authorization"))
}

func TestHandlerUsesLongestPrefixMatch(t *testing.T) {
	var firstHits, secondHits int
	first := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		firstHits++
		_, _ = io.WriteString(w, "first")
	}))
	defer first.Close()
	second := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		secondHits++
		_, _ = io.WriteString(w, "second")
	}))
	defer second.Close()

	reader := &stubPolicyReader{
		current: &policy.NetworkPolicy{
			APIProxy: &policy.APIProxy{
				Enabled: true,
				Identity: policy.APIProxyIdentity{
					Organization:   "acme",
					OrganizationID: "org-123",
					UserEmail:      "alice@example.com",
				},
				Routes: []policy.APIProxyRoute{
					{
						PathPrefix:  "/api/reason/",
						UpstreamURL: first.URL,
					},
					{
						PathPrefix:  "/api/reason/v2/",
						UpstreamURL: second.URL,
					},
				},
			},
		},
	}

	req := httptest.NewRequest(http.MethodGet, "http://localhost/api/reason/v2/chains/evm/addresses/0x1/detail", nil)
	w := httptest.NewRecorder()

	NewHandler(reader).ServeHTTP(w, req)

	require.Equal(t, http.StatusOK, w.Code)
	require.Equal(t, 0, firstHits)
	require.Equal(t, 1, secondHits)
}
