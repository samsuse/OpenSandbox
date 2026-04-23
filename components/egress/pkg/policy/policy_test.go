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

package policy

import (
	"net/netip"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestParsePolicy_EmptyOrNullDefaultsDeny(t *testing.T) {
	cases := []string{
		"",
		"   ",
		"null",
		"{}\n",
	}
	for _, raw := range cases {
		p, err := ParsePolicy(raw)
		require.NoErrorf(t, err, "raw %q returned error", raw)
		require.NotNilf(t, p, "raw %q expected default deny policy, got nil", raw)
		require.Equalf(t, ActionDeny, p.DefaultAction, "raw %q expected defaultAction deny", raw)
		require.Equalf(t, ActionDeny, p.Evaluate("example.com."), "raw %q expected deny evaluation", raw)
	}
}

func TestParsePolicy_DefaultActionFallback(t *testing.T) {
	p, err := ParsePolicy(`{"egress":[{"action":"allow","target":"example.com"}]}`)
	require.NoError(t, err)
	require.NotNil(t, p, "expected policy object, got nil")
	require.Equal(t, ActionDeny, p.DefaultAction, "expected defaultAction fallback to deny")
}

func TestParsePolicy_EmptyEgressDefaultsDeny(t *testing.T) {
	p, err := ParsePolicy(`{"defaultAction":""}`)
	require.NoError(t, err)
	require.Equal(t, ActionDeny, p.DefaultAction, "expected default deny when defaultAction missing")
	require.Equal(t, ActionDeny, p.Evaluate("anything.com."), "expected evaluation deny for empty egress")
}

func TestParsePolicy_IPAndCIDRSupported(t *testing.T) {
	raw := `{
		"defaultAction":"deny",
		"egress":[
			{"action":"allow","target":"1.1.1.1"},
			{"action":"allow","target":"2.2.0.0/16"},
			{"action":"deny","target":"2001:db8::/32"},
			{"action":"deny","target":"2001:db8::1"}
		]
	}`
	p, err := ParsePolicy(raw)
	require.NoError(t, err)
	allowV4, allowV6, denyV4, denyV6 := p.StaticIPSets()
	require.Len(t, allowV4, 2, "allowV4 length mismatch")
	require.Equal(t, "1.1.1.1", allowV4[0])
	require.Equal(t, "2.2.0.0/16", allowV4[1])
	require.Len(t, denyV6, 2, "expected 2 denyV6 entries")
	require.Empty(t, allowV6, "allowV6 should be empty")
	require.Empty(t, denyV4, "denyV4 should be empty")
}

func TestParsePolicy_InvalidAction(t *testing.T) {
	_, err := ParsePolicy(`{"egress":[{"action":"foo","target":"example.com"}]}`)
	require.Error(t, err, "expected error for invalid action")
}

func TestParsePolicy_EmptyTargetError(t *testing.T) {
	_, err := ParsePolicy(`{"egress":[{"action":"allow","target":""}]}`)
	require.Error(t, err, "expected error for empty target")
}

func TestWithExtraAllowIPs(t *testing.T) {
	p, err := ParsePolicy(`{"defaultAction":"deny","egress":[{"action":"allow","target":"example.com"}]}`)
	require.NoError(t, err)
	allowV4, allowV6, _, _ := p.StaticIPSets()
	require.Empty(t, allowV4, "domain-only policy should have no static allowV4 IPs")
	require.Empty(t, allowV6, "domain-only policy should have no static allowV6 IPs")

	ips := []netip.Addr{
		netip.MustParseAddr("192.168.65.7"),
		netip.MustParseAddr("2001:db8::1"),
	}
	merged := p.WithExtraAllowIPs(ips)
	require.NotSame(t, p, merged, "expected new policy instance")
	allowV4, allowV6, _, _ = merged.StaticIPSets()
	require.Len(t, allowV4, 1, "allowV4 length mismatch")
	require.Equal(t, "192.168.65.7", allowV4[0])
	require.Len(t, allowV6, 1, "allowV6 length mismatch")
	require.Equal(t, "2001:db8::1", allowV6[0])

	// nil/empty ips returns same policy
	require.Same(t, p, p.WithExtraAllowIPs(nil), "WithExtraAllowIPs(nil) should return same policy")
	require.Same(t, p, p.WithExtraAllowIPs([]netip.Addr{}), "WithExtraAllowIPs([]) should return same policy")
}

func TestAPIProxyUpstreamRules_NilDisabledEmpty(t *testing.T) {
	var nilPolicy *NetworkPolicy
	require.Nil(t, nilPolicy.APIProxyUpstreamRules())

	disabled := &NetworkPolicy{APIProxy: &APIProxy{Enabled: false}}
	require.Nil(t, disabled.APIProxyUpstreamRules())

	noRoutes := &NetworkPolicy{APIProxy: &APIProxy{Enabled: true, Routes: nil}}
	require.Nil(t, noRoutes.APIProxyUpstreamRules())
}

func TestAPIProxyUpstreamRules_SingleUpstream(t *testing.T) {
	p, err := ParsePolicy(`{
		"defaultAction":"deny",
		"egress":[{"action":"allow","target":"pypi.org"}],
		"api_proxy":{
			"enabled":true,
			"identity":{"organization":"test","organization_id":"id1","user_email":"u@t.co"},
			"auth_token":"tok",
			"routes":[{"path_prefix":"/api/screen/","upstream_url":"https://svc.cipherowl.ai"}]
		}
	}`)
	require.NoError(t, err)
	rules := p.APIProxyUpstreamRules()
	require.Len(t, rules, 1)
	require.Equal(t, ActionAllow, rules[0].Action)
	require.Equal(t, "svc.cipherowl.ai", rules[0].Target)
}

func TestAPIProxyUpstreamRules_Deduplicates(t *testing.T) {
	p, err := ParsePolicy(`{
		"defaultAction":"deny",
		"api_proxy":{
			"enabled":true,
			"identity":{"organization":"test","organization_id":"id1","user_email":"u@t.co"},
			"auth_token":"tok",
			"routes":[
				{"path_prefix":"/api/screen/","upstream_url":"https://svc.cipherowl.ai"},
				{"path_prefix":"/api/reason/","upstream_url":"https://svc.cipherowl.ai"}
			]
		}
	}`)
	require.NoError(t, err)
	rules := p.APIProxyUpstreamRules()
	require.Len(t, rules, 1, "duplicate upstream hostnames should be deduplicated")
}

func TestAPIProxyUpstreamRules_MultipleDistinctUpstreams(t *testing.T) {
	p, err := ParsePolicy(`{
		"defaultAction":"deny",
		"api_proxy":{
			"enabled":true,
			"identity":{"organization":"test","organization_id":"id1","user_email":"u@t.co"},
			"auth_token":"tok",
			"routes":[
				{"path_prefix":"/api/screen/","upstream_url":"https://svc.cipherowl.ai"},
				{"path_prefix":"/api/config/","upstream_url":"http://config.config-dev.svc.cluster.local"}
			]
		}
	}`)
	require.NoError(t, err)
	rules := p.APIProxyUpstreamRules()
	require.Len(t, rules, 2)
	targets := map[string]bool{}
	for _, r := range rules {
		targets[r.Target] = true
	}
	require.True(t, targets["svc.cipherowl.ai"])
	require.True(t, targets["config.config-dev.svc.cluster.local"])
}

func TestAPIProxyUpstreamRules_StripsPort(t *testing.T) {
	p, err := ParsePolicy(`{
		"defaultAction":"deny",
		"api_proxy":{
			"enabled":true,
			"identity":{"organization":"test","organization_id":"id1","user_email":"u@t.co"},
			"auth_token":"tok",
			"routes":[{"path_prefix":"/api/config/","upstream_url":"http://config.svc.cluster.local:8080"}]
		}
	}`)
	require.NoError(t, err)
	rules := p.APIProxyUpstreamRules()
	require.Len(t, rules, 1)
	require.Equal(t, "config.svc.cluster.local", rules[0].Target, "port should be stripped from hostname")
}
