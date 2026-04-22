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
	"encoding/json"
	"fmt"
	"math"
	"net/netip"
	"net/url"
	"slices"
	"strings"
)

const (
	ActionAllow = "allow"
	ActionDeny  = "deny"
)

type targetKind int

const (
	targetUnknown targetKind = iota
	targetDomain
	targetIP
	targetCIDR
)

// DefaultDenyPolicy returns a new policy that denies all traffic.
func DefaultDenyPolicy() *NetworkPolicy {
	return &NetworkPolicy{DefaultAction: ActionDeny}
}

// NetworkPolicy is the minimal MVP shape for egress control.
// Only domain/wildcard targets are honored in this MVP.
type NetworkPolicy struct {
	Egress        []EgressRule `json:"egress"`
	DefaultAction string       `json:"defaultAction"`
	APIProxy      *APIProxy    `json:"api_proxy,omitempty"`
}

type APIProxy struct {
	Enabled   bool             `json:"enabled"`
	Identity  APIProxyIdentity `json:"identity,omitempty"`
	AuthToken string           `json:"auth_token,omitempty"`
	Routes    []APIProxyRoute  `json:"routes,omitempty"`
}

type APIProxyIdentity struct {
	Organization   string `json:"organization,omitempty"`
	OrganizationID string `json:"organization_id,omitempty"`
	UserEmail      string `json:"user_email,omitempty"`
}

type APIProxyRoute struct {
	PathPrefix  string `json:"path_prefix"`
	UpstreamURL string `json:"upstream_url"`
}

// IsReady returns true when all trusted identity headers are present.
func (i APIProxyIdentity) IsReady() bool {
	return strings.TrimSpace(i.Organization) != "" &&
		strings.TrimSpace(i.OrganizationID) != "" &&
		strings.TrimSpace(i.UserEmail) != ""
}

type EgressRule struct {
	Action string `json:"action"`
	Target string `json:"target"`

	targetKind targetKind
	ip         netip.Addr
	prefix     netip.Prefix
}

// ParsePolicy parses JSON from env/config into a NetworkPolicy.
// Default action falls back to "deny" to align with proposal.
func ParsePolicy(raw string) (*NetworkPolicy, error) {
	trimmed := strings.TrimSpace(raw)
	if trimmed == "" || trimmed == "null" || trimmed == "{}" {
		return DefaultDenyPolicy(), nil
	}

	var p NetworkPolicy
	if err := json.Unmarshal([]byte(trimmed), &p); err != nil {
		return nil, err
	}
	if err := normalizePolicy(&p); err != nil {
		return nil, err
	}
	return ensureDefaults(&p), nil
}

// Evaluate returns allow/deny for a given domain (lowercased).
func (p *NetworkPolicy) Evaluate(domain string) string {
	if p == nil {
		return ActionDeny
	}
	domain = strings.ToLower(strings.TrimSuffix(domain, "."))
	for _, r := range p.Egress {
		if r.targetKind != targetDomain {
			continue
		}
		if r.matchesDomain(domain) {
			if r.Action == "" {
				return ActionDeny
			}
			return r.Action
		}
	}
	if p.DefaultAction == "" {
		return ActionDeny
	}
	return p.DefaultAction
}

// ensureDefaults guarantees a policy always has a default action.
func ensureDefaults(p *NetworkPolicy) *NetworkPolicy {
	if p == nil {
		return DefaultDenyPolicy()
	}
	if p.DefaultAction == "" {
		p.DefaultAction = ActionDeny
	}
	return p
}

func normalizePolicy(p *NetworkPolicy) error {
	p.DefaultAction = strings.ToLower(strings.TrimSpace(p.DefaultAction))
	if p.DefaultAction == "" {
		p.DefaultAction = ActionDeny
	}

	for i := range p.Egress {
		r := &p.Egress[i]
		r.Action = strings.ToLower(strings.TrimSpace(r.Action))
		if r.Action == "" {
			r.Action = ActionDeny
		}
		if r.Action != ActionAllow && r.Action != ActionDeny {
			return fmt.Errorf("unsupported action %q", r.Action)
		}

		r.Target = strings.TrimSpace(r.Target)
		if r.Target == "" {
			return fmt.Errorf("egress target cannot be empty")
		}
		if ip, err := netip.ParseAddr(r.Target); err == nil {
			r.targetKind = targetIP
			r.ip = ip
			continue
		}
		if prefix, err := netip.ParsePrefix(r.Target); err == nil {
			r.targetKind = targetCIDR
			r.prefix = prefix
			continue
		}
		r.targetKind = targetDomain
	}

	if err := normalizeAPIProxy(p); err != nil {
		return err
	}
	return nil
}

func normalizeAPIProxy(p *NetworkPolicy) error {
	if p.APIProxy == nil {
		return nil
	}
	if !p.APIProxy.Enabled {
		p.APIProxy.Identity = APIProxyIdentity{}
		p.APIProxy.AuthToken = ""
		p.APIProxy.Routes = nil
		return nil
	}
	if !p.APIProxy.Identity.IsReady() {
		return fmt.Errorf("api_proxy identity requires organization, organization_id, and user_email")
	}
	if len(p.APIProxy.Routes) == 0 {
		return fmt.Errorf("api_proxy routes cannot be empty")
	}

	seenPrefixes := make(map[string]struct{}, len(p.APIProxy.Routes))
	for i := range p.APIProxy.Routes {
		route := &p.APIProxy.Routes[i]
		route.PathPrefix = strings.TrimSpace(route.PathPrefix)
		route.UpstreamURL = strings.TrimSpace(route.UpstreamURL)
		if err := validateAPIProxyPathPrefix(route.PathPrefix); err != nil {
			return fmt.Errorf("invalid api_proxy path_prefix %q: %w", route.PathPrefix, err)
		}
		if _, exists := seenPrefixes[route.PathPrefix]; exists {
			return fmt.Errorf("duplicate api_proxy path_prefix %q", route.PathPrefix)
		}
		seenPrefixes[route.PathPrefix] = struct{}{}
		normalizedUpstream, err := validateAPIProxyUpstream(route.UpstreamURL, p.APIProxy.AuthToken != "")
		if err != nil {
			return fmt.Errorf("invalid api_proxy upstream_url %q: %w", route.UpstreamURL, err)
		}
		route.UpstreamURL = normalizedUpstream
	}

	return nil
}

func validateAPIProxyPathPrefix(pathPrefix string) error {
	if pathPrefix == "" {
		return fmt.Errorf("path_prefix cannot be empty")
	}
	if !strings.HasPrefix(pathPrefix, "/") {
		return fmt.Errorf("path_prefix must start with '/'")
	}
	if !strings.HasSuffix(pathPrefix, "/") {
		return fmt.Errorf("path_prefix must end with '/'")
	}
	if strings.Contains(pathPrefix, "?") || strings.Contains(pathPrefix, "#") {
		return fmt.Errorf("path_prefix cannot include query or fragment")
	}
	lower := strings.ToLower(pathPrefix)
	for _, fragment := range []string{"//", "/./", "/../", "%2f", "%5c", "%2e"} {
		if strings.Contains(lower, fragment) {
			return fmt.Errorf("path_prefix contains forbidden fragment %q", fragment)
		}
	}
	return nil
}

func validateAPIProxyUpstream(raw string, hasAuthToken bool) (string, error) {
	parsed, err := url.Parse(raw)
	if err != nil {
		return "", err
	}
	if !slices.Contains([]string{"http", "https"}, parsed.Scheme) {
		return "", fmt.Errorf("scheme must be http or https")
	}
	if parsed.User != nil {
		return "", fmt.Errorf("credentials are not allowed")
	}
	if parsed.Hostname() == "" {
		return "", fmt.Errorf("host cannot be empty")
	}
	isInternal := strings.HasSuffix(parsed.Hostname(), ".svc.cluster.local")
	if parsed.Scheme == "https" && !hasAuthToken {
		return "", fmt.Errorf("https upstream requires auth_token")
	}
	if !isInternal && !hasAuthToken {
		return "", fmt.Errorf("external upstream requires auth_token")
	}
	if !slices.Contains([]string{"", "/"}, parsed.EscapedPath()) {
		return "", fmt.Errorf("upstream_url must not include a path")
	}
	if parsed.RawQuery != "" || parsed.Fragment != "" {
		return "", fmt.Errorf("upstream_url must not include query or fragment")
	}
	return parsed.Scheme + "://" + parsed.Host, nil
}

// WithExtraAllowIPs returns a copy of the policy with additional allow rules for each IP.
// Used at startup to whitelist system nameservers so client DNS and proxy upstream work with private DNS.
func (p *NetworkPolicy) WithExtraAllowIPs(ips []netip.Addr) *NetworkPolicy {
	if p == nil || len(ips) == 0 {
		return p
	}
	out := *p
	n, m := len(p.Egress), len(ips)
	if m > math.MaxInt-n {
		panic("policy: egress rule slice capacity overflow")
	}
	out.Egress = make([]EgressRule, n, n+m)
	copy(out.Egress, p.Egress)
	for _, ip := range ips {
		out.Egress = append(out.Egress, EgressRule{
			Action:     ActionAllow,
			Target:     ip.String(),
			targetKind: targetIP,
			ip:         ip,
		})
	}
	return &out
}

// StaticIPSets splits static IP/CIDR rules into allow/deny IPv4/IPv6 buckets.
// Empty or nil policy returns empty slices.
func (p *NetworkPolicy) StaticIPSets() (allowV4, allowV6, denyV4, denyV6 []string) {
	if p == nil {
		return
	}
	for _, r := range p.Egress {
		switch r.targetKind {
		case targetIP:
			addr := r.ip
			target := addr.String()
			if r.Action == ActionAllow {
				if addr.Is4() {
					allowV4 = append(allowV4, target)
				} else if addr.Is6() {
					allowV6 = append(allowV6, target)
				}
			} else {
				if addr.Is4() {
					denyV4 = append(denyV4, target)
				} else if addr.Is6() {
					denyV6 = append(denyV6, target)
				}
			}
		case targetCIDR:
			pfx := r.prefix
			target := pfx.String()
			if r.Action == ActionAllow {
				if pfx.Addr().Is4() {
					allowV4 = append(allowV4, target)
				} else if pfx.Addr().Is6() {
					allowV6 = append(allowV6, target)
				}
			} else {
				if pfx.Addr().Is4() {
					denyV4 = append(denyV4, target)
				} else if pfx.Addr().Is6() {
					denyV6 = append(denyV6, target)
				}
			}
		default:
			continue
		}
	}
	return
}

func (r *EgressRule) matchesDomain(domain string) bool {
	pattern := strings.ToLower(strings.TrimSpace(r.Target))
	domain = strings.ToLower(domain)

	if pattern == "" {
		return false
	}
	if pattern == domain {
		return true
	}
	if strings.HasPrefix(pattern, "*.") {
		// "*.example.com" matches "a.example.com" but not "example.com"
		suffix := strings.TrimPrefix(pattern, "*")
		return strings.HasSuffix(domain, suffix) && domain != strings.TrimPrefix(pattern, "*.")
	}
	return false
}
