// Package verify turns offline findings into quick live/dead assessments:
// DNS resolve, TCP connect probe, JWT exp check. Strictly opt-in since it
// touches the network.
package verify

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"sort"
	"strings"
	"sync"
	"time"
)

// HostVerdict is the badge printed next to a finding value.
type HostVerdict string

const (
	VerdictLive     HostVerdict = "LIVE"     // resolved + TCP port open
	VerdictPublic   HostVerdict = "PUBLIC"   // resolved, at least one public IP
	VerdictInternal HostVerdict = "INTERNAL" // resolved to RFC1918/loopback only
	VerdictNXDomain HostVerdict = "NXDOMAIN" // no such host
	VerdictDNSErr   HostVerdict = "DNS-ERR"  // timeout / refused / other
	VerdictUnknown  HostVerdict = "UNKNOWN"
)

type HostStatus struct {
	Host       Host
	IPs        []string
	DNSErr     string
	Public     bool
	Internal   bool
	TCPChecked bool
	TCPOpen    bool
	TCPErr     string
	Verdict    HostVerdict
	// Wildcard is true when this host resolves to an IP shared by
	// multiple other hostnames — usually a DNS wildcard (*.apex) or
	// a parking / catch-all answer. Flagged so the operator doesn't
	// chase ghost targets.
	Wildcard bool
}

// JWTStatus is the parsed-claims view. Signature is NOT verified.
type JWTStatus struct {
	Raw     string
	Kid     string
	Issuer  string
	Subject string
	Expired bool
	ExpAt   time.Time
	NbfAt   time.Time
	Reason  string // "expired" | "not-yet-valid" | "malformed" | ""
}

type Options struct {
	DNSServer    string
	ProbeTCP     bool
	Timeout      time.Duration
	Concurrency  int
	VerifyCreds  bool
	CredsTimeout time.Duration
}

type Report struct {
	Hosts        map[string]*HostStatus // keyed by Host.Key()
	HostByRaw    map[string]*HostStatus // keyed by original value string
	JWTs         map[string]*JWTStatus
	Creds        map[string]*CredResult // SaaS vendor + active probes
	OAuthResults map[string]*CredResult // keyed by OAuthTarget.Key()
	Subdomains   map[string]*HostStatus // apex-enumerated subdomains, keyed by hostname
}

func NewReport() *Report {
	return &Report{
		Hosts:        map[string]*HostStatus{},
		HostByRaw:    map[string]*HostStatus{},
		JWTs:         map[string]*JWTStatus{},
		Creds:        map[string]*CredResult{},
		OAuthResults: map[string]*CredResult{},
		Subdomains:   map[string]*HostStatus{},
	}
}

func (r *Report) Empty() bool {
	return r == nil || (len(r.Hosts) == 0 && len(r.JWTs) == 0 &&
		len(r.Creds) == 0 && len(r.OAuthResults) == 0 && len(r.Subdomains) == 0)
}

func (r *Report) CredByValue(v string) *CredResult {
	if r == nil {
		return nil
	}
	return r.Creds[strings.TrimSpace(v)]
}

func (r *Report) HostByValue(v string) *HostStatus {
	if r == nil {
		return nil
	}
	if st, ok := r.HostByRaw[v]; ok {
		return st
	}
	h, ok := ExtractHostFromValue(v)
	if !ok {
		return nil
	}
	return r.Hosts[h.Key()]
}

func (r *Report) JWTByValue(v string) *JWTStatus {
	if r == nil {
		return nil
	}
	return r.JWTs[strings.TrimSpace(v)]
}

// OAuthByClientID returns the OAuth probe result whose ClientID matches v.
// Used by the CLI to annotate clientSecret/clientId fields inline.
func (r *Report) OAuthByClientID(v string) *CredResult {
	if r == nil {
		return nil
	}
	v = strings.TrimSpace(v)
	if v == "" {
		return nil
	}
	for _, c := range r.OAuthResults {
		if c != nil && c.Value == v {
			return c
		}
	}
	return nil
}

type CredTarget struct {
	Pattern string
	Value   string
}

// Run verifies every host, JWT, and cred target concurrently in two
// phases: (1) passive DNS/TCP + JWT exp decode, (2) active cred probes
// if VerifyCreds=true, gated on the phase-1 verdicts (skip Internal/
// NXDOMAIN hosts). Subdomains (apex-enumerated from heap strings) are
// resolved in phase 1 alongside finding-hosts but stored separately.
// nil ctx → context.Background.
func Run(ctx context.Context, hosts []Host, jwts []string, creds []CredTarget, oauthTargets []OAuthTarget, subdomains []string, opts Options) *Report {
	if ctx == nil {
		ctx = context.Background()
	}
	if opts.Timeout <= 0 {
		opts.Timeout = 3 * time.Second
	}
	if opts.Concurrency <= 0 {
		opts.Concurrency = 16
	}

	report := NewReport()
	resolver := buildResolver(opts.DNSServer)

	// Dedupe by Key so duplicate endpoints share one round-trip.
	unique := map[string]Host{}
	for _, h := range hosts {
		if _, seen := unique[h.Key()]; seen {
			continue
		}
		unique[h.Key()] = h
	}

	sem := make(chan struct{}, opts.Concurrency)
	var (
		wg sync.WaitGroup
		mu sync.Mutex
	)
	for _, h := range unique {
		h := h
		wg.Add(1)
		sem <- struct{}{}
		go func() {
			defer wg.Done()
			defer func() { <-sem }()
			st := verifyHost(ctx, resolver, h, opts)
			mu.Lock()
			report.Hosts[h.Key()] = st
			if h.Raw != "" {
				report.HostByRaw[h.Raw] = st
			}
			mu.Unlock()
		}()
	}
	wg.Wait()

	// Subdomains from apex enumeration — DNS only, no TCP. Dedup by host.
	if len(subdomains) > 0 {
		uniq := map[string]bool{}
		for _, s := range subdomains {
			s = strings.ToLower(strings.TrimSpace(s))
			if s != "" {
				uniq[s] = true
			}
		}
		for host := range uniq {
			host := host
			wg.Add(1)
			sem <- struct{}{}
			go func() {
				defer wg.Done()
				defer func() { <-sem }()
				subOpts := opts
				subOpts.ProbeTCP = false
				st := verifyHost(ctx, resolver, Host{Host: host}, subOpts)
				mu.Lock()
				report.Subdomains[host] = st
				mu.Unlock()
			}()
		}
		wg.Wait()
	}

	// Backfill HostByRaw for any hosts skipped by the dedup pass.
	for _, h := range hosts {
		if _, exists := report.HostByRaw[h.Raw]; exists {
			continue
		}
		if st, ok := report.Hosts[h.Key()]; ok {
			report.HostByRaw[h.Raw] = st
		}
	}

	// Wildcard detection: count how many distinct hostnames resolve to
	// each IP across both finding-hosts and subdomain-enum. If ≥ 3 share
	// one IP, mark those entries as wildcard so the operator ignores
	// ghost targets (DNS *.apex catch-all).
	ipHosts := map[string]map[string]bool{}
	track := func(st *HostStatus) {
		if st == nil {
			return
		}
		for _, ip := range st.IPs {
			if _, ok := ipHosts[ip]; !ok {
				ipHosts[ip] = map[string]bool{}
			}
			ipHosts[ip][st.Host.Host] = true
		}
	}
	for _, st := range report.Hosts {
		track(st)
	}
	for _, st := range report.Subdomains {
		track(st)
	}
	const wildcardThreshold = 3
	mark := func(st *HostStatus) {
		if st == nil {
			return
		}
		for _, ip := range st.IPs {
			if len(ipHosts[ip]) >= wildcardThreshold {
				st.Wildcard = true
				break
			}
		}
	}
	for _, st := range report.Hosts {
		mark(st)
	}
	for _, st := range report.Subdomains {
		mark(st)
	}

	for _, raw := range jwts {
		raw = strings.TrimSpace(raw)
		if raw == "" {
			continue
		}
		if _, dup := report.JWTs[raw]; dup {
			continue
		}
		report.JWTs[raw] = verifyJWT(raw)
	}

	if opts.VerifyCreds {
		client := NewCredClient(opts.CredsTimeout)
		oidcCache := newOIDCCache()

		// Phase 2a: SaaS vendor whoami (GitHub/OpenAI/...). Pattern-gated,
		// so only fires on vendor-specific regex hits that WERE in the dump.
		dedupSaaS := map[string]CredTarget{}
		for _, c := range creds {
			v := strings.TrimSpace(c.Value)
			if v == "" || c.Pattern == "" {
				continue
			}
			dedupSaaS[v] = CredTarget{Pattern: c.Pattern, Value: v}
		}
		credSem := make(chan struct{}, opts.Concurrency)
		var credWG sync.WaitGroup
		for _, t := range dedupSaaS {
			t := t
			credWG.Add(1)
			credSem <- struct{}{}
			go func() {
				defer credWG.Done()
				defer func() { <-credSem }()
				res, ok := VerifyCred(ctx, t.Pattern, t.Value, client)
				if !ok {
					return
				}
				mu.Lock()
				report.Creds[t.Value] = &res
				mu.Unlock()
			}()
		}
		credWG.Wait()

		// Phase 2b: Active OAuth2 probes against endpoints from the dump,
		// only for publicly-reachable base URLs.
		for _, t := range oauthTargets {
			t := t
			if t.BaseURL == "" || t.ClientID == "" {
				continue
			}
			if !reachableForActiveProbe(t.BaseURL, report.Hosts) {
				report.OAuthResults[t.Key()] = &CredResult{
					Pattern: "oauth2",
					Value:   t.ClientID,
					Vendor:  "oauth2:" + hostOf(t.BaseURL),
					Verdict: CredUnknown,
					Reason:  "skipped: not reachable from internet",
				}
				continue
			}
			credWG.Add(1)
			credSem <- struct{}{}
			go func() {
				defer credWG.Done()
				defer func() { <-credSem }()
				var res CredResult
				switch {
				case t.ClientSecret != "":
					res = VerifyOAuth2ClientCredentials(ctx, t, client)
				case strings.ToLower(t.GrantType) == "password" && t.Username != "" && t.Password != "":
					res = VerifyOAuth2PasswordGrant(ctx, t, client)
				default:
					return
				}
				mu.Lock()
				report.OAuthResults[t.Key()] = &res
				mu.Unlock()
			}()
		}
		credWG.Wait()

		// Phase 2c: OIDC userinfo for every JWT whose issuer host we
		// already know is publicly reachable.
		for raw, js := range report.JWTs {
			raw, js := raw, js
			if js == nil || js.Issuer == "" || js.Expired {
				continue
			}
			if !reachableForActiveProbe(js.Issuer, report.Hosts) {
				continue
			}
			credWG.Add(1)
			credSem <- struct{}{}
			go func() {
				defer credWG.Done()
				defer func() { <-credSem }()
				res := VerifyOIDCUserinfo(ctx, js.Issuer, raw, client, oidcCache)
				mu.Lock()
				report.Creds[raw] = &res
				mu.Unlock()
			}()
		}
		credWG.Wait()
	}

	return report
}

// verifyHost performs DNS resolution and (when port known) a single TCP
// connect. Classification is strictly based on what the observed data
// says, never on heuristics about the name itself.
func verifyHost(ctx context.Context, resolver *net.Resolver, h Host, opts Options) *HostStatus {
	st := &HostStatus{Host: h, Verdict: VerdictUnknown}

	dnsCtx, cancel := context.WithTimeout(ctx, opts.Timeout)
	defer cancel()
	addrs, err := resolver.LookupHost(dnsCtx, h.Host)
	if err != nil {
		st.DNSErr = simplifyDNSErr(err)
		if st.DNSErr == "NXDOMAIN" {
			st.Verdict = VerdictNXDomain
		} else {
			st.Verdict = VerdictDNSErr
		}
		return st
	}
	sort.Strings(addrs)
	st.IPs = addrs
	for _, a := range addrs {
		ip := net.ParseIP(a)
		if ip == nil {
			continue
		}
		if isPrivateIP(ip) {
			st.Internal = true
		} else {
			st.Public = true
		}
	}

	st.Verdict = VerdictInternal
	if st.Public {
		st.Verdict = VerdictPublic
	}

	if opts.ProbeTCP && h.Port > 0 && len(addrs) > 0 {
		st.TCPChecked = true
		target := net.JoinHostPort(addrs[0], fmtPort(h.Port))
		dialer := net.Dialer{Timeout: opts.Timeout}
		conn, derr := dialer.DialContext(ctx, "tcp", target)
		if derr == nil {
			_ = conn.Close()
			st.TCPOpen = true
			if st.Public {
				st.Verdict = VerdictLive
			}
		} else {
			st.TCPErr = simplifyTCPErr(derr)
		}
	}

	return st
}

// verifyJWT decodes the middle segment of a JWT and classifies it as
// expired / not-yet-valid / malformed / valid. Does NOT verify the
// signature — that's a separate offline primitive in internal/decrypt.
func verifyJWT(raw string) *JWTStatus {
	st := &JWTStatus{Raw: raw}
	parts := strings.Split(raw, ".")
	if len(parts) != 3 {
		st.Reason = "malformed"
		return st
	}
	// Header for "kid" attribution.
	if h, ok := base64DecodeURL(parts[0]); ok {
		var hdr struct {
			Kid string `json:"kid"`
		}
		_ = json.Unmarshal(h, &hdr)
		st.Kid = hdr.Kid
	}
	payload, ok := base64DecodeURL(parts[1])
	if !ok {
		st.Reason = "malformed"
		return st
	}
	var claims map[string]any
	if err := json.Unmarshal(payload, &claims); err != nil {
		st.Reason = "malformed"
		return st
	}
	if iss, ok := claims["iss"].(string); ok {
		st.Issuer = iss
	}
	if sub, ok := claims["sub"].(string); ok {
		st.Subject = sub
	}
	now := time.Now()
	if exp, ok := claimTime(claims, "exp"); ok {
		st.ExpAt = exp
		if now.After(exp) {
			st.Expired = true
			st.Reason = "expired"
		}
	}
	if nbf, ok := claimTime(claims, "nbf"); ok {
		st.NbfAt = nbf
		if now.Before(nbf) && st.Reason == "" {
			st.Reason = "not-yet-valid"
		}
	}
	return st
}

func claimTime(claims map[string]any, key string) (time.Time, bool) {
	v, ok := claims[key]
	if !ok {
		return time.Time{}, false
	}
	f, ok := v.(float64)
	if !ok {
		return time.Time{}, false
	}
	return time.Unix(int64(f), 0).UTC(), true
}

func base64DecodeURL(s string) ([]byte, bool) {
	// JWT segments use URL-safe base64 without padding.
	for len(s)%4 != 0 {
		s += "="
	}
	b, err := base64.URLEncoding.DecodeString(s)
	if err != nil {
		return nil, false
	}
	return b, true
}

func isPrivateIP(ip net.IP) bool {
	if ip == nil {
		return false
	}
	return ip.IsLoopback() || ip.IsPrivate() || ip.IsLinkLocalUnicast() ||
		ip.IsUnspecified() || ip.IsMulticast()
}

// buildResolver returns a resolver that talks to the configured DNS
// server. Empty string → system resolver.
func buildResolver(dns string) *net.Resolver {
	if dns == "" {
		return net.DefaultResolver
	}
	addr := dns
	if !strings.Contains(addr, ":") {
		addr += ":53"
	}
	return &net.Resolver{
		PreferGo: true,
		Dial: func(ctx context.Context, _, _ string) (net.Conn, error) {
			d := net.Dialer{Timeout: 3 * time.Second}
			return d.DialContext(ctx, "udp", addr)
		},
	}
}

func simplifyDNSErr(err error) string {
	var dnsErr *net.DNSError
	if errors.As(err, &dnsErr) {
		if dnsErr.IsNotFound {
			return "NXDOMAIN"
		}
		if dnsErr.IsTimeout {
			return "timeout"
		}
	}
	s := err.Error()
	switch {
	case strings.Contains(s, "no such host"):
		return "NXDOMAIN"
	case strings.Contains(s, "timeout"):
		return "timeout"
	case strings.Contains(s, "refused"):
		return "refused"
	}
	return "error"
}

func simplifyTCPErr(err error) string {
	s := err.Error()
	switch {
	case strings.Contains(s, "timeout"):
		return "timeout"
	case strings.Contains(s, "connection refused"):
		return "refused"
	case strings.Contains(s, "network is unreachable"):
		return "unreachable"
	case strings.Contains(s, "no route"):
		return "no-route"
	}
	return "closed"
}

func fmtPort(p int) string { return fmt.Sprintf("%d", p) }
