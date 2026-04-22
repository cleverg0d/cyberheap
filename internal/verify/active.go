package verify

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/url"
	"strings"
	"sync"
)

// OAuthTarget groups credentials extracted from one Spring property
// prefix: base URL plus at least (clientID, clientSecret). User+Pass
// are optional — when present and GrantType="password", unlocks the
// password-grant probe.
type OAuthTarget struct {
	Prefix       string
	BaseURL      string
	ClientID     string
	ClientSecret string
	Username     string
	Password     string
	GrantType    string
	Scope        string
}

// Key identifies a target uniquely for dedup.
func (t OAuthTarget) Key() string {
	return t.BaseURL + "|" + t.ClientID
}

// tokenPathCandidates returns URL candidates in priority order:
//   - base itself (common for apps that stored the fully-qualified
//     token endpoint in baseurl)
//   - /token sub-path (apps that stored the realm root only)
//   - /protocol/openid-connect/token (Keycloak realm root)
//   - /oauth/token (Spring-style OAuth2 servers)
func tokenPathCandidates(base string) []string {
	b := strings.TrimRight(base, "/")
	low := strings.ToLower(b)
	// If base already ends with a known token path segment, try it
	// first and don't append sub-paths on top.
	for _, suffix := range []string{"/token", "/protocol/openid-connect/token", "/oauth/token"} {
		if strings.HasSuffix(low, suffix) {
			return []string{b}
		}
	}
	return []string{
		b,
		b + "/token",
		b + "/protocol/openid-connect/token",
		b + "/oauth/token",
	}
}

// VerifyOAuth2ClientCredentials tries client_credentials grant at one
// of candidateTokenPaths. Non-invasive: service-to-service auth, no
// user account involvement.
func VerifyOAuth2ClientCredentials(ctx context.Context, t OAuthTarget, client *http.Client) CredResult {
	r := CredResult{
		Pattern: "oauth2-client-credentials",
		Value:   t.ClientID,
		Vendor:  "oauth2:" + hostOf(t.BaseURL),
	}
	form := url.Values{
		"grant_type":    {"client_credentials"},
		"client_id":     {t.ClientID},
		"client_secret": {t.ClientSecret},
	}
	if t.Scope != "" {
		form.Set("scope", t.Scope)
	}
	r = postToken(ctx, t.BaseURL, form, client, r)
	return r
}

// VerifyOAuth2PasswordGrant tries password grant. INVASIVE: binds a
// real user account. Gated on caller (currently: only when GrantType=
// "password" was observed in the dump, i.e. the app itself uses this flow).
func VerifyOAuth2PasswordGrant(ctx context.Context, t OAuthTarget, client *http.Client) CredResult {
	r := CredResult{
		Pattern: "oauth2-password",
		Value:   t.Username,
		Vendor:  "oauth2:" + hostOf(t.BaseURL),
	}
	form := url.Values{
		"grant_type": {"password"},
		"username":   {t.Username},
		"password":   {t.Password},
		"client_id":  {t.ClientID},
	}
	if t.ClientSecret != "" {
		form.Set("client_secret", t.ClientSecret)
	}
	if t.Scope != "" {
		form.Set("scope", t.Scope)
	}
	r = postToken(ctx, t.BaseURL, form, client, r)
	if r.Verdict == CredValid {
		r.Account = t.Username
	}
	return r
}

// postToken walks tokenPathCandidates, first 2xx+access_token wins.
// "invalid_client"/"invalid_grant" in JSON body → Revoked.
func postToken(ctx context.Context, base string, form url.Values, client *http.Client, r CredResult) CredResult {
	var lastStatus int
	var lastBody string
	var lastURL string
	for _, u := range tokenPathCandidates(base) {
		req, err := http.NewRequestWithContext(ctx, "POST", u, strings.NewReader(form.Encode()))
		if err != nil {
			r.Verdict = CredError
			r.Reason = err.Error()
			return r
		}
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		req.Header.Set("Accept", "application/json")
		status, _, body, err := do(client, req)
		if err != nil {
			r.Verdict = CredError
			r.Reason = netErrorReason(err)
			return r
		}
		lastStatus = status
		lastBody = string(body)
		lastURL = u
		if status >= 200 && status < 300 {
			var ok struct {
				AccessToken string `json:"access_token"`
			}
			_ = json.Unmarshal(body, &ok)
			if ok.AccessToken != "" {
				r.Verdict = CredValid
				r.Status = status
				r.Reason = "token endpoint: " + u
				return r
			}
		}
		if status == 400 || status == 401 {
			break
		}
	}
	r.Status = lastStatus
	_ = lastURL
	switch {
	case strings.Contains(lastBody, "invalid_client"),
		strings.Contains(lastBody, "invalid_grant"),
		strings.Contains(lastBody, "unauthorized"):
		r.Verdict = CredRevoked
		r.Reason = extractOAuthError(lastBody)
	case lastStatus == 429:
		r.Verdict = CredRateLimited
	case lastStatus >= 500 || lastStatus == 0:
		r.Verdict = CredError
	default:
		r.Verdict = CredUnknown
	}
	return r
}

func extractOAuthError(body string) string {
	var b struct {
		Error            string `json:"error"`
		ErrorDescription string `json:"error_description"`
	}
	_ = json.Unmarshal([]byte(body), &b)
	if b.Error != "" {
		return b.Error
	}
	return ""
}

// VerifyOIDCUserinfo discovers userinfo_endpoint via OIDC well-known
// metadata, then GETs it with Bearer token.
func VerifyOIDCUserinfo(ctx context.Context, iss, token string, client *http.Client, cache *oidcDiscoveryCache) CredResult {
	r := CredResult{
		Pattern: "oidc-userinfo",
		Value:   token,
		Vendor:  "oidc:" + hostOf(iss),
	}
	userinfoURL := cache.userinfoEndpoint(ctx, iss, client)
	if userinfoURL == "" {
		r.Verdict = CredUnknown
		r.Reason = "no userinfo endpoint"
		return r
	}
	req, _ := http.NewRequestWithContext(ctx, "GET", userinfoURL, nil)
	req.Header.Set("Authorization", "Bearer "+token)
	status, _, body, err := do(client, req)
	if err != nil {
		r.Verdict = CredError
		r.Reason = netErrorReason(err)
		return r
	}
	r.Status = status
	r.Verdict = classifyStatus(status)
	if r.Verdict == CredValid {
		var b struct {
			Sub               string `json:"sub"`
			PreferredUsername string `json:"preferred_username"`
			Email             string `json:"email"`
		}
		_ = json.Unmarshal(body, &b)
		switch {
		case b.PreferredUsername != "":
			r.Account = b.PreferredUsername
		case b.Email != "":
			r.Account = b.Email
		case b.Sub != "":
			r.Account = b.Sub
		}
	}
	return r
}

// VerifyHTTPBasic: HEAD baseurl with Basic. 200/3xx → Valid, 401 → Revoked.
func VerifyHTTPBasic(ctx context.Context, baseURL, user, pass string, client *http.Client) CredResult {
	r := CredResult{
		Pattern: "http-basic",
		Value:   user,
		Vendor:  "basic:" + hostOf(baseURL),
	}
	req, err := http.NewRequestWithContext(ctx, "HEAD", baseURL, nil)
	if err != nil {
		r.Verdict = CredError
		r.Reason = err.Error()
		return r
	}
	req.SetBasicAuth(user, pass)
	status, _, _, err := do(client, req)
	if err != nil {
		r.Verdict = CredError
		r.Reason = netErrorReason(err)
		return r
	}
	r.Status = status
	r.Verdict = classifyStatus(status)
	if r.Verdict == CredValid {
		r.Account = user
	}
	return r
}

// oidcDiscoveryCache memoises userinfo lookups per issuer string.
type oidcDiscoveryCache struct {
	mu sync.Mutex
	m  map[string]string
}

func newOIDCCache() *oidcDiscoveryCache {
	return &oidcDiscoveryCache{m: map[string]string{}}
}

func (c *oidcDiscoveryCache) userinfoEndpoint(ctx context.Context, iss string, client *http.Client) string {
	c.mu.Lock()
	defer c.mu.Unlock()
	if v, ok := c.m[iss]; ok {
		return v
	}
	url := strings.TrimRight(iss, "/") + "/.well-known/openid-configuration"
	req, _ := http.NewRequestWithContext(ctx, "GET", url, nil)
	_, _, body, err := do(client, req)
	if err != nil {
		c.m[iss] = ""
		return ""
	}
	var meta struct {
		UserinfoEndpoint string `json:"userinfo_endpoint"`
	}
	_ = json.Unmarshal(body, &meta)
	c.m[iss] = meta.UserinfoEndpoint
	return meta.UserinfoEndpoint
}

// hostOf strips scheme/path from a URL to produce a short label.
func hostOf(raw string) string {
	u, err := url.Parse(raw)
	if err != nil || u.Host == "" {
		return raw
	}
	return u.Hostname()
}

// reachableForActiveProbe returns true if the host backing this URL has
// been verified as LIVE or PUBLIC (with TCP open). Internal/NXDOMAIN
// endpoints return false so active probes skip them.
func reachableForActiveProbe(baseURL string, hostReports map[string]*HostStatus) bool {
	h, ok := ExtractHostFromValue(baseURL)
	if !ok {
		return false
	}
	st := hostReports[h.Key()]
	if st == nil {
		return false
	}
	switch st.Verdict {
	case VerdictLive:
		return true
	case VerdictPublic:
		return !st.TCPChecked || st.TCPOpen
	}
	return false
}

// limitedReader helper used in tests to bound response bodies.
var _ = io.LimitReader
