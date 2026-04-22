package verify

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strings"
	"time"
)

type CredVerdict string

const (
	CredValid       CredVerdict = "VALID"
	CredRevoked     CredVerdict = "REVOKED"
	CredRateLimited CredVerdict = "RATE-LIMITED"
	CredError       CredVerdict = "ERROR"
	CredUnknown     CredVerdict = "UNKNOWN"
)

type CredResult struct {
	Pattern string
	Value   string
	Vendor  string
	Verdict CredVerdict
	Account string
	Scopes  []string
	Status  int
	Reason  string
}

// VerifyCred dispatches to the vendor checker for patternName. All
// checkers are strictly read-only (whoami-style GETs).
func VerifyCred(ctx context.Context, patternName, value string, client *http.Client) (CredResult, bool) {
	value = strings.TrimSpace(value)
	if value == "" {
		return CredResult{}, false
	}
	// JWT short-circuit: if the token is already expired per its exp
	// claim, don't waste an HTTP call — it would 401 anyway.
	if strings.HasPrefix(value, "eyJ") && strings.Count(value, ".") == 2 {
		if js := verifyJWT(value); js.Expired {
			return CredResult{
				Pattern: patternName,
				Value:   value,
				Verdict: CredRevoked,
				Reason:  "expired (jwt.exp)",
			}, true
		}
	}
	switch patternName {
	case "github-token", "github-fine-grained-pat":
		return checkGitHub(ctx, value, client), true
	case "gitlab-pat":
		return checkGitLab(ctx, value, client), true
	case "openai-key":
		return checkOpenAI(ctx, value, client), true
	case "anthropic-key":
		return checkAnthropic(ctx, value, client), true
	case "slack-token":
		return checkSlack(ctx, value, client), true
	case "slack-webhook-url":
		return checkSlackWebhook(ctx, value, client), true
	case "sendgrid-key":
		return checkSendGrid(ctx, value, client), true
	case "mailgun-key":
		return checkMailgun(ctx, value, client), true
	case "discord-bot-token":
		return checkDiscord(ctx, value, client), true
	case "telegram-bot-token":
		return checkTelegram(ctx, value, client), true
	case "stripe-key":
		return checkStripe(ctx, value, client), true
	case "npm-token":
		return checkNPM(ctx, value, client), true
	case "huggingface-token":
		return checkHuggingFace(ctx, value, client), true
	}
	return CredResult{}, false
}

// NewCredClient builds an http.Client for --verify-creds: bounded
// timeout, env proxy, stable UA.
func NewCredClient(timeout time.Duration) *http.Client {
	if timeout <= 0 {
		timeout = 5 * time.Second
	}
	return &http.Client{
		Timeout: timeout,
		Transport: &http.Transport{
			Proxy: http.ProxyFromEnvironment,
			DialContext: (&net.Dialer{
				Timeout: timeout,
			}).DialContext,
			TLSHandshakeTimeout: timeout,
		},
	}
}

const credUA = "cyberheap/verify-creds (+https://github.com/cleverg0d/cyberheap)"

// do sets UA, runs the request, returns a bounded (64 KiB) body.
func do(client *http.Client, req *http.Request) (int, http.Header, []byte, error) {
	req.Header.Set("User-Agent", credUA)
	resp, err := client.Do(req)
	if err != nil {
		return 0, nil, nil, err
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 64<<10))
	return resp.StatusCode, resp.Header, body, nil
}

// classifyStatus maps HTTP status to verdict.
func classifyStatus(status int) CredVerdict {
	switch {
	case status >= 200 && status < 300:
		return CredValid
	case status == 401 || status == 403:
		return CredRevoked
	case status == 429:
		return CredRateLimited
	case status >= 500:
		return CredError
	}
	return CredUnknown
}

func netErrorReason(err error) string {
	var ue *url.Error
	if errors.As(err, &ue) {
		if ue.Timeout() {
			return "timeout"
		}
		if strings.Contains(ue.Err.Error(), "no such host") {
			return "NXDOMAIN"
		}
		if strings.Contains(ue.Err.Error(), "connection refused") {
			return "refused"
		}
		return ue.Err.Error()
	}
	return err.Error()
}

// ---- per-vendor checkers -------------------------------------------------

func checkGitHub(ctx context.Context, tok string, client *http.Client) CredResult {
	r := CredResult{Pattern: "github-token", Value: tok, Vendor: "github"}
	req, _ := http.NewRequestWithContext(ctx, "GET", "https://api.github.com/user", nil)
	req.Header.Set("Authorization", "token "+tok)
	req.Header.Set("Accept", "application/vnd.github+json")
	status, hdr, body, err := do(client, req)
	if err != nil {
		r.Verdict = CredError
		r.Reason = netErrorReason(err)
		return r
	}
	r.Status = status
	r.Verdict = classifyStatus(status)
	if r.Verdict == CredValid {
		var b struct {
			Login string `json:"login"`
			Email string `json:"email"`
		}
		_ = json.Unmarshal(body, &b)
		if b.Login != "" {
			r.Account = b.Login
		}
		if sc := hdr.Get("X-OAuth-Scopes"); sc != "" {
			for _, s := range strings.Split(sc, ",") {
				if s = strings.TrimSpace(s); s != "" {
					r.Scopes = append(r.Scopes, s)
				}
			}
		}
	}
	return r
}

func checkGitLab(ctx context.Context, tok string, client *http.Client) CredResult {
	r := CredResult{Pattern: "gitlab-pat", Value: tok, Vendor: "gitlab"}
	req, _ := http.NewRequestWithContext(ctx, "GET", "https://gitlab.com/api/v4/user", nil)
	req.Header.Set("PRIVATE-TOKEN", tok)
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
			Username string `json:"username"`
			Email    string `json:"email"`
		}
		_ = json.Unmarshal(body, &b)
		if b.Username != "" {
			r.Account = b.Username
		}
	}
	return r
}

func checkOpenAI(ctx context.Context, tok string, client *http.Client) CredResult {
	r := CredResult{Pattern: "openai-key", Value: tok, Vendor: "openai"}
	req, _ := http.NewRequestWithContext(ctx, "GET", "https://api.openai.com/v1/models", nil)
	req.Header.Set("Authorization", "Bearer "+tok)
	status, _, _, err := do(client, req)
	if err != nil {
		r.Verdict = CredError
		r.Reason = netErrorReason(err)
		return r
	}
	r.Status = status
	r.Verdict = classifyStatus(status)
	return r
}

func checkAnthropic(ctx context.Context, tok string, client *http.Client) CredResult {
	r := CredResult{Pattern: "anthropic-key", Value: tok, Vendor: "anthropic"}
	req, _ := http.NewRequestWithContext(ctx, "GET", "https://api.anthropic.com/v1/models", nil)
	req.Header.Set("x-api-key", tok)
	req.Header.Set("anthropic-version", "2023-06-01")
	status, _, _, err := do(client, req)
	if err != nil {
		r.Verdict = CredError
		r.Reason = netErrorReason(err)
		return r
	}
	r.Status = status
	r.Verdict = classifyStatus(status)
	return r
}

func checkSlack(ctx context.Context, tok string, client *http.Client) CredResult {
	r := CredResult{Pattern: "slack-token", Value: tok, Vendor: "slack"}
	req, _ := http.NewRequestWithContext(ctx, "GET", "https://slack.com/api/auth.test", nil)
	req.Header.Set("Authorization", "Bearer "+tok)
	status, _, body, err := do(client, req)
	if err != nil {
		r.Verdict = CredError
		r.Reason = netErrorReason(err)
		return r
	}
	r.Status = status
	// Slack returns 200 regardless; validity is in the JSON "ok" field.
	var b struct {
		OK    bool   `json:"ok"`
		Team  string `json:"team"`
		User  string `json:"user"`
		Error string `json:"error"`
	}
	_ = json.Unmarshal(body, &b)
	switch {
	case b.OK:
		r.Verdict = CredValid
		r.Account = b.User
		if b.Team != "" {
			r.Account = b.User + "@" + b.Team
		}
	case b.Error == "invalid_auth" || b.Error == "not_authed" || b.Error == "token_revoked":
		r.Verdict = CredRevoked
		r.Reason = b.Error
	case b.Error == "ratelimited":
		r.Verdict = CredRateLimited
	default:
		r.Verdict = CredError
		r.Reason = b.Error
	}
	return r
}

func checkSlackWebhook(ctx context.Context, u string, client *http.Client) CredResult {
	r := CredResult{Pattern: "slack-webhook-url", Value: u, Vendor: "slack-webhook"}
	// POST empty body: live webhook → "invalid_payload", dead → "no_service".
	// Never sends a message to the channel.
	req, _ := http.NewRequestWithContext(ctx, "POST", u, strings.NewReader(""))
	req.Header.Set("Content-Type", "application/json")
	status, _, body, err := do(client, req)
	if err != nil {
		r.Verdict = CredError
		r.Reason = netErrorReason(err)
		return r
	}
	r.Status = status
	text := string(body)
	switch {
	case strings.Contains(text, "no_service"):
		r.Verdict = CredRevoked
		r.Reason = "no_service"
	case strings.Contains(text, "invalid_payload"), strings.Contains(text, "missing_text_or_fallback_or_attachments"):
		r.Verdict = CredValid
	case status == 200 && text == "ok":
		r.Verdict = CredValid
	default:
		r.Verdict = CredUnknown
		r.Reason = fmt.Sprintf("HTTP %d", status)
	}
	return r
}

func checkSendGrid(ctx context.Context, tok string, client *http.Client) CredResult {
	r := CredResult{Pattern: "sendgrid-key", Value: tok, Vendor: "sendgrid"}
	req, _ := http.NewRequestWithContext(ctx, "GET", "https://api.sendgrid.com/v3/scopes", nil)
	req.Header.Set("Authorization", "Bearer "+tok)
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
			Scopes []string `json:"scopes"`
		}
		_ = json.Unmarshal(body, &b)
		r.Scopes = b.Scopes
	}
	return r
}

func checkMailgun(ctx context.Context, tok string, client *http.Client) CredResult {
	r := CredResult{Pattern: "mailgun-key", Value: tok, Vendor: "mailgun"}
	req, _ := http.NewRequestWithContext(ctx, "GET", "https://api.mailgun.net/v4/domains", nil)
	req.SetBasicAuth("api", tok)
	status, _, _, err := do(client, req)
	if err != nil {
		r.Verdict = CredError
		r.Reason = netErrorReason(err)
		return r
	}
	r.Status = status
	r.Verdict = classifyStatus(status)
	return r
}

func checkDiscord(ctx context.Context, tok string, client *http.Client) CredResult {
	r := CredResult{Pattern: "discord-bot-token", Value: tok, Vendor: "discord"}
	req, _ := http.NewRequestWithContext(ctx, "GET", "https://discord.com/api/v10/users/@me", nil)
	req.Header.Set("Authorization", "Bot "+tok)
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
			Username string `json:"username"`
			ID       string `json:"id"`
		}
		_ = json.Unmarshal(body, &b)
		if b.Username != "" {
			r.Account = b.Username
		}
	}
	return r
}

func checkTelegram(ctx context.Context, tok string, client *http.Client) CredResult {
	r := CredResult{Pattern: "telegram-bot-token", Value: tok, Vendor: "telegram"}
	req, _ := http.NewRequestWithContext(ctx, "GET", "https://api.telegram.org/bot"+tok+"/getMe", nil)
	status, _, body, err := do(client, req)
	if err != nil {
		r.Verdict = CredError
		r.Reason = netErrorReason(err)
		return r
	}
	r.Status = status
	var b struct {
		OK     bool `json:"ok"`
		Result struct {
			Username  string `json:"username"`
			FirstName string `json:"first_name"`
			ID        int64  `json:"id"`
		} `json:"result"`
		Description string `json:"description"`
	}
	_ = json.Unmarshal(body, &b)
	switch {
	case b.OK:
		r.Verdict = CredValid
		r.Account = "@" + b.Result.Username
	case status == 401 || strings.Contains(b.Description, "Unauthorized"):
		r.Verdict = CredRevoked
	default:
		r.Verdict = classifyStatus(status)
		r.Reason = b.Description
	}
	return r
}

func checkStripe(ctx context.Context, tok string, client *http.Client) CredResult {
	r := CredResult{Pattern: "stripe-key", Value: tok, Vendor: "stripe"}
	req, _ := http.NewRequestWithContext(ctx, "GET", "https://api.stripe.com/v1/account", nil)
	req.SetBasicAuth(tok, "")
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
			ID           string `json:"id"`
			BusinessName string `json:"business_profile.name"`
			Email        string `json:"email"`
		}
		_ = json.Unmarshal(body, &b)
		if b.Email != "" {
			r.Account = b.Email
		} else if b.ID != "" {
			r.Account = b.ID
		}
	}
	return r
}

func checkNPM(ctx context.Context, tok string, client *http.Client) CredResult {
	r := CredResult{Pattern: "npm-token", Value: tok, Vendor: "npm"}
	req, _ := http.NewRequestWithContext(ctx, "GET", "https://registry.npmjs.org/-/whoami", nil)
	req.Header.Set("Authorization", "Bearer "+tok)
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
			Username string `json:"username"`
		}
		_ = json.Unmarshal(body, &b)
		if b.Username != "" {
			r.Account = b.Username
		}
	}
	return r
}

func checkHuggingFace(ctx context.Context, tok string, client *http.Client) CredResult {
	r := CredResult{Pattern: "huggingface-token", Value: tok, Vendor: "huggingface"}
	req, _ := http.NewRequestWithContext(ctx, "GET", "https://huggingface.co/api/whoami-v2", nil)
	req.Header.Set("Authorization", "Bearer "+tok)
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
			Name  string `json:"name"`
			Email string `json:"email"`
		}
		_ = json.Unmarshal(body, &b)
		if b.Name != "" {
			r.Account = b.Name
		}
	}
	return r
}
