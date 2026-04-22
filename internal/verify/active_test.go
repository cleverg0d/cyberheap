package verify

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
)

// TestVerifyOAuth2ClientCredentials_Valid spins up a mock Keycloak-style
// token endpoint and asserts we classify a 200+access_token as VALID.
func TestVerifyOAuth2ClientCredentials_Valid(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/protocol/openid-connect/token" {
			w.WriteHeader(http.StatusNotFound)
			return
		}
		body, _ := io.ReadAll(r.Body)
		assert.Contains(t, string(body), "grant_type=client_credentials")
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"access_token":"eyJ...","token_type":"Bearer","expires_in":300}`))
	}))
	defer srv.Close()

	r := VerifyOAuth2ClientCredentials(context.Background(),
		OAuthTarget{BaseURL: srv.URL, ClientID: "app", ClientSecret: "s3cret"},
		srv.Client())
	assert.Equal(t, CredValid, r.Verdict)
	assert.Contains(t, r.Reason, "/protocol/openid-connect/token")
}

// TestVerifyOAuth2ClientCredentials_Revoked: 401 invalid_client → Revoked.
func TestVerifyOAuth2ClientCredentials_Revoked(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusUnauthorized)
		_, _ = w.Write([]byte(`{"error":"invalid_client","error_description":"bad secret"}`))
	}))
	defer srv.Close()

	r := VerifyOAuth2ClientCredentials(context.Background(),
		OAuthTarget{BaseURL: srv.URL, ClientID: "app", ClientSecret: "wrong"},
		srv.Client())
	assert.Equal(t, CredRevoked, r.Verdict)
	assert.Equal(t, "invalid_client", r.Reason)
}

// TestVerifyHTTPBasic_Valid confirms 200 on HEAD with Basic auth → Valid.
func TestVerifyHTTPBasic_Valid(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		u, p, ok := r.BasicAuth()
		if !ok || u != "admin" || p != "s3cret" {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	r := VerifyHTTPBasic(context.Background(), srv.URL, "admin", "s3cret", srv.Client())
	assert.Equal(t, CredValid, r.Verdict)
	assert.Equal(t, "admin", r.Account)
}

// TestVerifyOIDCUserinfo: discovery + userinfo both live → Valid with sub.
func TestVerifyOIDCUserinfo(t *testing.T) {
	var srvURL string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/.well-known/openid-configuration":
			_, _ = w.Write([]byte(`{"userinfo_endpoint":"` + srvURL + `/userinfo"}`))
		case "/userinfo":
			auth := r.Header.Get("Authorization")
			if !strings.HasPrefix(auth, "Bearer ") {
				w.WriteHeader(http.StatusUnauthorized)
				return
			}
			_, _ = w.Write([]byte(`{"sub":"alice-uuid","preferred_username":"alice"}`))
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer srv.Close()
	srvURL = srv.URL

	cache := newOIDCCache()
	r := VerifyOIDCUserinfo(context.Background(), srv.URL, "token", srv.Client(), cache)
	assert.Equal(t, CredValid, r.Verdict)
	assert.Equal(t, "alice", r.Account)
}
