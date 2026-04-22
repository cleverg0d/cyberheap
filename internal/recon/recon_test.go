package recon

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestRun_Default200Only verifies the filter: out of 4 probed paths
// (200, 401, 404, 500) only the 200 reaches the shown slice while `all`
// keeps the full view for auto-download wiring.
func TestRun_Default200Only(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/actuator":
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`{"_links":{}}`))
		case "/env":
			w.WriteHeader(http.StatusUnauthorized)
		case "/heapdump":
			w.WriteHeader(http.StatusInternalServerError)
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer srv.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	shown, all, err := Run(ctx, Options{
		BaseURL: srv.URL,
		Paths:   []string{"/actuator", "/env", "/heapdump", "/missing"},
		Timeout: 2 * time.Second,
	})
	require.NoError(t, err)
	// Default filter: only 200 shown.
	assert.Len(t, shown, 1)
	assert.Equal(t, "/actuator", shown[0].Path)
	assert.Equal(t, 200, shown[0].Status)
	// Full list still has the 401 / 500 / 404 for internal wiring.
	assert.Len(t, all, 4)
}

// TestRun_ShowAuth adds 401/403 into the shown slice so the operator
// sees "endpoint exists, auth required" intel.
func TestRun_ShowAuth(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/actuator":
			w.WriteHeader(http.StatusOK)
		case "/actuator/env":
			w.WriteHeader(http.StatusUnauthorized)
		case "/actuator/heapdump":
			w.WriteHeader(http.StatusForbidden)
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer srv.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	shown, _, err := Run(ctx, Options{
		BaseURL:      srv.URL,
		Paths:        []string{"/actuator", "/actuator/env", "/actuator/heapdump"},
		ShowStatuses: map[int]bool{200: true, 401: true, 403: true},
		Timeout:      2 * time.Second,
	})
	require.NoError(t, err)
	assert.Len(t, shown, 3)
}

// TestHeapdumpHit_Detection ensures a 200 + octet-stream on an
// heapdump-ish path is flagged for auto-scan, while a 200 + HTML on the
// same path is NOT (that's a login page redirect usually).
func TestHeapdumpHit_Detection(t *testing.T) {
	yes := Result{Path: "/actuator/heapdump", Status: 200, ContentType: "application/octet-stream"}
	no := Result{Path: "/actuator/heapdump", Status: 200, ContentType: "text/html"}
	notHeapdump := Result{Path: "/actuator/env", Status: 200, ContentType: "application/octet-stream"}
	notLive := Result{Path: "/actuator/heapdump", Status: 401, ContentType: "application/octet-stream"}

	assert.True(t, yes.HeapdumpHit())
	assert.False(t, no.HeapdumpHit())
	assert.False(t, notHeapdump.HeapdumpHit())
	assert.False(t, notLive.HeapdumpHit())
}

// TestLoadWordlist skips blanks / comments and normalises leading slash.
func TestLoadWordlist(t *testing.T) {
	input := strings.NewReader(`
# comment at top
/actuator/heapdump
actuator/env

   /jolokia
# trailing
`)
	got := LoadWordlist(input)
	assert.Equal(t, []string{"/actuator/heapdump", "/actuator/env", "/jolokia"}, got)
}

// TestNormaliseBase_Variations accepts bare hostnames, scheme URLs,
// and ones with a non-root path prefix.
func TestNormaliseBase_Variations(t *testing.T) {
	cases := map[string]string{
		"example.com":              "https://example.com",
		"http://example.com":       "http://example.com",
		"https://example.com:8443": "https://example.com:8443",
		"https://example.com/":     "https://example.com",
		"https://example.com/api":  "https://example.com/api",
	}
	for in, want := range cases {
		got, err := normaliseBase(in)
		require.NoError(t, err, in)
		assert.Equal(t, want, got, in)
	}
}
