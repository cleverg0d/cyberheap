// Package recon probes a single base URL for exposed actuator / JMX
// endpoints. Given a hostname or full URL it issues GET requests to a
// curated path list (or a user-supplied wordlist), collects HTTP status
// and content type, and optionally streams the heap dump to disk when
// /actuator/heapdump responds with a large binary body.
//
// Recon intentionally does NOT implement RCE primitives against the
// discovered endpoints. /env POST-injection, /gateway route poisoning
// and Jolokia exploits are the job of dedicated tools (Spring exploit
// frameworks, jolokia-exploitation-toolkit). Recon only finds and labels.
package recon

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"sort"
	"strings"
	"sync"
	"time"
)

// Result is one probe outcome. Omitted when the request errored or
// produced a status the caller asked to hide.
type Result struct {
	Path        string
	URL         string
	Status      int
	ContentType string
	Size        int64 // -1 if unknown (HEAD / no Content-Length)
	Note        string
	Err         string
}

// HeapdumpHit marks a result whose path suggests a downloadable heap
// dump and whose response was a large application/octet-stream.
func (r *Result) HeapdumpHit() bool {
	if r == nil || r.Status != 200 {
		return false
	}
	if !strings.Contains(r.Path, "heapdump") {
		return false
	}
	ct := strings.ToLower(r.ContentType)
	if strings.Contains(ct, "octet-stream") || strings.Contains(ct, "java-serialized") {
		return true
	}
	return r.Size > 1<<20 // > 1 MiB body, likely binary
}

// Options configure one recon run.
type Options struct {
	BaseURL     string
	Paths       []string
	Concurrency int
	Timeout     time.Duration
	UserAgent   string
	// ShowStatuses is the set of HTTP status codes the caller wants
	// surfaced. Empty means "only 200". 401/403 can be opted in for
	// "endpoint exists but auth required" intel.
	ShowStatuses map[int]bool
}

const defaultUA = "cyberheap/recon"

// Run probes every opts.Paths against opts.BaseURL concurrently and
// returns the filtered result set (only statuses in opts.ShowStatuses)
// plus the full unfiltered slice for internal wiring (auto-download).
func Run(ctx context.Context, opts Options) ([]Result, []Result, error) {
	base, err := normaliseBase(opts.BaseURL)
	if err != nil {
		return nil, nil, err
	}
	if opts.Concurrency <= 0 {
		opts.Concurrency = 12
	}
	if opts.Timeout <= 0 {
		opts.Timeout = 5 * time.Second
	}
	if opts.UserAgent == "" {
		opts.UserAgent = defaultUA
	}
	if len(opts.ShowStatuses) == 0 {
		opts.ShowStatuses = map[int]bool{200: true}
	}
	if len(opts.Paths) == 0 {
		opts.Paths = DefaultPaths()
	}

	client := &http.Client{
		Timeout: opts.Timeout,
		// Follow redirects but cap the chain — modern Spring Boot
		// likes 302 → /login for protected endpoints; we still want
		// the terminal status.
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			if len(via) >= 3 {
				return http.ErrUseLastResponse
			}
			return nil
		},
	}

	sem := make(chan struct{}, opts.Concurrency)
	var mu sync.Mutex
	var all []Result
	var wg sync.WaitGroup

	for _, p := range opts.Paths {
		p := p
		wg.Add(1)
		sem <- struct{}{}
		go func() {
			defer wg.Done()
			defer func() { <-sem }()
			r := probe(ctx, client, base, p, opts.UserAgent)
			mu.Lock()
			all = append(all, r)
			mu.Unlock()
		}()
	}
	wg.Wait()

	sort.Slice(all, func(i, j int) bool {
		if all[i].Status != all[j].Status {
			return all[i].Status > all[j].Status // 200 first, 0 last
		}
		return all[i].Path < all[j].Path
	})

	var shown []Result
	for _, r := range all {
		if opts.ShowStatuses[r.Status] {
			shown = append(shown, r)
		}
	}
	return shown, all, nil
}

// probe fires one GET and captures status + content-type + size.
// Body is discarded (we never keep the whole response in memory);
// the caller runs a dedicated downloader for heapdump hits.
func probe(ctx context.Context, client *http.Client, base, path, ua string) Result {
	full := base + path
	r := Result{Path: path, URL: full, Size: -1}
	req, err := http.NewRequestWithContext(ctx, "GET", full, nil)
	if err != nil {
		r.Err = err.Error()
		return r
	}
	req.Header.Set("User-Agent", ua)
	req.Header.Set("Accept", "*/*")
	resp, err := client.Do(req)
	if err != nil {
		r.Err = simplifyNetErr(err)
		return r
	}
	defer resp.Body.Close()
	// Drain body briefly to avoid server hang on large bodies, but
	// never read full payload — reserved for the dedicated downloader.
	_, _ = io.CopyN(io.Discard, resp.Body, 4096)
	r.Status = resp.StatusCode
	r.ContentType = resp.Header.Get("Content-Type")
	if cl := resp.Header.Get("Content-Length"); cl != "" {
		fmt.Sscanf(cl, "%d", &r.Size)
	}
	r.Note = annotate(path, resp.StatusCode, r.ContentType)
	return r
}

// annotate adds a short pentest-relevant note next to each result.
func annotate(path string, status int, ct string) string {
	p := strings.ToLower(path)
	switch {
	case strings.HasSuffix(p, "/heapdump") && status == 200:
		return "heapdump downloadable — triage with cyberheap scan"
	case strings.HasSuffix(p, "/env") && status == 200:
		return "property leak — also check POST for injection (external tool)"
	case strings.HasSuffix(p, "/configprops") && status == 200:
		return "configuration tree — secrets by spring.* key"
	case strings.Contains(p, "jolokia") && status == 200:
		return "Jolokia MBean bridge — see jolokia-exploitation-toolkit"
	case strings.HasSuffix(p, "/httpexchanges") || strings.HasSuffix(p, "/httptrace"):
		return "recent request/response headers — may leak Authorization"
	case strings.HasSuffix(p, "/gateway/routes") && status == 200:
		return "gateway route injection surface (external RCE tool)"
	}
	return ""
}

// DownloadHeapdump streams the body of url into dst. Returns bytes
// written and a size-safety error if the response is tiny (suggesting
// an HTML login page rather than a real dump).
func DownloadHeapdump(ctx context.Context, url, dst, ua string, timeout time.Duration) (int64, error) {
	if timeout <= 0 {
		timeout = 5 * time.Minute
	}
	client := &http.Client{Timeout: timeout}
	req, err := http.NewRequestWithContext(ctx, "GET", url, nil)
	if err != nil {
		return 0, err
	}
	req.Header.Set("User-Agent", ua)
	req.Header.Set("Accept", "application/octet-stream")
	resp, err := client.Do(req)
	if err != nil {
		return 0, fmt.Errorf("GET %s: %w", url, err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		return 0, fmt.Errorf("GET %s: HTTP %d", url, resp.StatusCode)
	}
	out, err := os.Create(dst)
	if err != nil {
		return 0, err
	}
	defer out.Close()
	n, err := io.Copy(out, resp.Body)
	if err != nil {
		return n, err
	}
	if n < 1<<20 {
		return n, fmt.Errorf("suspiciously small body (%d bytes) — likely not a heap dump", n)
	}
	return n, nil
}

// normaliseBase accepts a bare hostname, scheme-only prefix or full URL
// and returns a base of the form "https://host[:port]" with no trailing
// slash. Bare hostnames default to https.
func normaliseBase(raw string) (string, error) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return "", errors.New("empty target")
	}
	if !strings.Contains(raw, "://") {
		raw = "https://" + raw
	}
	u, err := url.Parse(raw)
	if err != nil {
		return "", fmt.Errorf("invalid URL %q: %w", raw, err)
	}
	if u.Host == "" {
		return "", fmt.Errorf("no host in %q", raw)
	}
	scheme := u.Scheme
	if scheme == "" {
		scheme = "https"
	}
	base := scheme + "://" + u.Host
	// Preserve a non-root path prefix (e.g. user passed `/api/v1`).
	if strings.TrimSuffix(u.Path, "/") != "" {
		base += strings.TrimSuffix(u.Path, "/")
	}
	return base, nil
}

func simplifyNetErr(err error) string {
	s := err.Error()
	switch {
	case strings.Contains(s, "no such host"):
		return "NXDOMAIN"
	case strings.Contains(s, "timeout"), strings.Contains(s, "deadline"):
		return "timeout"
	case strings.Contains(s, "refused"):
		return "refused"
	case strings.Contains(s, "no route"):
		return "no-route"
	case strings.Contains(s, "certificate"):
		return "tls-error"
	}
	return "error"
}
