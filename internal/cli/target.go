package cli

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/cleverg0d/cyberheap/internal/hprof"
)

// target captures where the heapdump came from and how to access it.
// Scan logic needs a ReadSeeker (ParseHeader then Scan over the same bytes),
// so remote downloads are staged to a tempfile.
type target struct {
	displayName string // what to print on the report: /path/file.hprof OR example.com
	safeName    string // slug safe for filenames, derived from displayName
	size        int64
	file        *os.File
	header      *hprof.Header // filled in by the caller after ParseHeader
	cleanup     func()
	isRemote    bool
}

func (t *target) Close() {
	if t.file != nil {
		t.file.Close()
	}
	if t.cleanup != nil {
		t.cleanup()
	}
}

// openTarget resolves a CLI argument to a readable HPROF source.
// Supports local paths and http(s) URLs. Remote responses are streamed to a
// temp file so we keep ReadSeeker semantics without holding the full dump in
// RAM twice.
func openTarget(arg string) (*target, error) {
	if strings.HasPrefix(arg, "http://") || strings.HasPrefix(arg, "https://") {
		return openRemote(arg)
	}
	return openLocal(arg)
}

func openLocal(path string) (*target, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("open %s: %w", path, err)
	}
	st, err := f.Stat()
	if err != nil {
		f.Close()
		return nil, err
	}
	return &target{
		displayName: path,
		safeName:    slugForFilename(filepath.Base(path)),
		size:        st.Size(),
		file:        f,
	}, nil
}

func openRemote(raw string) (*target, error) {
	u, err := url.Parse(raw)
	if err != nil {
		return nil, fmt.Errorf("parse url: %w", err)
	}

	// 10 min default is enough for a 5-10 GB actuator/heapdump over a slow
	// pivot tunnel; callers can cancel via Ctrl-C.
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Minute)

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, raw, nil)
	if err != nil {
		cancel()
		return nil, err
	}
	req.Header.Set("User-Agent", "CyberHeap/0.1 (+https://github.com/cleverg0d/cyberheap)")
	req.Header.Set("Accept", "*/*")

	fmt.Fprintf(os.Stderr, "  fetching %s ... ", raw)
	start := time.Now()

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		cancel()
		return nil, fmt.Errorf("http: %w", err)
	}
	if resp.StatusCode >= 400 {
		resp.Body.Close()
		cancel()
		return nil, fmt.Errorf("http %d %s", resp.StatusCode, resp.Status)
	}

	tmp, err := os.CreateTemp("", "cyberheap-*.hprof")
	if err != nil {
		resp.Body.Close()
		cancel()
		return nil, err
	}

	n, err := io.Copy(tmp, resp.Body)
	resp.Body.Close()
	if err != nil {
		tmp.Close()
		os.Remove(tmp.Name())
		cancel()
		return nil, fmt.Errorf("download: %w", err)
	}
	if _, err := tmp.Seek(0, io.SeekStart); err != nil {
		tmp.Close()
		os.Remove(tmp.Name())
		cancel()
		return nil, err
	}

	fmt.Fprintf(os.Stderr, "%s in %s\n", humanBytes(n), time.Since(start).Round(100*time.Millisecond))

	host := u.Host
	if host == "" {
		host = raw
	}

	return &target{
		displayName: raw,
		safeName:    slugForFilename(host),
		size:        n,
		file:        tmp,
		isRemote:    true,
		cleanup: func() {
			os.Remove(tmp.Name())
			cancel()
		},
	}, nil
}

// slugForFilename sanitizes a target into a safe filename component.
// e.g. "actuator.acme.com:8080" -> "actuator.acme.com_8080"
func slugForFilename(s string) string {
	bad := []string{"/", "\\", ":", "?", "*", "|", "\"", "<", ">", " "}
	for _, b := range bad {
		s = strings.ReplaceAll(s, b, "_")
	}
	s = strings.TrimSuffix(s, ".hprof")
	if s == "" {
		return "target"
	}
	return s
}
