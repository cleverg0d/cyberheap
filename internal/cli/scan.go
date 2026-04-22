package cli

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"regexp"
	"sort"
	"strings"
	"time"

	"github.com/spf13/cobra"

	"github.com/cleverg0d/cyberheap/internal/decode"
	"github.com/cleverg0d/cyberheap/internal/heap"
	"github.com/cleverg0d/cyberheap/internal/hprof"
	"github.com/cleverg0d/cyberheap/internal/scanner"
	"github.com/cleverg0d/cyberheap/internal/spiders"
	"github.com/cleverg0d/cyberheap/internal/verify"
)

type scanFlags struct {
	format        string
	severities    []string
	categories    []string
	skipHeader    bool
	utf16         bool
	noColor       bool // filled from NO_COLOR env var only
	mask          bool
	minCount      int
	verbose       bool
	outputDir     string
	noRegex       bool
	noSpiders     bool
	diffAgainst   string
	patternFiles  []string
	patternsOnly  bool
	offline       bool
	dnsServer     string
	doVerifyCreds bool
	timeout       time.Duration
	apexes        []string
}

// maxValueChars caps displayed value length. Fits a JWT header + a few claims.
const maxValueChars = 200

func newScanCmd() *cobra.Command {
	var f scanFlags
	cmd := &cobra.Command{
		Use:   "scan <file.hprof | http(s)://host/actuator/heapdump>",
		Short: "Scan a heap dump for credentials, keys, tokens and secrets",
		Long: `Scan runs a fast regex-based pass over the raw bytes of an HPROF file.
This catches credentials, API keys, tokens, JDBC URLs and similar artefacts
without requiring full heap parsing. Recognized tokens (basic auth, JWT) are
decoded inline for quick triage.

The target may be a local file path or an http(s) URL (e.g. an exposed
Spring Boot actuator/heapdump endpoint). Remote dumps are streamed to a
temp file and deleted after the scan.`,
		Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			return runScan(cmd, args[0], &f)
		},
	}
	// Output shape.
	cmd.Flags().StringVar(&f.format, "format", "pretty", "output format: pretty, json, markdown")
	cmd.Flags().StringVarP(&f.outputDir, "output", "o", "", "save/merge findings as JSON into DIR/<target>.json")

	// Filtering.
	cmd.Flags().StringSliceVar(&f.severities, "severity", nil, "filter by severity (comma-separated): critical,high,medium,low,info")
	cmd.Flags().StringSliceVar(&f.categories, "category", nil, "filter by category (comma-separated)")
	cmd.Flags().IntVar(&f.minCount, "min-count", 1, "drop findings seen fewer than N times")

	// Presentation.
	cmd.Flags().BoolVar(&f.mask, "mask", false, "mask secret values (for client-facing reports)")
	cmd.Flags().BoolVarP(&f.verbose, "verbose", "v", false, "show byte offsets and raw values next to decoded findings")

	// Network validation (default: passive DNS + TCP + JWT exp).
	cmd.Flags().BoolVar(&f.offline, "offline", false, "skip ALL network (no DNS, no TCP, no cred probes)")
	cmd.Flags().BoolVar(&f.doVerifyCreds, "verify-creds", false, "actively validate each leaked cred/token against its service (1 attempt, public endpoints only)")
	cmd.Flags().StringVar(&f.dnsServer, "dns", "1.1.1.1", "DNS server for host resolution")
	cmd.Flags().DurationVar(&f.timeout, "timeout", 5*time.Second, "per-lookup timeout (DNS, TCP, HTTP)")
	cmd.Flags().StringSliceVar(&f.apexes, "domain", nil, "enumerate and resolve every subdomain of this apex found in heap strings (repeatable, comma-separated)")

	// Retest.
	cmd.Flags().StringVar(&f.diffAgainst, "diff-against", "", "compare against earlier JSON report — tag new (+), unchanged (=), closed (-)")

	// Power-user passes (hidden — the default scan runs both).
	cmd.Flags().BoolVar(&f.noRegex, "no-regex", false, "")
	cmd.Flags().BoolVar(&f.noSpiders, "no-spiders", false, "")
	cmd.Flags().BoolVar(&f.utf16, "utf16", false, "")
	cmd.Flags().BoolVar(&f.skipHeader, "no-header-check", false, "")
	cmd.Flags().StringArrayVar(&f.patternFiles, "patterns", nil, "")
	cmd.Flags().BoolVar(&f.patternsOnly, "patterns-only", false, "")
	for _, hidden := range []string{"no-regex", "no-spiders", "utf16", "no-header-check", "patterns", "patterns-only"} {
		_ = cmd.Flags().MarkHidden(hidden)
	}

	return cmd
}

func runScan(cmd *cobra.Command, arg string, f *scanFlags) error {
	f.noColor = f.noColor || os.Getenv("NO_COLOR") != ""

	tgt, err := openTarget(arg)
	if err != nil {
		return err
	}
	defer tgt.Close()

	if !f.skipHeader {
		h, err := hprof.ParseHeader(tgt.file)
		if err != nil {
			return fmt.Errorf("not a readable HPROF file: %w (use --no-header-check to scan anyway)", err)
		}
		tgt.header = h
		if _, err := tgt.file.Seek(0, io.SeekStart); err != nil {
			return fmt.Errorf("seek: %w", err)
		}
	}

	sevSet, err := parseSeverities(f.severities)
	if err != nil {
		return err
	}
	catSet, err := parseCategories(f.categories)
	if err != nil {
		return err
	}

	start := time.Now()

	var enriched []enrichedMatch
	var spiderFindings []spiders.Finding
	var regexElapsed, spiderElapsed time.Duration

	if !f.noRegex {
		patterns, perr := resolvePatternSet(f.patternFiles, f.patternsOnly)
		if perr != nil {
			return perr
		}
		t0 := time.Now()
		scanOpts := scanner.Options{
			Severities: sevSet,
			Categories: catSet,
			ScanUTF16:  f.utf16,
			Patterns:   patterns,
		}
		// Auto-pick streaming for large dumps so we don't try to ReadAll
		// a 5 GiB file into RAM. ShouldStream returns true above ~512 MiB;
		// below that the single-pass path is both faster and simpler.
		var (
			matches []scanner.Match
			err     error
		)
		if scanner.ShouldStream(tgt.size) {
			if _, serr := tgt.file.Seek(0, io.SeekStart); serr != nil {
				return fmt.Errorf("seek for streaming scan: %w", serr)
			}
			matches, err = scanner.ScanStream(tgt.file, tgt.size, scanner.StreamOptions{Options: scanOpts})
		} else {
			matches, err = scanner.Scan(tgt.file, scanOpts)
		}
		if err != nil {
			return fmt.Errorf("regex scan: %w", err)
		}
		regexElapsed = time.Since(t0)

		if f.minCount > 1 {
			filtered := matches[:0:0]
			for _, m := range matches {
				if m.Count >= f.minCount {
					filtered = append(filtered, m)
				}
			}
			matches = filtered
		}
		enriched = enrich(matches)
	}

	var subdomains []string
	needIndex := !f.noSpiders || len(f.apexes) > 0

	if needIndex {
		t0 := time.Now()
		mi, err := buildIndex(tgt)
		if err != nil {
			// Don't fail the whole scan — just tell the user and keep the regex findings.
			fmt.Fprintf(cmd.ErrOrStderr(), "  %sstructured pass skipped: %v%s\n",
				dimOnly(!f.noColor), err, resetOnly(!f.noColor))
		} else {
			defer mi.Close()
			if !f.noSpiders {
				for _, sp := range spiders.Registry() {
					spiderFindings = append(spiderFindings, sp.Sniff(mi.Index)...)
				}
				spiderFindings = filterSpiderFindings(spiderFindings, sevSet, catSet)
				spiderFindings = spiders.TagDefaultAndWeak(spiderFindings)
				sortSpiderFindings(spiderFindings)
			}
			if len(f.apexes) > 0 {
				subdomains = extractSubdomainsFromIndex(mi.Index, f.apexes)
			}
		}
		spiderElapsed = time.Since(t0)
	}

	var verifyReport *verify.Report
	if !f.offline {
		hosts, jwts, creds, oauthTargets := collectVerificationTargets(enriched, spiderFindings)
		if len(hosts) > 0 || len(jwts) > 0 || len(creds) > 0 || len(oauthTargets) > 0 || len(subdomains) > 0 {
			overall := f.timeout * time.Duration(len(hosts)+len(jwts)+len(creds)+len(oauthTargets)+len(subdomains)+4)
			if overall < 15*time.Second {
				overall = 15 * time.Second
			}
			ctx, cancel := context.WithTimeout(cmd.Context(), overall)
			verifyReport = verify.Run(ctx, hosts, jwts, creds, oauthTargets, subdomains, verify.Options{
				DNSServer:    f.dnsServer,
				ProbeTCP:     true,
				Timeout:      f.timeout,
				Concurrency:  16,
				VerifyCreds:  f.doVerifyCreds,
				CredsTimeout: f.timeout,
			})
			cancel()
		}
	}

	// Post-verify: elevate to CRITICAL only when a credential was
	// actually validated against a live service. Otherwise findings stay
	// at their default HIGH — we refuse to claim "critical" on
	// unvalidated leaks.
	elevateSeverityOnValidation(spiderFindings, verifyReport)
	sortSpiderFindings(spiderFindings)

	elapsed := time.Since(start)
	_ = regexElapsed
	_ = spiderElapsed

	diff, err := loadDiffState(f.diffAgainst)
	if err != nil {
		return err
	}

	w := cmd.OutOrStdout()
	switch f.format {
	case "json":
		if err := emitJSON(w, tgt, enriched, spiderFindings, verifyReport); err != nil {
			return err
		}
	case "pretty":
		if err := emitPretty(w, tgt, enriched, spiderFindings, elapsed, f, diff, verifyReport); err != nil {
			return err
		}
	case "markdown", "md":
		if err := emitMarkdown(w, tgt, enriched, spiderFindings, elapsed, f); err != nil {
			return err
		}
	default:
		return fmt.Errorf("unknown format %q (use pretty, json, or markdown)", f.format)
	}

	if f.outputDir != "" {
		path, added, updated, err := saveReport(f.outputDir, tgt.safeName, tgt.displayName, enriched, spiderFindings)
		if err != nil {
			return err
		}
		fmt.Fprintf(w, "\n  %ssaved%s %s  (+%d new, %d updated)\n",
			dimOnly(!f.noColor), resetOnly(!f.noColor), path, added, updated)
	}

	return nil
}

// collectVerificationTargets pulls probe inputs from both passes:
//   - hosts: URL/host-shaped values for DNS/TCP
//   - jwts:  eyJ… dot-separated tokens
//   - creds: regex matches with vendor-specific patterns (SaaS whoami)
//   - oauth: (baseurl + clientId + clientSecret[+ user/pass + grantType])
//     triples extracted from structured findings for active OAuth probes
func collectVerificationTargets(items []enrichedMatch, spFindings []spiders.Finding) (
	hosts []verify.Host, jwts []string, creds []verify.CredTarget, oauth []verify.OAuthTarget,
) {
	seenJWT := map[string]bool{}
	addJWT := func(v string) {
		v = strings.TrimSpace(v)
		if !strings.HasPrefix(v, "eyJ") || strings.Count(v, ".") != 2 {
			return
		}
		if seenJWT[v] {
			return
		}
		seenJWT[v] = true
		jwts = append(jwts, v)
	}

	values := make([]string, 0, len(items)+len(spFindings)*4)
	seenCred := map[string]bool{}
	for _, em := range items {
		values = append(values, em.m.Value)
		switch em.m.Pattern.Name {
		case "jwt-token", "bearer-token":
			addJWT(em.m.Value)
		}
		key := em.m.Pattern.Name + "|" + em.m.Value
		if !seenCred[key] {
			seenCred[key] = true
			creds = append(creds, verify.CredTarget{
				Pattern: em.m.Pattern.Name,
				Value:   em.m.Value,
			})
		}
	}
	for _, sf := range spFindings {
		for _, kv := range sf.Fields {
			values = append(values, kv.Value)
			addJWT(kv.Value)
		}
		oauth = append(oauth, extractOAuthTargets(sf)...)
	}

	hosts = verify.ExtractHostsFromValues(values)
	return hosts, jwts, creds, oauth
}

// extractOAuthTargets groups fields in one structured finding by
// property-prefix. A prefix yields a target iff we can resolve
// {baseurl, clientId, clientSecret}. Optional fields (username/password/
// grantType/scope) unlock password-grant when present.
func extractOAuthTargets(sf spiders.Finding) []verify.OAuthTarget {
	type acc struct{ base, cid, csec, user, pass, grant, scope string }
	byPrefix := map[string]*acc{}
	get := func(p string) *acc {
		if v, ok := byPrefix[p]; ok {
			return v
		}
		v := &acc{}
		byPrefix[p] = v
		return v
	}
	for _, kv := range sf.Fields {
		leaf := kv.Name
		prefix := ""
		if i := strings.LastIndexByte(kv.Name, '.'); i > 0 {
			prefix = kv.Name[:i]
			leaf = kv.Name[i+1:]
		}
		n := strings.ToLower(strings.ReplaceAll(strings.ReplaceAll(leaf, "-", ""), "_", ""))
		a := get(prefix)
		switch {
		case strings.Contains(n, "baseurl"), n == "url", n == "uri", strings.HasSuffix(n, "endpoint"):
			if strings.Contains(kv.Value, "://") && a.base == "" {
				a.base = kv.Value
			}
		case strings.Contains(n, "clientsecret"):
			a.csec = kv.Value
		case strings.Contains(n, "clientid"):
			a.cid = kv.Value
		case n == "username" || strings.HasSuffix(n, "username") || n == "user" || strings.HasSuffix(n, "user") || n == "login" || strings.HasSuffix(n, "login"):
			a.user = kv.Value
		case strings.Contains(n, "password"):
			a.pass = kv.Value
		case strings.Contains(n, "granttype"), strings.Contains(n, "grantflow"):
			a.grant = kv.Value
		case n == "scope" || strings.HasSuffix(n, "scope"):
			a.scope = kv.Value
		}
	}
	var out []verify.OAuthTarget
	for p, a := range byPrefix {
		if a.base == "" || a.cid == "" {
			continue
		}
		out = append(out, verify.OAuthTarget{
			Prefix:       p,
			BaseURL:      a.base,
			ClientID:     a.cid,
			ClientSecret: a.csec,
			Username:     a.user,
			Password:     a.pass,
			GrantType:    a.grant,
			Scope:        a.scope,
		})
	}
	// Stable sort for deterministic tests/output.
	sort.Slice(out, func(i, j int) bool { return out[i].Prefix < out[j].Prefix })
	return out
}

// extractSubdomainsFromIndex walks the heap string table + every
// java.lang.String instance, regex-matches hostnames whose suffix is
// one of the configured apex domains, and returns the deduplicated
// sorted list. Apex-filtered enumeration gives a pentester the attack
// surface beyond OSINT — CT logs, search indexes, bruteforce — since
// internal staging names often only exist inside the dump.
func extractSubdomainsFromIndex(idx *heap.Index, apexes []string) []string {
	normalized := normalizeApexes(apexes)
	if len(normalized) == 0 {
		return nil
	}
	re := buildApexRegex(normalized)
	seen := map[string]bool{}
	consume := func(s string) {
		if s == "" {
			return
		}
		low := strings.ToLower(s)
		for _, m := range re.FindAllString(low, -1) {
			m = strings.Trim(m, ".-")
			if m == "" || !isPlausibleHostname(m) {
				continue
			}
			seen[m] = true
		}
	}
	for _, s := range idx.Strings {
		consume(s)
	}
	if cls, ok := idx.ClassByName["java.lang.String"]; ok {
		for _, inst := range idx.Instances[cls.ID] {
			if v, ok := idx.ReadString(inst.ID); ok {
				consume(v)
			}
		}
	}
	out := make([]string, 0, len(seen))
	for k := range seen {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

func normalizeApexes(in []string) []string {
	seen := map[string]bool{}
	out := make([]string, 0, len(in))
	for _, a := range in {
		a = strings.ToLower(strings.TrimSpace(a))
		a = strings.TrimPrefix(a, "*.")
		a = strings.Trim(a, ".")
		if a == "" || seen[a] {
			continue
		}
		seen[a] = true
		out = append(out, a)
	}
	return out
}

func buildApexRegex(apexes []string) *regexp.Regexp {
	quoted := make([]string, len(apexes))
	for i, a := range apexes {
		quoted[i] = regexp.QuoteMeta(a)
	}
	return regexp.MustCompile(`\b(?:[a-z0-9][a-z0-9-]{0,62}\.)*(?:` + strings.Join(quoted, "|") + `)\b`)
}

// isPlausibleHostname rejects matches whose last label is mixed-case
// (Java classnames) or too long (garbage), reusing the stricter
// verify.isHostLiteral rules indirectly by bounding labels here.
func isPlausibleHostname(h string) bool {
	if len(h) < 4 || len(h) > 253 {
		return false
	}
	for _, part := range strings.Split(h, ".") {
		if part == "" || len(part) > 63 {
			return false
		}
		if part[0] == '-' || part[len(part)-1] == '-' {
			return false
		}
	}
	return true
}

// elevateSeverityOnValidation bumps a finding to Critical iff any of
// its values was actually validated live (OAuth2/OIDC/SaaS whoami
// returned VALID). No verify-creds → no elevation.
func elevateSeverityOnValidation(findings []spiders.Finding, rep *verify.Report) {
	if rep == nil || rep.Empty() {
		return
	}
	for i := range findings {
		validated := false
		for _, kv := range findings[i].Fields {
			if c := rep.CredByValue(kv.Value); c != nil && c.Verdict == verify.CredValid {
				validated = true
				break
			}
			if c := rep.OAuthByClientID(kv.Value); c != nil && c.Verdict == verify.CredValid {
				validated = true
				break
			}
		}
		if validated {
			findings[i].Severity = spiders.SeverityCritical
			findings[i].Flags = append(findings[i].Flags, "validated")
		}
	}
}

// sortSpiderFindings: severity desc, then title asc.
func sortSpiderFindings(in []spiders.Finding) {
	sort.SliceStable(in, func(i, j int) bool {
		if in[i].Severity != in[j].Severity {
			return in[i].Severity > in[j].Severity
		}
		if in[i].Title != in[j].Title {
			return in[i].Title < in[j].Title
		}
		return in[i].ObjectID < in[j].ObjectID
	})
}

// filterSpiderFindings applies the same --severity / --category filters the
// regex scanner honours.
func filterSpiderFindings(in []spiders.Finding, sev scanner.SeveritySet, cat scanner.CategorySet) []spiders.Finding {
	if sev == nil && cat == nil {
		return in
	}
	out := in[:0:0]
	for _, f := range in {
		if sev != nil && !sev[spiderSevToScanner(f.Severity)] {
			continue
		}
		if cat != nil && !cat[scanner.Category(f.Category)] {
			continue
		}
		out = append(out, f)
	}
	return out
}

func spiderSevToScanner(s spiders.Severity) scanner.Severity {
	switch s {
	case spiders.SeverityCritical:
		return scanner.SeverityCritical
	case spiders.SeverityHigh:
		return scanner.SeverityHigh
	case spiders.SeverityMedium:
		return scanner.SeverityMedium
	case spiders.SeverityLow:
		return scanner.SeverityLow
	}
	return scanner.SeverityInfo
}

// enrichedMatch pairs a scanner.Match with an optional inline decoding.
type enrichedMatch struct {
	m   scanner.Match
	dec *decode.Decoded
}

func enrich(matches []scanner.Match) []enrichedMatch {
	out := make([]enrichedMatch, 0, len(matches))
	for _, m := range matches {
		em := enrichedMatch{m: m}
		em.dec = decode.TryDecode(m.Pattern.Name, m.Value)
		out = append(out, em)
	}
	return out
}

func parseSeverities(raw []string) (scanner.SeveritySet, error) {
	if len(raw) == 0 {
		return nil, nil
	}
	out := scanner.SeveritySet{}
	for _, item := range raw {
		for _, s := range strings.Split(item, ",") {
			s = strings.TrimSpace(s)
			if s == "" {
				continue
			}
			sev, ok := scanner.ParseSeverity(s)
			if !ok {
				return nil, fmt.Errorf("unknown severity %q", s)
			}
			out[sev] = true
		}
	}
	return out, nil
}

// knownCategories lists the category names every built-in pattern and
// spider uses. Custom TOML rules can define new categories — those are
// accepted verbatim. Strictness here is the difference between a typo
// ("cloul" instead of "cloud") producing no findings silently vs. an
// explicit error the user can fix.
var knownCategories = map[scanner.Category]bool{
	scanner.CatDatasource:  true,
	scanner.CatCredentials: true,
	scanner.CatCloud:       true,
	scanner.CatSCM:         true,
	scanner.CatPaymentSaaS: true,
	scanner.CatPrivateKey:  true,
	scanner.CatJWT:         true,
	scanner.CatConnString:  true,
	scanner.CatAuth:        true,
	scanner.CatPersonal:    true,
	// Spider-emitted categories that aren't in the scanner enum:
	"shiro": true,
}

func parseCategories(raw []string) (scanner.CategorySet, error) {
	if len(raw) == 0 {
		return nil, nil
	}
	out := scanner.CategorySet{}
	for _, item := range raw {
		for _, s := range strings.Split(item, ",") {
			s = strings.TrimSpace(strings.ToLower(s))
			if s == "" {
				continue
			}
			cat := scanner.Category(s)
			if !knownCategories[cat] {
				return nil, fmt.Errorf("unknown category %q (known: datasource, credentials, cloud, scm, payment-saas, private-key, jwt, connection-string, auth, personal, shiro)", s)
			}
			out[cat] = true
		}
	}
	return out, nil
}

type jsonFinding struct {
	Severity    string `json:"severity"`
	Category    string `json:"category"`
	Pattern     string `json:"pattern"`
	Value       string `json:"value"`
	Offset      int64  `json:"offset"`
	Count       int    `json:"count"`
	DecodedKind string `json:"decoded_kind,omitempty"`
	DecodedText string `json:"decoded_text,omitempty"`
}

type jsonSpiderFinding struct {
	Severity string            `json:"severity"`
	Category string            `json:"category"`
	Spider   string            `json:"spider"`
	Title    string            `json:"title"`
	ClassFQN string            `json:"class_fqn"`
	ObjectID string            `json:"object_id"`
	Fields   map[string]string `json:"fields"`
}

type jsonOut struct {
	File     string              `json:"file"`
	Size     int64               `json:"size_bytes"`
	Total    int                 `json:"total"`
	Findings []jsonFinding       `json:"findings"`
	Spiders  []jsonSpiderFinding `json:"structured_findings,omitempty"`
	Verify   *jsonVerify         `json:"verify,omitempty"`
}

type jsonVerifyHost struct {
	Host    string   `json:"host"`
	Port    int      `json:"port,omitempty"`
	Scheme  string   `json:"scheme,omitempty"`
	Verdict string   `json:"verdict"`
	IPs     []string `json:"ips,omitempty"`
	DNSErr  string   `json:"dns_err,omitempty"`
	TCPOpen bool     `json:"tcp_open,omitempty"`
	TCPErr  string   `json:"tcp_err,omitempty"`
}

type jsonVerifyJWT struct {
	Issuer  string `json:"iss,omitempty"`
	Subject string `json:"sub,omitempty"`
	Kid     string `json:"kid,omitempty"`
	Expired bool   `json:"expired"`
	ExpAt   string `json:"exp_at,omitempty"`
	Reason  string `json:"reason,omitempty"`
}

type jsonVerifyCred struct {
	Pattern string   `json:"pattern"`
	Vendor  string   `json:"vendor,omitempty"`
	Verdict string   `json:"verdict"`
	Account string   `json:"account,omitempty"`
	Scopes  []string `json:"scopes,omitempty"`
	Status  int      `json:"status,omitempty"`
	Reason  string   `json:"reason,omitempty"`
}

type jsonVerify struct {
	Hosts []jsonVerifyHost `json:"hosts,omitempty"`
	JWTs  []jsonVerifyJWT  `json:"jwts,omitempty"`
	Creds []jsonVerifyCred `json:"creds,omitempty"`
}

func emitJSON(w io.Writer, tgt *target, items []enrichedMatch, spFindings []spiders.Finding, rep *verify.Report) error {
	out := jsonOut{File: tgt.displayName, Size: tgt.size, Total: len(items) + len(spFindings)}
	if rep != nil && !rep.Empty() {
		vj := &jsonVerify{}
		for _, st := range rep.Hosts {
			item := jsonVerifyHost{
				Host:    st.Host.Host,
				Port:    st.Host.Port,
				Scheme:  st.Host.Scheme,
				Verdict: string(st.Verdict),
				IPs:     st.IPs,
				DNSErr:  st.DNSErr,
				TCPOpen: st.TCPOpen,
				TCPErr:  st.TCPErr,
			}
			vj.Hosts = append(vj.Hosts, item)
		}
		for _, j := range rep.JWTs {
			item := jsonVerifyJWT{
				Issuer:  j.Issuer,
				Subject: j.Subject,
				Kid:     j.Kid,
				Expired: j.Expired,
				Reason:  j.Reason,
			}
			if !j.ExpAt.IsZero() {
				item.ExpAt = j.ExpAt.Format(time.RFC3339)
			}
			vj.JWTs = append(vj.JWTs, item)
		}
		for _, c := range rep.Creds {
			vj.Creds = append(vj.Creds, jsonVerifyCred{
				Pattern: c.Pattern,
				Vendor:  c.Vendor,
				Verdict: string(c.Verdict),
				Account: c.Account,
				Scopes:  c.Scopes,
				Status:  c.Status,
				Reason:  c.Reason,
			})
		}
		sort.Slice(vj.Hosts, func(i, k int) bool { return vj.Hosts[i].Host < vj.Hosts[k].Host })
		sort.Slice(vj.Creds, func(i, k int) bool { return vj.Creds[i].Vendor < vj.Creds[k].Vendor })
		out.Verify = vj
	}
	for _, em := range items {
		f := jsonFinding{
			Severity: em.m.Pattern.Severity.String(),
			Category: string(em.m.Pattern.Category),
			Pattern:  em.m.Pattern.Name,
			Value:    em.m.Value,
			Offset:   em.m.Offset,
			Count:    em.m.Count,
		}
		if em.dec != nil {
			f.DecodedKind = em.dec.Kind
			f.DecodedText = em.dec.Text
		}
		out.Findings = append(out.Findings, f)
	}
	for _, sf := range spFindings {
		fm := make(map[string]string, len(sf.Fields))
		for _, kv := range sf.Fields {
			fm[kv.Name] = kv.Value
		}
		out.Spiders = append(out.Spiders, jsonSpiderFinding{
			Severity: spiderSevToScanner(sf.Severity).String(),
			Category: sf.Category,
			Spider:   sf.Spider,
			Title:    sf.Title,
			ClassFQN: sf.ClassFQN,
			ObjectID: fmt.Sprintf("0x%x", sf.ObjectID),
			Fields:   fm,
		})
	}
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	return enc.Encode(out)
}

var allSeverities = []scanner.Severity{
	scanner.SeverityCritical,
	scanner.SeverityHigh,
	scanner.SeverityMedium,
	scanner.SeverityLow,
	scanner.SeverityInfo,
}

func emitPretty(w io.Writer, tgt *target, items []enrichedMatch, spFindings []spiders.Finding, elapsed time.Duration, f *scanFlags, diff *diffState, rep *verify.Report) error {
	fmt.Fprint(w, banner(Version, f.noColor))
	fmt.Fprintln(w)

	emitExecSummary(w, tgt, items, spFindings, elapsed, f, rep)

	if rep != nil && !rep.Empty() {
		printVerifySection(w, rep, f)
	}

	total := len(items) + len(spFindings)
	if total == 0 {
		fmt.Fprintln(w, "  No secrets found with current patterns and filters.")
		return nil
	}

	fmt.Fprintln(w, detailedDivider(f.noColor))
	fmt.Fprintln(w)

	labelWidth := 0
	for _, em := range items {
		l := len(em.m.Pattern.Name) + 1
		if l > labelWidth {
			labelWidth = l
		}
	}
	if labelWidth > 36 {
		labelWidth = 36
	}

	emitInterleavedBySeverity(w, items, spFindings, labelWidth, f, diff, rep)

	if diff != nil {
		diff.printGoneSection(w, f.noColor)
	}

	fmt.Fprintln(w)
	return nil
}

// emitInterleavedBySeverity renders regex + structured findings in one
// severity-descending stream (CRITICAL → INFO). Within each bucket:
// structured blocks first (full class context), then regex one-liners.
func emitInterleavedBySeverity(w io.Writer, items []enrichedMatch, spFindings []spiders.Finding, labelWidth int, f *scanFlags, diff *diffState, rep *verify.Report) {
	structBySev := map[scanner.Severity][]spiders.Finding{}
	for _, sf := range spFindings {
		s := spiderSevToScanner(sf.Severity)
		structBySev[s] = append(structBySev[s], sf)
	}
	regexBySev := map[scanner.Severity][]enrichedMatch{}
	for _, em := range items {
		regexBySev[em.m.Pattern.Severity] = append(regexBySev[em.m.Pattern.Severity], em)
	}

	first := true
	for _, sev := range allSeverities {
		st := structBySev[sev]
		rx := regexBySev[sev]
		if len(st) == 0 && len(rx) == 0 {
			continue
		}
		if !first {
			fmt.Fprintln(w)
		}
		first = false
		fmt.Fprintln(w, sectionDivider(sev, f.noColor))
		fmt.Fprintln(w)
		for _, sf := range st {
			printStructured(w, sf, f, diff, rep)
		}
		for _, em := range rx {
			printFinding(w, em, f, labelWidth, diff, rep)
		}
	}
}

func execSummaryDivider(noColor bool) string {
	label := " EXECUTIVE SUMMARY "
	full := 80
	side := (full - len(label)) / 2
	line := strings.Repeat("━", side) + label + strings.Repeat("━", full-side-len(label))
	if noColor {
		return line
	}
	return cBold + cBCyan + line + cReset
}

// emitExecSummary renders the top screenshot-friendly block: target
// meta, severity tally, highlights, and top services at risk.
func emitExecSummary(w io.Writer, tgt *target, items []enrichedMatch, spFindings []spiders.Finding, elapsed time.Duration, f *scanFlags, rep *verify.Report) {
	bySev := map[scanner.Severity]int{}
	for _, em := range items {
		bySev[em.m.Pattern.Severity]++
	}
	for _, sf := range spFindings {
		bySev[spiderSevToScanner(sf.Severity)]++
	}
	total := len(items) + len(spFindings)

	fmt.Fprintln(w, execSummaryDivider(f.noColor))
	fmt.Fprintln(w)

	kind := "target"
	if tgt.isRemote {
		kind = "url   "
	}
	fmt.Fprintln(w, kvLine(kind, tgt.displayName, f.noColor))
	if tgt.header != nil {
		fmt.Fprintln(w, kvLine("format", fmt.Sprintf(
			"HPROF %s · %s · id-size %d",
			tgt.header.Version, humanBytes(tgt.size), tgt.header.IDSize,
		), f.noColor))
		fmt.Fprintln(w, kvLine("dumped", tgt.header.Timestamp.Format("2006-01-02 15:04:05 MST"), f.noColor))
	} else {
		fmt.Fprintln(w, kvLine("size", humanBytes(tgt.size), f.noColor))
	}
	fmt.Fprintln(w, kvLine("scanned", elapsed.Round(time.Millisecond).String(), f.noColor))

	var parts []string
	for _, sev := range allSeverities {
		n := bySev[sev]
		label := fmt.Sprintf("%s %d %s", sevBullet(sev, f.noColor), n, sev)
		if n == 0 && !f.noColor {
			label = cDim + fmt.Sprintf("● %d %s", n, sev) + cReset
		}
		parts = append(parts, label)
	}
	fmt.Fprintln(w, kvLine("findings", fmt.Sprintf("%d total · %s", total, strings.Join(parts, " · ")), f.noColor))

	fmt.Fprintln(w)
	renderHighlights(w, items, spFindings, rep, f)
	renderTopServices(w, spFindings, rep, f)
	fmt.Fprintln(w)
}

// highlight: one severity-ordered row in the Exec Summary risk list.
type highlight struct {
	sev     scanner.Severity
	label   string
	count   int
	example string
}

// renderHighlights prints the per-risk tally, strictly ordered
// CRITICAL → INFO. Colour of each row follows the severity bullet, so
// the rainbow reads top-down red→green→dim.
func renderHighlights(w io.Writer, items []enrichedMatch, spFindings []spiders.Finding, rep *verify.Report, f *scanFlags) {
	dim := dimOnly(!f.noColor)
	reset := resetOnly(!f.noColor)

	// 1. Default / weak creds from both structured findings and regex
	//    basic-auth captures.
	defCount, defEx := 0, ""
	weakCount, weakEx := 0, ""
	for _, sf := range spFindings {
		for _, fl := range sf.Flags {
			switch fl {
			case "default-creds":
				defCount++
				if defEx == "" {
					defEx = shortLabel(sf)
				}
			case "weak":
				weakCount++
				if weakEx == "" {
					weakEx = shortLabel(sf)
				}
			}
		}
	}
	for _, em := range items {
		if em.m.Pattern.Name != "basic-auth" || em.dec == nil {
			continue
		}
		// Use the decoded "user:pass" text, not the base64 capture.
		decoded := em.dec.Text
		switch spiders.ClassifyBasicAuth(decoded) {
		case "default-creds":
			defCount++
			if defEx == "" {
				defEx = decoded
			}
		case "weak":
			weakCount++
			if weakEx == "" {
				weakEx = decoded
			}
		}
	}

	// 2. Private keys exposed — regex patterns.
	privKeys, privKeyEx := 0, ""
	for _, em := range items {
		switch em.m.Pattern.Name {
		case "rsa-private-key", "google-service-account-private-key":
			privKeys++
			if privKeyEx == "" {
				privKeyEx = em.m.Pattern.Name
			}
		}
	}

	// 3. Host & token intel from verify report.
	exp, live, internal, nx := 0, 0, 0, 0
	validCreds, revokedCreds := 0, 0
	var liveEx, internalEx, expEx, nxEx, validEx string

	if rep != nil {
		for _, j := range rep.JWTs {
			if j.Expired {
				exp++
				if expEx == "" && j.Issuer != "" {
					expEx = j.Issuer
				}
			}
		}
		for _, st := range rep.Hosts {
			switch st.Verdict {
			case verify.VerdictLive:
				live++
				if liveEx == "" {
					liveEx = st.Host.Host
				}
			case verify.VerdictPublic:
				if st.TCPChecked && st.TCPOpen {
					live++
					if liveEx == "" {
						liveEx = st.Host.Host
					}
				}
			case verify.VerdictInternal:
				internal++
				if internalEx == "" {
					internalEx = st.Host.Host
				}
			case verify.VerdictNXDomain:
				nx++
				if nxEx == "" {
					nxEx = st.Host.Host
				}
			}
		}
		for _, c := range rep.Creds {
			switch c.Verdict {
			case verify.CredValid:
				validCreds++
				if validEx == "" {
					validEx = strings.TrimSpace(c.Vendor + " " + c.Account)
				}
			case verify.CredRevoked:
				revokedCreds++
			}
		}
		for _, c := range rep.OAuthResults {
			switch c.Verdict {
			case verify.CredValid:
				validCreds++
				if validEx == "" {
					validEx = c.Vendor
				}
			case verify.CredRevoked:
				revokedCreds++
			}
		}
	}

	// Severity mapping: CRITICAL only when actually validated live.
	// Default/weak creds are HIGH (leaked + known-risky). Reachable
	// endpoints are MEDIUM (attack surface), internal is LOW intel,
	// dead things are INFO.
	hl := []highlight{
		{scanner.SeverityCritical, "private keys exposed", privKeys, privKeyEx},
		{scanner.SeverityCritical, "valid live credentials", validCreds, validEx},
		{scanner.SeverityHigh, "default credentials", defCount, defEx},
		{scanner.SeverityHigh, "weak credentials", weakCount, weakEx},
		{scanner.SeverityMedium, "live public endpoints", live, liveEx},
		{scanner.SeverityMedium, "expired tokens", exp, expEx},
		{scanner.SeverityLow, "internal-only endpoints", internal, internalEx},
		{scanner.SeverityInfo, "revoked credentials", revokedCreds, ""},
		{scanner.SeverityInfo, "internal-only names (NXDOMAIN)", nx, nxEx},
	}

	any := false
	for _, h := range hl {
		if h.count == 0 {
			continue
		}
		any = true
		line := fmt.Sprintf("    %s %d %s", sevBullet(h.sev, f.noColor), h.count, h.label)
		if h.example != "" {
			line += "  " + dim + h.example + reset
		}
		fmt.Fprintln(w, line)
	}
	if any {
		fmt.Fprintln(w)
	}
}

// shortLabel turns a Finding into a compact "Title (value)" for
// example-in-highlight rendering.
func shortLabel(sf spiders.Finding) string {
	u, p := pickUserPass(sf.Fields)
	short := sf.Title
	if i := strings.Index(short, ": "); i >= 0 {
		short = short[i+2:]
	}
	if u != "" && p != "" {
		return fmt.Sprintf("%s/%s @ %s", u, p, short)
	}
	return short
}

// pickUserPass mirrors spiders.pickUserPass but is internal to the CLI
// so we don't force a new public function in the spiders package.
func pickUserPass(fields []spiders.Field) (user, pass string) {
	for _, f := range fields {
		n := strings.ToLower(f.Name)
		if pass == "" && strings.Contains(n, "password") {
			pass = f.Value
		}
		if user == "" && (strings.HasSuffix(n, "username") || n == "username" ||
			strings.HasSuffix(n, "login") || n == "login" ||
			n == "user" || strings.HasSuffix(n, "user")) {
			user = f.Value
		}
	}
	return
}

// renderTopServices lists up to 5 structured findings ranked by severity,
// flag badges, and host-reachability to give the operator a TL;DR.
func renderTopServices(w io.Writer, spFindings []spiders.Finding, rep *verify.Report, f *scanFlags) {
	if len(spFindings) == 0 {
		return
	}
	dim := dimOnly(!f.noColor)
	reset := resetOnly(!f.noColor)

	type row struct {
		sf   spiders.Finding
		rank int
		note string
	}
	var rows []row
	for _, sf := range spFindings {
		r := row{sf: sf, rank: int(sf.Severity) * 10}
		for _, fl := range sf.Flags {
			switch fl {
			case "default-creds":
				r.rank += 7
				r.note = "default creds"
			case "weak":
				r.rank += 3
				if r.note == "" {
					r.note = "weak password"
				}
			}
		}
		if rep != nil {
			for _, kv := range sf.Fields {
				if st := rep.HostByValue(kv.Value); st != nil {
					switch st.Verdict {
					case verify.VerdictLive:
						r.rank += 5
						if r.note == "" {
							r.note = "live @ " + st.Host.Host
						}
					case verify.VerdictPublic:
						r.rank += 3
						if r.note == "" {
							r.note = "public @ " + st.Host.Host
						}
					case verify.VerdictInternal:
						r.rank += 1
					}
				}
			}
			for _, c := range rep.OAuthResults {
				if c == nil {
					continue
				}
				for _, kv := range sf.Fields {
					if kv.Value == c.Value && c.Verdict == verify.CredValid {
						r.rank += 8
						r.note = "OAuth2 VALID"
					}
				}
			}
		}
		rows = append(rows, r)
	}
	sort.Slice(rows, func(i, j int) bool {
		if rows[i].rank != rows[j].rank {
			return rows[i].rank > rows[j].rank
		}
		return rows[i].sf.Title < rows[j].sf.Title
	})
	limit := 5
	if len(rows) < limit {
		limit = len(rows)
	}
	if limit == 0 {
		return
	}
	fmt.Fprintf(w, "  %stop services at risk:%s\n", dim, reset)
	for _, r := range rows[:limit] {
		line := fmt.Sprintf("    • %s", r.sf.Title)
		if r.note != "" {
			line += "   " + dim + r.note + reset
		}
		fmt.Fprintln(w, line)
	}
}

func detailedDivider(noColor bool) string {
	label := " DETAILED FINDINGS "
	full := 80
	side := (full - len(label)) / 2
	line := strings.Repeat("━", side) + label + strings.Repeat("━", full-side-len(label))
	if noColor {
		return line
	}
	return cBold + cBCyan + line + cReset
}

func structuredDivider(noColor bool) string {
	label := " STRUCTURED (class-aware) "
	full := 80
	side := (full - len(label)) / 2
	line := strings.Repeat("━", side) + label + strings.Repeat("━", full-side-len(label))
	if noColor {
		return line
	}
	return cBold + cBCyan + line + cReset
}

func verifyDivider(noColor bool) string {
	label := " VERIFICATION (live status) "
	full := 80
	side := (full - len(label)) / 2
	line := strings.Repeat("━", side) + label + strings.Repeat("━", full-side-len(label))
	if noColor {
		return line
	}
	return cBold + cBCyan + line + cReset
}

func verdictBadge(v verify.HostVerdict, noColor bool) string {
	label := string(v)
	if noColor {
		return "[" + label + "]"
	}
	var color string
	switch v {
	case verify.VerdictLive:
		color = cBGreen
	case verify.VerdictPublic:
		color = cBCyan
	case verify.VerdictInternal:
		color = cYellow
	case verify.VerdictNXDomain:
		color = cBRed
	case verify.VerdictDNSErr:
		color = cRed
	default:
		color = cDim
	}
	return color + "[" + label + "]" + cReset
}

// annotateHost returns the inline suffix for a verified host.
func annotateHost(st *verify.HostStatus, noColor bool) string {
	if st == nil {
		return ""
	}
	dim := dimOnly(!noColor)
	reset := resetOnly(!noColor)
	var parts []string
	parts = append(parts, verdictBadge(st.Verdict, noColor))
	if len(st.IPs) > 0 {
		ips := st.IPs
		if len(ips) > 2 {
			ips = ips[:2]
		}
		parts = append(parts, strings.Join(ips, ","))
	}
	if st.Host.Port > 0 && st.TCPChecked {
		status := "open"
		if !st.TCPOpen {
			status = st.TCPErr
			if status == "" {
				status = "closed"
			}
		}
		parts = append(parts, fmt.Sprintf("tcp:%d %s", st.Host.Port, status))
	}
	if st.DNSErr != "" && len(st.IPs) == 0 {
		parts = append(parts, "("+st.DNSErr+")")
	}
	return "  " + dim + "→" + reset + " " + strings.Join(parts, " ")
}

func annotateJWT(st *verify.JWTStatus, noColor bool) string {
	if st == nil {
		return ""
	}
	dim := dimOnly(!noColor)
	reset := resetOnly(!noColor)
	var badge string
	switch {
	case st.Reason == "malformed":
		badge = cRed + "[MALFORMED]" + cReset
	case st.Expired:
		ago := time.Since(st.ExpAt).Round(time.Minute)
		badge = cBRed + "[EXPIRED " + humanDuration(ago) + " ago]" + cReset
	case !st.ExpAt.IsZero():
		ttl := time.Until(st.ExpAt).Round(time.Minute)
		badge = cBGreen + "[VALID, " + humanDuration(ttl) + " left]" + cReset
	default:
		badge = cBGreen + "[VALID (no exp)]" + cReset
	}
	if noColor {
		badge = strings.ReplaceAll(badge, cBRed, "")
		badge = strings.ReplaceAll(badge, cBGreen, "")
		badge = strings.ReplaceAll(badge, cRed, "")
		badge = strings.ReplaceAll(badge, cReset, "")
	}
	return "  " + dim + "→" + reset + " " + badge
}

func humanDuration(d time.Duration) string {
	if d < 0 {
		d = -d
	}
	switch {
	case d < time.Minute:
		return fmt.Sprintf("%ds", int(d.Seconds()))
	case d < time.Hour:
		return fmt.Sprintf("%dm", int(d.Minutes()))
	case d < 24*time.Hour:
		return fmt.Sprintf("%dh%dm", int(d.Hours()), int(d.Minutes())%60)
	case d < 7*24*time.Hour:
		return fmt.Sprintf("%dd", int(d.Hours()/24))
	}
	return fmt.Sprintf("%dd", int(d.Hours()/24))
}

// printVerifySection renders the summary table at the end of the run.
func printVerifySection(w io.Writer, rep *verify.Report, f *scanFlags) {
	if rep == nil || rep.Empty() {
		return
	}
	dim := dimOnly(!f.noColor)
	reset := resetOnly(!f.noColor)

	fmt.Fprintln(w)
	fmt.Fprintln(w, verifyDivider(f.noColor))
	fmt.Fprintln(w)

	hosts := make([]*verify.HostStatus, 0, len(rep.Hosts))
	for _, st := range rep.Hosts {
		hosts = append(hosts, st)
	}
	// Sort by verdict severity (LIVE/PUBLIC first, NXDOMAIN last), then host.
	verdictRank := map[verify.HostVerdict]int{
		verify.VerdictLive: 0, verify.VerdictPublic: 1,
		verify.VerdictInternal: 2, verify.VerdictNXDomain: 3,
		verify.VerdictDNSErr: 4, verify.VerdictUnknown: 5,
	}
	sort.Slice(hosts, func(i, j int) bool {
		if verdictRank[hosts[i].Verdict] != verdictRank[hosts[j].Verdict] {
			return verdictRank[hosts[i].Verdict] < verdictRank[hosts[j].Verdict]
		}
		return hosts[i].Host.Host < hosts[j].Host.Host
	})

	// Tally by verdict.
	tally := map[verify.HostVerdict]int{}
	for _, st := range hosts {
		tally[st.Verdict]++
	}
	if len(hosts) > 0 {
		fmt.Fprintf(w, "  %shosts%s  %d total   %sLIVE %d · PUBLIC %d · INTERNAL %d · NXDOMAIN %d · DNS-ERR %d%s\n",
			dim, reset, len(hosts), dim,
			tally[verify.VerdictLive], tally[verify.VerdictPublic], tally[verify.VerdictInternal],
			tally[verify.VerdictNXDomain], tally[verify.VerdictDNSErr], reset)
		fmt.Fprintln(w)
	}

	// Column widths for host display.
	maxEndpoint := 0
	for _, st := range hosts {
		ep := st.Host.Host
		if st.Host.Port > 0 {
			ep += ":" + fmt.Sprintf("%d", st.Host.Port)
		}
		if len(ep) > maxEndpoint {
			maxEndpoint = len(ep)
		}
	}
	if maxEndpoint > 48 {
		maxEndpoint = 48
	}

	for _, st := range hosts {
		ep := st.Host.Host
		if st.Host.Port > 0 {
			ep = fmt.Sprintf("%s:%d", st.Host.Host, st.Host.Port)
		}
		line := fmt.Sprintf("  %s %-*s", verdictBadge(st.Verdict, f.noColor), maxEndpoint, ep)
		var trail []string
		if len(st.IPs) > 0 {
			trail = append(trail, strings.Join(st.IPs, ","))
		}
		if st.Host.Port > 0 && st.TCPChecked {
			status := "open"
			if !st.TCPOpen {
				status = st.TCPErr
				if status == "" {
					status = "closed"
				}
			}
			trail = append(trail, fmt.Sprintf("tcp %s", status))
		}
		if st.DNSErr != "" && len(st.IPs) == 0 {
			trail = append(trail, "("+st.DNSErr+")")
		}
		if len(trail) > 0 {
			line += "   " + dim + strings.Join(trail, "  ") + reset
		}
		fmt.Fprintln(w, line)
	}

	if len(rep.Subdomains) > 0 {
		fmt.Fprintln(w)
		subs := make([]*verify.HostStatus, 0, len(rep.Subdomains))
		for _, st := range rep.Subdomains {
			subs = append(subs, st)
		}
		verdictRank := map[verify.HostVerdict]int{
			verify.VerdictLive: 0, verify.VerdictPublic: 1,
			verify.VerdictInternal: 2, verify.VerdictNXDomain: 3,
			verify.VerdictDNSErr: 4, verify.VerdictUnknown: 5,
		}
		sort.Slice(subs, func(i, j int) bool {
			if verdictRank[subs[i].Verdict] != verdictRank[subs[j].Verdict] {
				return verdictRank[subs[i].Verdict] < verdictRank[subs[j].Verdict]
			}
			return subs[i].Host.Host < subs[j].Host.Host
		})
		tally := map[verify.HostVerdict]int{}
		for _, st := range subs {
			tally[st.Verdict]++
		}
		fmt.Fprintf(w, "  %ssubdomains%s  %d total   %sPUBLIC %d · INTERNAL %d · NXDOMAIN %d · DNS-ERR %d%s\n",
			dim, reset, len(subs), dim,
			tally[verify.VerdictPublic]+tally[verify.VerdictLive],
			tally[verify.VerdictInternal],
			tally[verify.VerdictNXDomain],
			tally[verify.VerdictDNSErr], reset)
		fmt.Fprintln(w)
		maxHost := 0
		for _, st := range subs {
			if len(st.Host.Host) > maxHost {
				maxHost = len(st.Host.Host)
			}
		}
		if maxHost > 60 {
			maxHost = 60
		}
		for _, st := range subs {
			line := fmt.Sprintf("  %s %-*s", verdictBadge(st.Verdict, f.noColor), maxHost, st.Host.Host)
			switch {
			case len(st.IPs) > 0:
				line += "   " + dim + strings.Join(st.IPs, ",") + reset
			case st.DNSErr != "":
				line += "   " + dim + "(" + st.DNSErr + ")" + reset
			}
			fmt.Fprintln(w, line)
		}
	}

	if len(rep.JWTs) > 0 {
		fmt.Fprintln(w)
		var valid []*verify.JWTStatus
		expired, malformed := 0, 0
		for _, j := range rep.JWTs {
			switch {
			case j.Reason == "malformed":
				malformed++
			case j.Expired:
				expired++
			default:
				valid = append(valid, j)
			}
		}
		sort.Slice(valid, func(i, j int) bool { return valid[i].Issuer < valid[j].Issuer })
		fmt.Fprintf(w, "  %sjwts%s  %d total   %sVALID %d · EXPIRED %d · MALFORMED %d%s\n",
			dim, reset, len(rep.JWTs), dim, len(valid), expired, malformed, reset)
		if len(valid) > 0 {
			fmt.Fprintln(w)
			for _, j := range valid {
				iss := j.Issuer
				if iss == "" {
					iss = "(no iss)"
				}
				fmt.Fprintf(w, "  %s %s\n", strings.TrimSpace(annotateJWT(j, f.noColor)), iss)
				if j.Subject != "" {
					fmt.Fprintf(w, "      %ssub%s %s\n", dim, reset, j.Subject)
				}
			}
		}
	}

	if len(rep.Creds) > 0 {
		fmt.Fprintln(w)
		list := make([]*verify.CredResult, 0, len(rep.Creds))
		for _, c := range rep.Creds {
			list = append(list, c)
		}
		credRank := map[verify.CredVerdict]int{
			verify.CredValid: 0, verify.CredRateLimited: 1,
			verify.CredError: 2, verify.CredUnknown: 3, verify.CredRevoked: 4,
		}
		sort.Slice(list, func(i, j int) bool {
			if credRank[list[i].Verdict] != credRank[list[j].Verdict] {
				return credRank[list[i].Verdict] < credRank[list[j].Verdict]
			}
			return list[i].Vendor < list[j].Vendor
		})
		tally := map[verify.CredVerdict]int{}
		for _, c := range list {
			tally[c.Verdict]++
		}
		fmt.Fprintf(w, "  %screds%s  %d total   %sVALID %d · REVOKED %d · RATE-LIMITED %d · ERROR %d%s\n",
			dim, reset, len(list), dim,
			tally[verify.CredValid], tally[verify.CredRevoked],
			tally[verify.CredRateLimited], tally[verify.CredError], reset)
		fmt.Fprintln(w)
		for _, c := range list {
			line := strings.TrimSpace(annotateCred(c, f.noColor))
			fmt.Fprintln(w, "  "+line)
			if len(c.Scopes) > 0 {
				fmt.Fprintf(w, "      %sscopes%s %s\n", dim, reset, strings.Join(c.Scopes, ", "))
			}
		}
	}
	fmt.Fprintln(w)
}

// printStructured renders one spider finding with optional verify badges.
func printStructured(w io.Writer, sf spiders.Finding, f *scanFlags, diff *diffState, rep *verify.Report) {
	sev := spiderSevToScanner(sf.Severity)
	open, close := sevStyle(sev, f.noColor)
	bold := ""
	reset := ""
	if !f.noColor {
		bold = cBold
		reset = cReset
	}
	marker := ""
	if diff != nil && diff.enabled {
		marker = formatDiffMarker(diff.markStruct(sf.Spider, sf.ClassFQN, sf.ObjectID), f.noColor) + " "
	}
	flagBadge := ""
	for _, fl := range sf.Flags {
		switch fl {
		case "default-creds":
			if f.noColor {
				flagBadge += " [DEFAULT CREDS]"
			} else {
				flagBadge += " " + cBRed + "[DEFAULT CREDS]" + cReset
			}
		case "weak":
			if f.noColor {
				flagBadge += " [WEAK]"
			} else {
				flagBadge += " " + cYellow + "[WEAK]" + cReset
			}
		}
	}
	fmt.Fprintf(w, "  %s%s[%s]%s %s%s%s%s\n",
		marker, open, sev, close, bold, sf.Title, reset, flagBadge)
	fmt.Fprintf(w, "      %sclass:%s %s   %sobject:%s 0x%x\n",
		dimOnly(!f.noColor), resetOnly(!f.noColor), sf.ClassFQN,
		dimOnly(!f.noColor), resetOnly(!f.noColor), sf.ObjectID)
	for _, kv := range sf.Fields {
		val := kv.Value
		annot := verifyAnnotation(kv.Value, rep, f.noColor)
		if f.mask && looksSensitive(kv.Name) {
			val = maskSecret(val, 2, 2)
		}
		if f.verbose && strings.ContainsAny(val, "\n\r") {
			fmt.Fprintf(w, "      %s%-22s%s%s\n",
				dimOnly(!f.noColor), kv.Name, resetOnly(!f.noColor), annot)
			writeIndentedBlock(w, "          ", val)
			continue
		}
		val = oneLine(val, truncLen(f, false))
		fmt.Fprintf(w, "      %s%-22s%s  %s%s\n",
			dimOnly(!f.noColor), kv.Name, resetOnly(!f.noColor), val, annot)
	}
	fmt.Fprintln(w)
}

// verifyAnnotation: inline suffix from rep (cred / OAuth / JWT / host).
func verifyAnnotation(value string, rep *verify.Report, noColor bool) string {
	if rep == nil {
		return ""
	}
	if c := rep.CredByValue(value); c != nil {
		return annotateCred(c, noColor)
	}
	if c := rep.OAuthByClientID(value); c != nil {
		return annotateCred(c, noColor)
	}
	if j := rep.JWTByValue(value); j != nil {
		return annotateJWT(j, noColor)
	}
	if st := rep.HostByValue(value); st != nil {
		return annotateHost(st, noColor)
	}
	return ""
}

func annotateCred(c *verify.CredResult, noColor bool) string {
	if c == nil {
		return ""
	}
	dim := dimOnly(!noColor)
	reset := resetOnly(!noColor)
	label := string(c.Verdict)
	var color string
	switch c.Verdict {
	case verify.CredValid:
		color = cBGreen
	case verify.CredRevoked:
		color = cBRed
	case verify.CredRateLimited:
		color = cYellow
	case verify.CredError:
		color = cRed
	default:
		color = cDim
	}
	badge := "[" + label + "]"
	if !noColor {
		badge = color + badge + cReset
	}
	parts := []string{badge}
	if c.Vendor != "" {
		parts = append(parts, dim+c.Vendor+reset)
	}
	if c.Account != "" {
		parts = append(parts, c.Account)
	}
	if c.Reason != "" && c.Verdict != verify.CredValid {
		parts = append(parts, dim+"("+c.Reason+")"+reset)
	}
	return "  " + dim + "→" + reset + " " + strings.Join(parts, " ")
}

// looksSensitive decides which structured-field names get masked under --mask.
// Keep non-credential fields (url, driverClassName) in plain text.
func looksSensitive(name string) bool {
	n := strings.ToLower(name)
	return strings.Contains(n, "password") ||
		strings.Contains(n, "secret") ||
		strings.Contains(n, "key") ||
		strings.Contains(n, "token")
}

func printFinding(w io.Writer, em enrichedMatch, f *scanFlags, labelWidth int, diff *diffState, rep *verify.Report) {
	label := em.m.Pattern.Name + ":"
	padding := labelWidth - len(label)
	if padding < 1 {
		padding = 1
	}

	marker := ""
	if diff != nil && diff.enabled {
		m := diff.markRegex(em.m.Pattern.Name, em.m.Value)
		marker = formatDiffMarker(m, f.noColor)
	}

	// Decoded form is the primary display; raw shows in verbose. --mask
	// masks both.
	hasDecoded := em.dec != nil
	var primary string
	switch {
	case f.mask && hasDecoded:
		primary = maskDecoded(em.dec.Kind, em.dec.Text)
	case f.mask:
		primary = maskForPattern(em.m.Pattern.Name, em.m.Value)
	case hasDecoded:
		primary = em.dec.Text
	default:
		primary = em.m.Value
	}
	multiline := f.verbose && strings.ContainsAny(primary, "\n\r")
	if !multiline {
		primary = oneLine(primary, truncLen(f, hasDecoded && !f.mask))
	}

	sevOpen, sevClose := sevStyle(em.m.Pattern.Severity, f.noColor)
	if multiline {
		fmt.Fprintf(w, "  %s%s%s%s\n", marker, sevOpen, label, sevClose)
		writeIndentedBlock(w, "  ", primary)
	} else {
		fmt.Fprintf(w, "  %s%s%s%s%s  %s", marker, sevOpen, label, sevClose, strings.Repeat(" ", padding), primary)
		if em.m.Count > 1 {
			fmt.Fprintf(w, " %s(x%d)%s", dimOnly(!f.noColor), em.m.Count, resetOnly(!f.noColor))
		}
		if annot := verifyAnnotation(em.m.Value, rep, f.noColor); annot != "" {
			fmt.Fprint(w, annot)
		}
		if f.verbose {
			fmt.Fprintf(w, "   %s@ 0x%x%s", dimOnly(!f.noColor), em.m.Offset, resetOnly(!f.noColor))
		}
		fmt.Fprintln(w)
	}

	if hasDecoded && f.verbose && !multiline {
		var raw string
		if f.mask {
			raw = maskForPattern(em.m.Pattern.Name, em.m.Value)
		} else {
			raw = em.m.Value
		}
		rawMulti := strings.ContainsAny(raw, "\n\r")
		indent := strings.Repeat(" ", labelWidth+2)
		if rawMulti {
			fmt.Fprintf(w, "  %s%sraw:%s\n", indent, dimOnly(!f.noColor), resetOnly(!f.noColor))
			writeIndentedBlock(w, "  "+indent+"  ", raw)
		} else {
			raw = oneLine(raw, truncLen(f, false))
			fmt.Fprintf(w, "  %s%sraw: %s%s\n", indent, dimOnly(!f.noColor), raw, resetOnly(!f.noColor))
		}
	}
}

// writeIndentedBlock prints each line of value prefixed with indent.
// Used to render multi-line secrets (PEM blocks) without collapsing.
func writeIndentedBlock(w io.Writer, indent, value string) {
	value = strings.ReplaceAll(value, "\r\n", "\n")
	for _, line := range strings.Split(value, "\n") {
		fmt.Fprintln(w, indent+line)
	}
}

// truncLen returns the display budget. --verbose disables truncation
// entirely so full RSA keys, long JWTs, multi-line PEM blocks reach
// the operator unchopped.
func truncLen(f *scanFlags, decoded bool) int {
	if f.verbose {
		return 1 << 30
	}
	base := maxValueChars
	if decoded {
		base *= 3
	}
	return base
}

func oneLine(s string, max int) string {
	s = strings.ReplaceAll(s, "\n", " ")
	s = strings.ReplaceAll(s, "\r", " ")
	s = strings.ReplaceAll(s, "\t", " ")
	if max > 0 && len(s) > max {
		return s[:max] + "..."
	}
	return s
}

func dimOnly(on bool) string {
	if on {
		return cDim
	}
	return ""
}

func resetOnly(on bool) string {
	if on {
		return cReset
	}
	return ""
}
