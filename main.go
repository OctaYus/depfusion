// depfusion — dependency-confusion candidate finder (Go, stdlib only).
//
// Pulls JS / sourcemap URLs in memory, extracts npm package references,
// filters node builtins / invalid names / path aliases, and queries the
// npm registry to classify each name as registered / claimable / unknown.
//
// Results are STREAMED to disk as they are produced, so an interrupted run
// (Ctrl-C / kill / crash) still leaves complete partial output:
//
//	<out>/claimable.txt    name<TAB>source-url   — submission candidates (clean 404)
//	<out>/registered.txt   name<TAB>source-url   — exists on npm
//	<out>/unknown.txt      name<TAB>source-url   — check failed, verify manually
//	<out>/results.jsonl    one JSON object per URL
//	<out>/scope_report.txt per-scope tally (rewritten periodically + at end)
//	<out>/summary.md       human-readable run summary
//	<out>/run_info.json    config + final stats (machine-readable)
//
// Build:  go install github.com/OctaYus/depfusion@latest
// Run:    depfusion -f urls.txt -o out -workers 40
package main

import (
	"bufio"
	"crypto/tls"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"
)

const version = "1.1.0"

// ---------------------------------------------------------------------------
// Filters
// ---------------------------------------------------------------------------

var nodeBuiltins = map[string]bool{
	"assert": true, "async_hooks": true, "buffer": true, "child_process": true,
	"cluster": true, "console": true, "constants": true, "crypto": true,
	"dgram": true, "diagnostics_channel": true, "dns": true, "domain": true,
	"events": true, "fs": true, "http": true, "http2": true, "https": true,
	"inspector": true, "module": true, "net": true, "os": true, "path": true,
	"perf_hooks": true, "process": true, "punycode": true, "querystring": true,
	"readline": true, "repl": true, "stream": true, "string_decoder": true,
	"sys": true, "timers": true, "tls": true, "trace_events": true, "tty": true,
	"url": true, "util": true, "v8": true, "vm": true, "wasi": true,
	"worker_threads": true, "zlib": true,
}

const npmNameMaxLen = 214

var (
	npmNameRe = regexp.MustCompile(`^(?:@[a-z0-9][a-z0-9._-]*/)?[a-z0-9][a-z0-9._-]*$`)

	jsPatterns = []*regexp.Regexp{
		regexp.MustCompile(`require\s*\(\s*['"]([^'"]+)['"]`),
		regexp.MustCompile(`require\.resolve\s*\(\s*['"]([^'"]+)['"]`),
		regexp.MustCompile(`import\s+(?:type\s+)?(?:[\w*\s{},$]+\s+from\s+)?['"]([^'"]+)['"]`),
		regexp.MustCompile(`import\s*\(\s*['"]([^'"]+)['"]`),
		regexp.MustCompile(`export\s+(?:\*|\{[^}]*\}|\w+)\s+from\s+['"]([^'"]+)['"]`),
	}
	nodeModulesRe   = regexp.MustCompile(`node_modules[\\/](@[^\\/'"\s]+[\\/][^\\/'"\s]+|[^\\/'"\s][^\\/'"\s]*)`)
	inlineSourceMap = regexp.MustCompile(`//[#@]\s*sourceMappingURL=([^\s'"]+)`)
)

func stripNodePrefix(s string) string {
	return strings.TrimPrefix(s, "node:")
}

// rootPackage reduces a specifier to its installable root, or "" if not a pkg.
func rootPackage(spec string) string {
	spec = stripNodePrefix(spec)
	if spec == "" {
		return ""
	}
	if c := spec[0]; c == '.' || c == '/' || c == '\\' {
		return ""
	}
	if strings.Contains(spec, "://") {
		return ""
	}
	if strings.HasPrefix(spec, "@") {
		parts := strings.Split(spec, "/")
		if len(parts) < 2 || parts[1] == "" {
			return ""
		}
		return parts[0] + "/" + parts[1]
	}
	return strings.Split(spec, "/")[0]
}

func isValidNpmName(name string) bool {
	if name == "" || len(name) > npmNameMaxLen {
		return false
	}
	if nodeBuiltins[name] {
		return false
	}
	return npmNameRe.MatchString(name)
}

// ---------------------------------------------------------------------------
// Extraction
// ---------------------------------------------------------------------------

func extractFromJS(content string) map[string]struct{} {
	out := make(map[string]struct{})
	for _, pat := range jsPatterns {
		for _, m := range pat.FindAllStringSubmatch(content, -1) {
			if r := rootPackage(m[1]); r != "" {
				out[r] = struct{}{}
			}
		}
	}
	for _, m := range nodeModulesRe.FindAllStringSubmatch(content, -1) {
		if r := rootPackage(strings.ReplaceAll(m[1], `\`, "/")); r != "" {
			out[r] = struct{}{}
		}
	}
	return out
}

type sourceMap struct {
	Sources []string `json:"sources"`
}

func extractFromSourceMap(content string) map[string]struct{} {
	var sm sourceMap
	if err := json.Unmarshal([]byte(content), &sm); err != nil {
		return extractFromJS(content) // wrong content-type fallback
	}
	out := make(map[string]struct{})
	for _, src := range sm.Sources {
		s := strings.ReplaceAll(src, `\`, "/")
		if m := nodeModulesRe.FindStringSubmatch(s); m != nil {
			if r := rootPackage(m[1]); r != "" {
				out[r] = struct{}{}
			}
		}
	}
	return out
}

func looksLikeSourceMap(url, content string) bool {
	if strings.HasSuffix(url, ".map") {
		return true
	}
	t := strings.TrimSpace(content)
	if len(t) == 0 || t[0] != '{' {
		return false
	}
	head := content
	if len(head) > 4096 {
		head = head[:4096]
	}
	return strings.Contains(head, `"sources"`)
}

// ---------------------------------------------------------------------------
// Registry
// ---------------------------------------------------------------------------

const (
	stRegistered = "registered"
	stClaimable  = "claimable"
	stUnknown    = "unknown"
	stInvalid    = "invalid"
)

type registry struct {
	client  *http.Client
	retries int
	backoff time.Duration
	mu      sync.Mutex
	cache   map[string]string
}

func newRegistry(client *http.Client) *registry {
	return &registry{
		client:  client,
		retries: 2,
		backoff: 400 * time.Millisecond,
		cache:   make(map[string]string),
	}
}

func (r *registry) check(name string) string {
	r.mu.Lock()
	if v, ok := r.cache[name]; ok {
		r.mu.Unlock()
		return v
	}
	r.mu.Unlock()

	var result string
	if !isValidNpmName(name) {
		result = stInvalid
	} else {
		result = r.query(name)
	}

	r.mu.Lock()
	r.cache[name] = result
	r.mu.Unlock()
	return result
}

func (r *registry) query(name string) string {
	url := "https://registry.npmjs.org/" + name
	for attempt := 0; attempt <= r.retries; attempt++ {
		req, _ := http.NewRequest("GET", url, nil)
		req.Header.Set("User-Agent", "depfusion/"+version+" (+security-research)")
		resp, err := r.client.Do(req)
		if err != nil {
			time.Sleep(r.backoff << attempt)
			continue
		}
		io.Copy(io.Discard, resp.Body)
		resp.Body.Close()
		switch {
		case resp.StatusCode == 200:
			return stRegistered
		case resp.StatusCode == 404:
			return stClaimable
		case resp.StatusCode == 429 || resp.StatusCode >= 500:
			time.Sleep(r.backoff << attempt)
			continue
		default:
			return stUnknown
		}
	}
	return stUnknown
}

// ---------------------------------------------------------------------------
// Pretty printer (ANSI colors, TTY-aware)
// ---------------------------------------------------------------------------

type ui struct {
	w     io.Writer
	color bool
}

var theUI = &ui{w: os.Stderr, color: false}

func detectColor(force, disable bool) bool {
	if disable || os.Getenv("NO_COLOR") != "" {
		return false
	}
	if force {
		return true
	}
	fi, err := os.Stderr.Stat()
	if err != nil {
		return false
	}
	return (fi.Mode() & os.ModeCharDevice) != 0
}

const (
	cReset  = "\x1b[0m"
	cBold   = "\x1b[1m"
	cDim    = "\x1b[2m"
	cRed    = "\x1b[31m"
	cGreen  = "\x1b[32m"
	cYellow = "\x1b[33m"
	cBlue   = "\x1b[34m"
	cCyan   = "\x1b[36m"
	cGray   = "\x1b[90m"
)

func (u *ui) c(code, s string) string {
	if !u.color {
		return s
	}
	return code + s + cReset
}

func (u *ui) bold(s string) string   { return u.c(cBold, s) }
func (u *ui) dim(s string) string    { return u.c(cDim, s) }
func (u *ui) red(s string) string    { return u.c(cRed, s) }
func (u *ui) green(s string) string  { return u.c(cGreen, s) }
func (u *ui) yellow(s string) string { return u.c(cYellow, s) }
func (u *ui) cyan(s string) string   { return u.c(cCyan, s) }
func (u *ui) gray(s string) string   { return u.c(cGray, s) }

func (u *ui) printf(format string, a ...any) {
	fmt.Fprintf(u.w, format, a...)
}

func (u *ui) section(title string) {
	u.printf("\n%s\n", u.bold(u.cyan(title)))
}

func (u *ui) kv(k string, v any) {
	u.printf("  %s %v\n", u.gray(padRight(k, 18)), v)
}

func padRight(s string, n int) string {
	if len(s) >= n {
		return s
	}
	return s + strings.Repeat(" ", n-len(s))
}

func padLeft(s string, n int) string {
	if len(s) >= n {
		return s
	}
	return strings.Repeat(" ", n-len(s)) + s
}

func humanDuration(d time.Duration) string {
	if d < time.Second {
		return fmt.Sprintf("%dms", d.Milliseconds())
	}
	d = d.Round(time.Second)
	h := int(d / time.Hour)
	d -= time.Duration(h) * time.Hour
	m := int(d / time.Minute)
	d -= time.Duration(m) * time.Minute
	s := int(d / time.Second)
	switch {
	case h > 0:
		return fmt.Sprintf("%dh%02dm%02ds", h, m, s)
	case m > 0:
		return fmt.Sprintf("%dm%02ds", m, s)
	default:
		return fmt.Sprintf("%ds", s)
	}
}

func humanNum(n uint64) string {
	s := fmt.Sprintf("%d", n)
	if len(s) <= 3 {
		return s
	}
	var b strings.Builder
	pre := len(s) % 3
	if pre > 0 {
		b.WriteString(s[:pre])
		if len(s) > pre {
			b.WriteByte(',')
		}
	}
	for i := pre; i < len(s); i += 3 {
		b.WriteString(s[i : i+3])
		if i+3 < len(s) {
			b.WriteByte(',')
		}
	}
	return b.String()
}

func pct(n, total uint64) string {
	if total == 0 {
		return "  0.0%"
	}
	return fmt.Sprintf("%5.1f%%", float64(n)*100/float64(total))
}

func (u *ui) banner() {
	box := []string{
		"╭──────────────────────────────────────────────────╮",
		"│  " + u.bold("depfusion") + "  v" + version + "  ·  dependency-confusion finder  │",
		"│  " + u.dim("github.com/OctaYus/depfusion") + "                      │",
		"╰──────────────────────────────────────────────────╯",
	}
	for _, line := range box {
		u.printf("%s\n", line)
	}
}

// ---------------------------------------------------------------------------
// Streaming output sink
// ---------------------------------------------------------------------------

type sink struct {
	mu         sync.Mutex
	claimable  *bufio.Writer
	registered *bufio.Writer
	unknown    *bufio.Writer
	jsonl      *bufio.Writer
	files      []*os.File

	scopeMu sync.Mutex
	scope   map[string]map[string]int // scope -> {registered,claimable}
	outDir  string

	writes uint64

	// counters for the final summary
	regCount     uint64
	claimCount   uint64
	unknownCount uint64
	invalidCount uint64
}

func newSink(outDir string) (*sink, error) {
	if err := os.MkdirAll(outDir, 0o755); err != nil {
		return nil, err
	}
	open := func(name string) (*bufio.Writer, *os.File, error) {
		f, err := os.Create(filepath.Join(outDir, name))
		if err != nil {
			return nil, nil, err
		}
		return bufio.NewWriterSize(f, 64*1024), f, nil
	}
	s := &sink{scope: make(map[string]map[string]int), outDir: outDir}
	for _, spec := range []struct {
		name string
		dst  **bufio.Writer
	}{
		{"claimable.txt", &s.claimable},
		{"registered.txt", &s.registered},
		{"unknown.txt", &s.unknown},
		{"results.jsonl", &s.jsonl},
	} {
		w, f, err := open(spec.name)
		if err != nil {
			return nil, err
		}
		*spec.dst = w
		s.files = append(s.files, f)
	}
	return s, nil
}

func (s *sink) recordScope(name, cat string) {
	if !strings.HasPrefix(name, "@") {
		return
	}
	scope := strings.SplitN(name, "/", 2)[0]
	s.scopeMu.Lock()
	if s.scope[scope] == nil {
		s.scope[scope] = map[string]int{}
	}
	s.scope[scope][cat]++
	s.scopeMu.Unlock()
}

type urlResult struct {
	URL        string   `json:"url"`
	Registered []string `json:"registered"`
	Claimable  []string `json:"claimable"`
	Unknown    []string `json:"unknown"`
	Invalid    []string `json:"invalid_skipped"`
	Error      string   `json:"error,omitempty"`
}

func (s *sink) write(r urlResult) {
	s.mu.Lock()
	for _, n := range r.Claimable {
		fmt.Fprintf(s.claimable, "%s\t%s\n", n, r.URL)
	}
	for _, n := range r.Registered {
		fmt.Fprintf(s.registered, "%s\t%s\n", n, r.URL)
	}
	for _, n := range r.Unknown {
		fmt.Fprintf(s.unknown, "%s\t%s\n", n, r.URL)
	}
	b, _ := json.Marshal(r)
	s.jsonl.Write(b)
	s.jsonl.WriteByte('\n')
	n := atomic.AddUint64(&s.writes, 1)
	if n%200 == 0 {
		s.flushLocked()
	}
	s.mu.Unlock()

	atomic.AddUint64(&s.regCount, uint64(len(r.Registered)))
	atomic.AddUint64(&s.claimCount, uint64(len(r.Claimable)))
	atomic.AddUint64(&s.unknownCount, uint64(len(r.Unknown)))
	atomic.AddUint64(&s.invalidCount, uint64(len(r.Invalid)))

	for _, name := range r.Registered {
		s.recordScope(name, "registered")
	}
	for _, name := range r.Claimable {
		s.recordScope(name, "claimable")
	}
}

func (s *sink) flushLocked() {
	s.claimable.Flush()
	s.registered.Flush()
	s.unknown.Flush()
	s.jsonl.Flush()
}

func (s *sink) flush() {
	s.mu.Lock()
	s.flushLocked()
	s.mu.Unlock()
}

type scopeRow struct {
	scope      string
	reg, claim int
}

func (s *sink) scopeRows() []scopeRow {
	s.scopeMu.Lock()
	rows := make([]scopeRow, 0, len(s.scope))
	for sc, st := range s.scope {
		rows = append(rows, scopeRow{sc, st["registered"], st["claimable"]})
	}
	s.scopeMu.Unlock()
	sort.Slice(rows, func(i, j int) bool { return rows[i].scope < rows[j].scope })
	return rows
}

func (s *sink) writeScopeReport() {
	rows := s.scopeRows()
	var b strings.Builder
	for _, r := range rows {
		flag := ""
		if r.reg == 0 && r.claim > 0 {
			flag = "\t<-- HIGH SIGNAL"
		}
		fmt.Fprintf(&b, "%s\tregistered=%d\tclaimable=%d%s\n", r.scope, r.reg, r.claim, flag)
	}
	os.WriteFile(filepath.Join(s.outDir, "scope_report.txt"), []byte(b.String()), 0o644)
}

func (s *sink) close() {
	s.flush()
	s.writeScopeReport()
	for _, f := range s.files {
		f.Close()
	}
}

// ---------------------------------------------------------------------------
// Pipeline
// ---------------------------------------------------------------------------

type hunter struct {
	reg            *registry
	client         *http.Client
	followInline   bool
	seen           sync.Map // name -> struct{}, global dedup
	fetchFailCount uint64
}

func (h *hunter) fetch(url string) (string, error) {
	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return "", err
	}
	req.Header.Set("User-Agent", "depfusion/"+version+" (+security-research)")
	resp, err := h.client.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		io.Copy(io.Discard, resp.Body)
		return "", fmt.Errorf("status %d", resp.StatusCode)
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, 32<<20)) // 32 MiB cap
	if err != nil {
		return "", err
	}
	return string(body), nil
}

func joinURL(base, ref string) string {
	if strings.HasPrefix(ref, "http://") || strings.HasPrefix(ref, "https://") {
		return ref
	}
	if i := strings.LastIndex(base, "/"); i >= 0 {
		return base[:i+1] + strings.TrimPrefix(ref, "./")
	}
	return ref
}

func (h *hunter) process(url string) urlResult {
	r := urlResult{URL: url}
	content, err := h.fetch(url)
	if err != nil {
		atomic.AddUint64(&h.fetchFailCount, 1)
		r.Error = "fetch_failed: " + err.Error()
		return r
	}

	var modules map[string]struct{}
	if looksLikeSourceMap(url, content) {
		modules = extractFromSourceMap(content)
	} else {
		modules = extractFromJS(content)
		if h.followInline {
			if m := inlineSourceMap.FindStringSubmatch(content); m != nil && !strings.HasPrefix(m[1], "data:") {
				if mc, err := h.fetch(joinURL(url, m[1])); err == nil {
					for k := range extractFromSourceMap(mc) {
						modules[k] = struct{}{}
					}
				}
			}
		}
	}

	names := make([]string, 0, len(modules))
	for n := range modules {
		names = append(names, n)
	}
	sort.Strings(names)

	for _, name := range names {
		if _, dup := h.seen.LoadOrStore(name, struct{}{}); dup {
			continue
		}
		switch h.reg.check(name) {
		case stRegistered:
			r.Registered = append(r.Registered, name)
		case stClaimable:
			r.Claimable = append(r.Claimable, name)
			theUI.printf("  %s  %s  %s\n",
				theUI.bold(theUI.green("CLAIMABLE")),
				theUI.bold(padRight(name, 40)),
				theUI.dim(url))
		case stInvalid:
			r.Invalid = append(r.Invalid, name)
		default:
			r.Unknown = append(r.Unknown, name)
		}
	}
	return r
}

// ---------------------------------------------------------------------------
// Summary writers
// ---------------------------------------------------------------------------

type runStats struct {
	StartedAt        time.Time     `json:"started_at"`
	FinishedAt       time.Time     `json:"finished_at"`
	Elapsed          string        `json:"elapsed"`
	ElapsedSeconds   float64       `json:"elapsed_seconds"`
	InputURLs        int           `json:"input_urls"`
	TotalURLs        int           `json:"total_urls"`
	ProcessedURLs    uint64        `json:"processed_urls"`
	FetchFailures    uint64        `json:"fetch_failures"`
	UniquePackages   int           `json:"unique_packages"`
	Registered       uint64        `json:"registered"`
	Claimable        uint64        `json:"claimable"`
	Unknown          uint64        `json:"unknown"`
	InvalidSkipped   uint64        `json:"invalid_skipped"`
	AvgRate          float64       `json:"avg_urls_per_sec"`
	HighSignalScopes []string      `json:"high_signal_scopes"`
	TopScopes        []scopeStat   `json:"top_claimable_scopes"`
	Config           runConfig     `json:"config"`
	Version          string        `json:"version"`
	OutputDir        string        `json:"output_dir"`
	_                time.Duration // gofmt-friendly anchor
}

type scopeStat struct {
	Scope      string `json:"scope"`
	Claimable  int    `json:"claimable"`
	Registered int    `json:"registered"`
}

type runConfig struct {
	InputFile        string `json:"input_file"`
	OutputDir        string `json:"output_dir"`
	Workers          int    `json:"workers"`
	TimeoutSeconds   int    `json:"timeout_seconds"`
	ProbeMap         bool   `json:"probe_map"`
	FollowInlineMap  bool   `json:"follow_inline_map"`
	InsecureTLS      bool   `json:"insecure_tls"`
}

func writeSummaryMarkdown(path string, st runStats) error {
	var b strings.Builder
	fmt.Fprintf(&b, "# depfusion run summary\n\n")
	fmt.Fprintf(&b, "- **Version:** %s\n", st.Version)
	fmt.Fprintf(&b, "- **Started:** %s\n", st.StartedAt.Format(time.RFC3339))
	fmt.Fprintf(&b, "- **Finished:** %s\n", st.FinishedAt.Format(time.RFC3339))
	fmt.Fprintf(&b, "- **Elapsed:** %s\n", st.Elapsed)
	fmt.Fprintf(&b, "- **Avg rate:** %.1f URLs/s\n\n", st.AvgRate)

	fmt.Fprintf(&b, "## Config\n\n")
	fmt.Fprintf(&b, "| Setting | Value |\n|---|---|\n")
	fmt.Fprintf(&b, "| input file | `%s` |\n", st.Config.InputFile)
	fmt.Fprintf(&b, "| output dir | `%s` |\n", st.Config.OutputDir)
	fmt.Fprintf(&b, "| workers | %d |\n", st.Config.Workers)
	fmt.Fprintf(&b, "| timeout | %ds |\n", st.Config.TimeoutSeconds)
	fmt.Fprintf(&b, "| probe `.map` | %t |\n", st.Config.ProbeMap)
	fmt.Fprintf(&b, "| follow inline map | %t |\n", st.Config.FollowInlineMap)
	fmt.Fprintf(&b, "| insecure TLS | %t |\n\n", st.Config.InsecureTLS)

	fmt.Fprintf(&b, "## Queue\n\n")
	fmt.Fprintf(&b, "- Input URLs: **%d**\n", st.InputURLs)
	fmt.Fprintf(&b, "- Total URLs (incl. `.map` probes): **%d**\n", st.TotalURLs)
	fmt.Fprintf(&b, "- Processed: **%d**\n", st.ProcessedURLs)
	fmt.Fprintf(&b, "- Fetch failures: **%d**\n\n", st.FetchFailures)

	fmt.Fprintf(&b, "## Packages\n\n")
	fmt.Fprintf(&b, "Unique packages discovered: **%d**\n\n", st.UniquePackages)
	fmt.Fprintf(&b, "| Category | Count |\n|---|---|\n")
	fmt.Fprintf(&b, "| registered | %d |\n", st.Registered)
	fmt.Fprintf(&b, "| **claimable** | **%d** |\n", st.Claimable)
	fmt.Fprintf(&b, "| unknown | %d |\n", st.Unknown)
	fmt.Fprintf(&b, "| invalid (skipped) | %d |\n\n", st.InvalidSkipped)

	if len(st.HighSignalScopes) > 0 {
		fmt.Fprintf(&b, "## High-signal scopes\n\n")
		fmt.Fprintf(&b, "_Scopes where every observed package is claimable (no registered packages present)._\n\n")
		for _, sc := range st.HighSignalScopes {
			fmt.Fprintf(&b, "- `%s`\n", sc)
		}
		b.WriteString("\n")
	}

	if len(st.TopScopes) > 0 {
		fmt.Fprintf(&b, "## Top scopes by claimable count\n\n")
		fmt.Fprintf(&b, "| Scope | Claimable | Registered |\n|---|---:|---:|\n")
		for _, sc := range st.TopScopes {
			fmt.Fprintf(&b, "| `%s` | %d | %d |\n", sc.Scope, sc.Claimable, sc.Registered)
		}
		b.WriteString("\n")
	}

	fmt.Fprintf(&b, "## Outputs\n\n")
	fmt.Fprintf(&b, "All files are in `%s/`.\n\n", st.OutputDir)
	fmt.Fprintf(&b, "- `claimable.txt` — `name<TAB>url` for each claimable package (submission candidates)\n")
	fmt.Fprintf(&b, "- `registered.txt` — packages already on npm\n")
	fmt.Fprintf(&b, "- `unknown.txt` — registry check failed; verify manually\n")
	fmt.Fprintf(&b, "- `results.jsonl` — one JSON object per URL (full per-URL result)\n")
	fmt.Fprintf(&b, "- `scope_report.txt` — per-scope tally\n")
	fmt.Fprintf(&b, "- `summary.md` — this file\n")
	fmt.Fprintf(&b, "- `run_info.json` — machine-readable run metadata\n\n")

	fmt.Fprintf(&b, "## Caveat\n\n")
	fmt.Fprintf(&b, "A clean 404 is a _candidate_, not a confirmed takeover. npm sometimes ")
	fmt.Fprintf(&b, "security-holds previously-unpublished names. Before reporting, verify with ")
	fmt.Fprintf(&b, "`npm view <name>` and `npm publish --dry-run` on a throwaway package.\n")

	return os.WriteFile(path, []byte(b.String()), 0o644)
}

func writeRunInfo(path string, st runStats) error {
	b, err := json.MarshalIndent(st, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(path, b, 0o644)
}

// ---------------------------------------------------------------------------
// Live progress reporter
// ---------------------------------------------------------------------------

type progress struct {
	total      int
	done       *uint64
	fetchFails *uint64
	claim      *uint64
	start      time.Time
	stop       chan struct{}
}

func (p *progress) tick() {
	d := atomic.LoadUint64(p.done)
	elapsed := time.Since(p.start)
	rate := float64(d) / elapsed.Seconds()
	if rate < 0.01 {
		rate = 0
	}
	remaining := uint64(p.total) - d
	var eta string
	if rate > 0 && remaining > 0 {
		eta = humanDuration(time.Duration(float64(remaining)/rate) * time.Second)
	} else {
		eta = "—"
	}
	pctStr := pct(d, uint64(p.total))
	theUI.printf("  %s  %s/%s  %s  rate=%s  eta=%s  fetch-fail=%s  claim=%s\n",
		theUI.cyan("progress"),
		theUI.bold(humanNum(d)),
		humanNum(uint64(p.total)),
		theUI.dim("("+strings.TrimSpace(pctStr)+")"),
		theUI.bold(fmt.Sprintf("%.0f/s", rate)),
		theUI.bold(eta),
		theUI.yellow(humanNum(atomic.LoadUint64(p.fetchFails))),
		theUI.green(humanNum(atomic.LoadUint64(p.claim))),
	)
}

func (p *progress) run() {
	t := time.NewTicker(5 * time.Second)
	defer t.Stop()
	for {
		select {
		case <-t.C:
			p.tick()
		case <-p.stop:
			return
		}
	}
}

// ---------------------------------------------------------------------------
// Main
// ---------------------------------------------------------------------------

func readLines(path string) ([]string, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	var out []string
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 1024*1024), 4*1024*1024)
	for sc.Scan() {
		if l := strings.TrimSpace(sc.Text()); l != "" {
			out = append(out, l)
		}
	}
	return out, sc.Err()
}

func main() {
	var (
		file        = flag.String("f", "", "input file: one URL per line (required)")
		outDir      = flag.String("o", "", "output directory (required)")
		workers     = flag.Int("workers", 40, "concurrent workers")
		timeoutSec  = flag.Int("timeout", 20, "per-request timeout in seconds")
		noProbeMap  = flag.Bool("no-probe-map", false, "don't auto-append .map to each URL")
		noInlineMap = flag.Bool("no-follow-inline-map", false, "don't follow //# sourceMappingURL pointers")
		insecure    = flag.Bool("insecure", true, "skip TLS cert verification (handles wildcard/underscore host mismatches)")
		noColor     = flag.Bool("no-color", false, "disable ANSI colors (auto-disabled when stderr is not a TTY)")
		forceColor  = flag.Bool("color", false, "force ANSI colors even when stderr is not a TTY")
		showVersion = flag.Bool("version", false, "print version and exit")
	)
	flag.Parse()

	if *showVersion {
		fmt.Println("depfusion " + version)
		return
	}
	if *file == "" || *outDir == "" {
		flag.Usage()
		os.Exit(2)
	}

	theUI.color = detectColor(*forceColor, *noColor)
	theUI.banner()

	startedAt := time.Now()

	// --- read input ---
	urls, err := readLines(*file)
	if err != nil {
		fmt.Fprintf(os.Stderr, "%s cannot read input: %v\n", theUI.red("error:"), err)
		os.Exit(1)
	}

	targets := make([]string, 0, len(urls)*2)
	for _, u := range urls {
		targets = append(targets, u)
		if !*noProbeMap && !strings.HasSuffix(u, ".map") {
			targets = append(targets, u+".map")
		}
	}

	// --- config block ---
	theUI.section("config")
	theUI.kv("input", *file)
	theUI.kv("output dir", *outDir+"/")
	theUI.kv("workers", *workers)
	theUI.kv("timeout", fmt.Sprintf("%ds", *timeoutSec))
	theUI.kv("probe .map", yesno(!*noProbeMap))
	theUI.kv("inline maps", yesno(!*noInlineMap))
	theUI.kv("insecure tls", yesno(*insecure))

	theUI.section("queue")
	theUI.kv("input URLs", humanNum(uint64(len(urls))))
	theUI.kv("total URLs", humanNum(uint64(len(targets))))
	theUI.kv("started", startedAt.Format("2006-01-02 15:04:05"))

	// --- HTTP / sink / hunter ---
	transport := &http.Transport{
		MaxIdleConns:        200,
		MaxIdleConnsPerHost: 4,
		IdleConnTimeout:     30 * time.Second,
		TLSClientConfig:     &tls.Config{InsecureSkipVerify: *insecure},
	}
	client := &http.Client{
		Timeout:   time.Duration(*timeoutSec) * time.Second,
		Transport: transport,
	}

	sk, err := newSink(*outDir)
	if err != nil {
		fmt.Fprintf(os.Stderr, "%s cannot create output: %v\n", theUI.red("error:"), err)
		os.Exit(1)
	}

	cfg := runConfig{
		InputFile:       *file,
		OutputDir:       *outDir,
		Workers:         *workers,
		TimeoutSeconds:  *timeoutSec,
		ProbeMap:        !*noProbeMap,
		FollowInlineMap: !*noInlineMap,
		InsecureTLS:     *insecure,
	}

	// --- signal handler: flush partial output ---
	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, os.Interrupt, syscall.SIGTERM)
	go func() {
		<-sigCh
		theUI.printf("\n%s signal received — flushing partial output to %s/\n",
			theUI.yellow("!"), *outDir)
		sk.close()
		os.Exit(130)
	}()

	h := &hunter{reg: newRegistry(client), client: client, followInline: !*noInlineMap}

	theUI.section("running")

	var done uint64
	prog := &progress{
		total:      len(targets),
		done:       &done,
		fetchFails: &h.fetchFailCount,
		claim:      &sk.claimCount,
		start:      time.Now(),
		stop:       make(chan struct{}),
	}
	go prog.run()

	jobs := make(chan string, *workers*4)
	var wg sync.WaitGroup
	total := len(targets)

	for i := 0; i < *workers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for u := range jobs {
				sk.write(h.process(u))
				n := atomic.AddUint64(&done, 1)
				if int(n) == total {
					sk.writeScopeReport()
				}
			}
		}()
	}
	for _, u := range targets {
		jobs <- u
	}
	close(jobs)
	wg.Wait()
	close(prog.stop)

	sk.close()
	finishedAt := time.Now()
	elapsed := finishedAt.Sub(startedAt)

	// --- collect stats ---
	regN := atomic.LoadUint64(&sk.regCount)
	claimN := atomic.LoadUint64(&sk.claimCount)
	unkN := atomic.LoadUint64(&sk.unknownCount)
	invN := atomic.LoadUint64(&sk.invalidCount)
	fetchFails := atomic.LoadUint64(&h.fetchFailCount)
	unique := regN + claimN + unkN + invN
	avgRate := float64(done) / elapsed.Seconds()
	if avgRate < 0.01 {
		avgRate = 0
	}

	rows := sk.scopeRows()
	var highSignal []string
	for _, r := range rows {
		if r.reg == 0 && r.claim > 0 {
			highSignal = append(highSignal, r.scope)
		}
	}

	// top-10 scopes by claimable
	topRows := append([]scopeRow(nil), rows...)
	sort.Slice(topRows, func(i, j int) bool {
		if topRows[i].claim != topRows[j].claim {
			return topRows[i].claim > topRows[j].claim
		}
		return topRows[i].scope < topRows[j].scope
	})
	topN := 10
	if len(topRows) < topN {
		topN = len(topRows)
	}
	var topScopes []scopeStat
	for i := 0; i < topN; i++ {
		if topRows[i].claim == 0 {
			break
		}
		topScopes = append(topScopes, scopeStat{
			Scope:      topRows[i].scope,
			Claimable:  topRows[i].claim,
			Registered: topRows[i].reg,
		})
	}

	st := runStats{
		StartedAt:        startedAt,
		FinishedAt:       finishedAt,
		Elapsed:          humanDuration(elapsed),
		ElapsedSeconds:   elapsed.Seconds(),
		InputURLs:        len(urls),
		TotalURLs:        len(targets),
		ProcessedURLs:    done,
		FetchFailures:    fetchFails,
		UniquePackages:   int(unique),
		Registered:       regN,
		Claimable:        claimN,
		Unknown:          unkN,
		InvalidSkipped:   invN,
		AvgRate:          avgRate,
		HighSignalScopes: highSignal,
		TopScopes:        topScopes,
		Config:           cfg,
		Version:          version,
		OutputDir:        *outDir,
	}

	// --- write summary files ---
	_ = writeSummaryMarkdown(filepath.Join(*outDir, "summary.md"), st)
	_ = writeRunInfo(filepath.Join(*outDir, "run_info.json"), st)

	// --- print final summary ---
	printFinalSummary(st, topScopes, highSignal)
}

func yesno(b bool) string {
	if b {
		return "yes"
	}
	return "no"
}

func printFinalSummary(st runStats, topScopes []scopeStat, highSignal []string) {
	u := theUI
	u.section("summary")
	u.kv("processed", fmt.Sprintf("%s / %s", humanNum(st.ProcessedURLs), humanNum(uint64(st.TotalURLs))))
	u.kv("elapsed", st.Elapsed)
	u.kv("avg rate", fmt.Sprintf("%.1f URLs/s", st.AvgRate))
	u.kv("fetch failures", u.yellow(humanNum(st.FetchFailures)))
	u.kv("unique packages", u.bold(humanNum(uint64(st.UniquePackages))))

	u.printf("\n  %s\n", u.gray("    category            count       share"))
	u.printf("    %s  %s  %s\n",
		padRight("registered", 18),
		padLeft(humanNum(st.Registered), 8),
		u.dim(pct(st.Registered, uint64(st.UniquePackages))))
	u.printf("    %s  %s  %s  %s\n",
		u.bold(u.green(padRight("claimable", 18))),
		u.bold(u.green(padLeft(humanNum(st.Claimable), 8))),
		u.dim(pct(st.Claimable, uint64(st.UniquePackages))),
		u.dim("← submission candidates"))
	u.printf("    %s  %s  %s\n",
		padRight("unknown", 18),
		padLeft(humanNum(st.Unknown), 8),
		u.dim(pct(st.Unknown, uint64(st.UniquePackages))))
	u.printf("    %s  %s  %s\n",
		u.dim(padRight("invalid (skipped)", 18)),
		u.dim(padLeft(humanNum(st.InvalidSkipped), 8)),
		u.dim(pct(st.InvalidSkipped, uint64(st.UniquePackages))))

	if len(highSignal) > 0 {
		u.section("high-signal scopes")
		u.printf("  %s\n", u.dim("(every observed package in these scopes is claimable)"))
		for _, sc := range highSignal {
			u.printf("    %s\n", u.bold(u.green(sc)))
		}
	}

	if len(topScopes) > 0 {
		u.section("top claimable scopes")
		for _, sc := range topScopes {
			flag := ""
			if sc.Registered == 0 {
				flag = u.bold(u.green("  HIGH SIGNAL"))
			}
			u.printf("    %s  claim=%s  reg=%s%s\n",
				padRight(sc.Scope, 30),
				u.bold(u.green(padLeft(fmt.Sprintf("%d", sc.Claimable), 4))),
				padLeft(fmt.Sprintf("%d", sc.Registered), 4),
				flag)
		}
	}

	u.section("outputs")
	u.kv("dir", st.OutputDir+"/")
	u.kv("claimable.txt", fmt.Sprintf("%s entries", humanNum(st.Claimable)))
	u.kv("registered.txt", fmt.Sprintf("%s entries", humanNum(st.Registered)))
	u.kv("unknown.txt", fmt.Sprintf("%s entries", humanNum(st.Unknown)))
	u.kv("results.jsonl", fmt.Sprintf("%s records", humanNum(st.ProcessedURLs)))
	u.kv("scope_report.txt", "per-scope tally")
	u.kv("summary.md", "human-readable")
	u.kv("run_info.json", "machine-readable")

	if st.Claimable > 0 {
		u.printf("\n%s %s claimable candidate(s) — verify with %s and %s before reporting.\n",
			u.bold(u.green("✓ done.")),
			u.bold(humanNum(st.Claimable)),
			u.bold("npm view <name>"),
			u.bold("npm publish --dry-run"))
	} else {
		u.printf("\n%s no claimable candidates this run.\n", u.bold(u.green("✓ done.")))
	}
}
