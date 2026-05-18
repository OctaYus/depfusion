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
	"log"
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
		req.Header.Set("User-Agent", "depfusion/1.0 (+security-research)")
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
	for _, n := range r.claimableLines() {
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

	for _, name := range r.Registered {
		s.recordScope(name, "registered")
	}
	for _, name := range r.Claimable {
		s.recordScope(name, "claimable")
	}
}

func (r urlResult) claimableLines() []string { return r.Claimable }

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

func (s *sink) writeScopeReport() {
	s.scopeMu.Lock()
	type row struct {
		scope             string
		reg, claim        int
	}
	var rows []row
	for sc, st := range s.scope {
		rows = append(rows, row{sc, st["registered"], st["claimable"]})
	}
	s.scopeMu.Unlock()
	sort.Slice(rows, func(i, j int) bool { return rows[i].scope < rows[j].scope })

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
	req.Header.Set("User-Agent", "depfusion/1.0 (+security-research)")
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
			log.Printf("CLAIMABLE   %s  (%s)", name, url)
		case stInvalid:
			r.Invalid = append(r.Invalid, name)
		default:
			r.Unknown = append(r.Unknown, name)
		}
	}
	return r
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
	)
	flag.Parse()
	if *file == "" || *outDir == "" {
		flag.Usage()
		os.Exit(2)
	}

	urls, err := readLines(*file)
	if err != nil {
		log.Fatalf("cannot read input: %v", err)
	}

	targets := make([]string, 0, len(urls)*2)
	for _, u := range urls {
		targets = append(targets, u)
		if !*noProbeMap && !strings.HasSuffix(u, ".map") {
			targets = append(targets, u+".map")
		}
	}
	log.Printf("queued %d URLs (%d input)", len(targets), len(urls))

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
		log.Fatalf("cannot create output: %v", err)
	}

	// Flush + write outputs on Ctrl-C / kill so partial runs are not lost.
	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, os.Interrupt, syscall.SIGTERM)
	go func() {
		<-sigCh
		log.Printf("signal received — flushing partial output to %s", *outDir)
		sk.close()
		os.Exit(130)
	}()

	h := &hunter{reg: newRegistry(client), client: client, followInline: !*noInlineMap}

	jobs := make(chan string, *workers*4)
	var wg sync.WaitGroup
	var done uint64
	total := len(targets)

	for i := 0; i < *workers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for u := range jobs {
				sk.write(h.process(u))
				n := atomic.AddUint64(&done, 1)
				if n%2500 == 0 || int(n) == total {
					log.Printf("processed %d/%d (fetch-fail=%d)",
						n, total, atomic.LoadUint64(&h.fetchFailCount))
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

	sk.close()
	log.Printf("done. output in %s/ (fetch-fail=%d)", *outDir,
		atomic.LoadUint64(&h.fetchFailCount))
}
