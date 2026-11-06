package rules

import (
	"context"
	"encoding/json"
	"errors"
	"net/netip"
	"regexp"
	"sort"
	"strings"
)

const (
	maxInputBytes = 1 << 20
	maxDepth      = 16
	maxHosts      = 256  // distinct hosts per call; more is an error (fail closed)
	maxCandidates = 1024 // distinct path-like tokens per call
)

// extracted is what a tool call's input refers to.
type extracted struct {
	hosts      []string // lower-case; IPv4 literals in canonical dotted form
	candidates []string // path-like tokens, for sensitive checks
	structured []string // values of known path keys, for scope checks
}

var pathKeys = map[string]bool{
	"file_path": true, "path": true, "notebook_path": true, "filename": true,
	"directory": true, "dir": true, "cwd": true, "filepath": true,
}

var (
	urlRe  = regexp.MustCompile(`[A-Za-z][A-Za-z0-9+.\-]*://([^\s/?#'"<>)\]\\]+|\[[0-9A-Fa-f:.]+\])`)
	scpRe  = regexp.MustCompile(`[\w.\-]+@([A-Za-z0-9][A-Za-z0-9.\-]*[A-Za-z0-9]):`)
	ipv4Re = regexp.MustCompile(`(?:^|[^0-9.])((?:[0-9]{1,3}\.){3}[0-9]{1,3})(?:$|[^0-9.])`)
)

// Commands whose bare arguments are network destinations.
var netCommands = map[string]bool{
	"curl": true, "wget": true, "ssh": true, "scp": true, "sftp": true, "nc": true, "ncat": true,
	"netcat": true, "telnet": true, "ftp": true, "rsync": true, "ping": true, "dig": true,
	"nslookup": true, "host": true, "traceroute": true, "mtr": true, "socat": true, "http": true, "https": true,
}

// Last labels that make a bare token look like a hostname. File-like names (sh, py, rs, md, in,
// cc, ...) are deliberately absent so main.py or Makefile.in are not mistaken for hosts.
var tlds = map[string]bool{}

func init() {
	for _, t := range strings.Fields(`com net org io dev ai app cloud xyz info biz co us uk de fr ru cn jp
		br au ca nl se eu tv ly gg onion internal local`) {
		tlds[t] = true
	}
}

// Endings that mark a dotted token as a file name, not a host, inside a network command
// (curl -o out.txt, wget file.zip).
var fileExts = map[string]bool{}

func init() {
	for _, t := range strings.Fields(`txt json zip tar gz tgz bz2 xz md log yaml yml toml html htm csv png jpg
		jpeg gif svg pdf py go js ts rs c h cpp hpp sh rb out bin so conf cfg ini xml sql lock sum mod
		java kt swift php pl lua exe dll dmg deb rpm whl jar war`) {
		fileExts[t] = true
	}
}

type walker struct {
	ctx   context.Context
	out   extracted
	bytes int
}

func extract(ctx context.Context, input []byte) (extracted, error) {
	if len(input) > maxInputBytes {
		return extracted{}, errors.New("tool input too large")
	}
	var v any
	if err := json.Unmarshal(input, &v); err != nil {
		return extracted{}, err
	}
	if _, ok := v.(map[string]any); !ok {
		return extracted{}, errors.New("tool input is not a JSON object")
	}
	w := &walker{ctx: ctx}
	if err := w.walk(v, "", 0); err != nil {
		return extracted{}, err
	}
	var err error
	if w.out.hosts, err = dedupe(w.out.hosts, maxHosts); err != nil {
		return extracted{}, err
	}
	if w.out.candidates, err = dedupe(w.out.candidates, maxCandidates); err != nil {
		return extracted{}, err
	}
	if w.out.structured, err = dedupe(w.out.structured, maxCandidates); err != nil {
		return extracted{}, err
	}
	return w.out, nil
}

func (w *walker) walk(v any, key string, depth int) error {
	if err := w.ctx.Err(); err != nil {
		return err
	}
	if depth > maxDepth {
		return errors.New("tool input nested too deeply")
	}
	switch t := v.(type) {
	case map[string]any:
		keys := make([]string, 0, len(t))
		for k := range t {
			keys = append(keys, k)
		}
		sort.Strings(keys) // deterministic ordering of findings
		for _, k := range keys {
			if err := w.walk(t[k], k, depth+1); err != nil {
				return err
			}
		}
	case []any:
		for _, e := range t {
			if err := w.walk(e, key, depth+1); err != nil {
				return err
			}
		}
	case string:
		w.bytes += len(t)
		if w.bytes > maxInputBytes {
			return errors.New("tool input strings too large")
		}
		w.scan(key, t)
	}
	return nil
}

func (w *walker) addHost(h string) {
	h = strings.ToLower(strings.TrimSuffix(h, "."))
	if h == "" {
		return
	}
	if ip, ok := looseIPv4(h); ok {
		h = ip
	}
	w.out.hosts = append(w.out.hosts, h)
}

func (w *walker) scan(key, s string) {
	if pathKeys[strings.ToLower(key)] && s != "" {
		w.out.structured = append(w.out.structured, s)
		w.out.candidates = append(w.out.candidates, s)
	}
	for _, m := range urlRe.FindAllStringSubmatch(s, -1) {
		w.addHost(authorityHost(m[1]))
	}
	for _, m := range scpRe.FindAllStringSubmatch(s, -1) {
		w.addHost(m[1])
	}
	for _, m := range ipv4Re.FindAllStringSubmatch(s, -1) {
		w.addHost(m[1])
	}

	netCtx, gitCtx := false, false
	for _, tok := range tokenize(s) {
		if tok == "" { // separator: a new command begins
			netCtx, gitCtx = false, false
			continue
		}
		base := tok
		if i := strings.LastIndexByte(base, '/'); i >= 0 && i < len(base)-1 {
			base = base[i+1:]
		}
		if netCommands[base] {
			netCtx = true
			continue
		}
		if base == "git" {
			gitCtx = true
			continue
		}
		if looksLikePath(tok) {
			w.out.candidates = append(w.out.candidates, tok)
		}
		if strings.Contains(tok, "://") {
			continue // handled by urlRe
		}
		if ip, ok := looseIPv4(tok); ok && ip == metadataIP {
			w.out.hosts = append(w.out.hosts, ip)
			continue
		}
		if h, ok := hostToken(tok); ok {
			last := h[strings.LastIndexByte(h, '.')+1:]
			switch {
			case tlds[last]:
				w.addHost(h)
			case netCtx && !fileExts[last] && !allDigits(last):
				w.addHost(h)
			case gitCtx && strings.Contains(tok, ":") && !fileExts[last] && !allDigits(last):
				w.addHost(h) // git clone evil.example:org/repo.git
			}
		} else if netCtx && !strings.HasPrefix(tok, "-") {
			if h, ok := bareHost(tok); ok {
				w.addHost(h)
			}
		}
	}
}

func allDigits(s string) bool {
	for i := 0; i < len(s); i++ {
		if s[i] < '0' || s[i] > '9' {
			return false
		}
	}
	return s != ""
}

// authorityHost extracts the host from a URL authority (userinfo, port and brackets removed).
func authorityHost(a string) string {
	if i := strings.LastIndexByte(a, '@'); i >= 0 {
		a = a[i+1:]
	}
	if strings.HasPrefix(a, "[") {
		if j := strings.IndexByte(a, ']'); j > 0 {
			return a[1:j]
		}
	}
	if i := strings.LastIndexByte(a, ':'); i >= 0 {
		a = a[:i]
	}
	return a
}

// tokenize splits shell-ish text into tokens. An empty string marks a command separator.
func tokenize(s string) []string {
	var toks []string
	var cur strings.Builder
	flush := func() {
		if cur.Len() > 0 {
			toks = append(toks, cur.String())
			cur.Reset()
		}
	}
	for _, r := range s {
		switch r {
		case ' ', '\t', '\n', '\r', '\'', '"', '`', '(', ')', '{', '}', '<', '>', ',', '=', '$', '[', ']':
			flush()
		case ';', '|', '&':
			flush()
			toks = append(toks, "")
		default:
			cur.WriteRune(r)
		}
	}
	flush()
	for i, t := range toks {
		toks[i] = strings.TrimRight(t, ".:!?")
		if toks[i] == "" && t != "" {
			toks[i] = t
		}
	}
	return toks
}

func looksLikePath(t string) bool {
	if strings.HasPrefix(t, "/") || strings.HasPrefix(t, "~") || strings.HasPrefix(t, "./") || strings.HasPrefix(t, "../") || t == ".." {
		return true
	}
	for _, seg := range strings.Split(t, "/") {
		if seg == ".ssh" || seg == ".env" || strings.HasPrefix(seg, ".env.") {
			return true
		}
	}
	return false
}

// hostToken reports whether t (optionally with a :port or /path suffix) is a dotted hostname.
func hostToken(t string) (string, bool) {
	if i := strings.IndexAny(t, "/?#"); i >= 0 {
		t = t[:i]
	}
	// No userinfo stripping here: user@host.com outside a network command is an email address.
	if i := strings.IndexByte(t, ':'); i >= 0 {
		// host:port, or the scp/git form host:path.
		t = t[:i]
	}
	t = strings.ToLower(strings.TrimSuffix(t, "."))
	if !strings.Contains(t, ".") || !validHost(t) {
		return "", false
	}
	if _, err := netip.ParseAddr(t); err == nil {
		return t, true
	}
	return t, true
}

// bareHost accepts dotless names (localhost, internal-svc) in a network-command context.
func bareHost(t string) (string, bool) {
	if i := strings.LastIndexByte(t, '@'); i >= 0 {
		t = t[i+1:]
	}
	if i := strings.LastIndexByte(t, ':'); i >= 0 {
		t = t[:i]
	}
	t = strings.ToLower(t)
	if t == "" || !validHost(t) || strings.ContainsAny(t, "/") {
		return "", false
	}
	return t, true
}

// dedupe removes repeats, keeping first-seen order, and fails when more than max remain.
func dedupe(in []string, max int) ([]string, error) {
	seen := make(map[string]bool, len(in))
	out := in[:0:0]
	for _, v := range in {
		if seen[v] {
			continue
		}
		if len(out) >= max {
			return nil, errors.New("tool input refers to too many distinct hosts or paths")
		}
		seen[v] = true
		out = append(out, v)
	}
	return out, nil
}
