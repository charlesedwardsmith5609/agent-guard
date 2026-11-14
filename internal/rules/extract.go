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
	ctxEvery      = 256  // tokens between cancellation checks
)

var errTooMany = errors.New("tool input refers to too many distinct hosts or paths")

// extracted is what a tool call's input refers to.
type extracted struct {
	hosts      []string // lower-case; numeric IPv4 spellings in canonical dotted form
	candidates []string // path-like tokens, for sensitive checks
	structured []string // values of known path keys, for scope checks
}

var pathKeys = map[string]bool{
	"file_path": true, "path": true, "notebook_path": true, "filename": true,
	"directory": true, "dir": true, "cwd": true, "filepath": true,
}

var (
	// The authority runs up to / ? # or a delimiter. ']' stays inside the match so
	// user@[2001:db8::1] is one authority; authorityHost then keeps the host.
	urlRe  = regexp.MustCompile(`[A-Za-z][A-Za-z0-9+.\-]*://([^\s/?#'"<>)\\]+)`)
	scpRe  = regexp.MustCompile(`[\w.\-]+@([A-Za-z0-9][A-Za-z0-9.\-]*[A-Za-z0-9]):`)
	ipv4Re = regexp.MustCompile(`(?:^|[^0-9.])((?:[0-9]{1,3}\.){3}[0-9]{1,3})(?:$|[^0-9.])`)
)

// Commands whose operands are network destinations.
var netCommands = map[string]bool{
	"curl": true, "wget": true, "ssh": true, "scp": true, "sftp": true, "nc": true, "ncat": true,
	"netcat": true, "telnet": true, "ftp": true, "rsync": true, "ping": true, "dig": true,
	"nslookup": true, "host": true, "traceroute": true, "mtr": true, "socat": true, "http": true, "https": true,
}

// For these, a bare dotted operand is a local file; only host:path and user@host forms count.
// (sftp is not listed: its operand is the destination.)
var localFileCommands = map[string]bool{"scp": true, "rsync": true}

// Options whose next token is a value (a file, header, method...) and never a destination.
var valueOptions = map[string]map[string]bool{
	"curl": setOf("-o", "--output", "-T", "--upload-file", "-F", "--form", "-d", "--data", "--data-raw",
		"--data-binary", "-H", "--header", "-A", "--user-agent", "-b", "--cookie", "-c", "--cookie-jar",
		"-K", "--config", "-w", "--write-out", "-X", "--request", "-e", "--referer", "-u", "--user",
		"-m", "--max-time", "-D", "--dump-header"),
	"wget": setOf("-O", "--output-document", "-o", "--output-file", "-P", "--directory-prefix",
		"-i", "--input-file", "-t", "--tries", "-T", "--timeout", "-w", "--wait"),
}

func setOf(v ...string) map[string]bool {
	m := make(map[string]bool, len(v))
	for _, s := range v {
		m[s] = true
	}
	return m
}

// Last labels that make a dotted token look like a hostname anywhere in a command line.
// File-like names (sh, py, rs, md, in, cc, ...) are deliberately absent so main.py or Makefile.in
// are not mistaken for hosts; inside a network command every dotted operand is a host anyway.
var tlds = setOf(strings.Fields(`com net org io dev ai app cloud xyz info biz co us uk de fr ru cn jp
	br au ca nl se eu tv ly gg onion internal local`)...)

// uniq is an insertion-ordered set with a cap, so memory stays bounded while collecting.
type uniq struct {
	seen map[string]struct{}
	list []string
	max  int
}

func newUniq(max int) *uniq { return &uniq{seen: map[string]struct{}{}, max: max} }

// add returns false when the set is full and s is new.
func (u *uniq) add(s string) bool {
	if _, ok := u.seen[s]; ok {
		return true
	}
	if len(u.list) >= u.max {
		return false
	}
	u.seen[s] = struct{}{}
	u.list = append(u.list, s)
	return true
}

type walker struct {
	ctx                      context.Context
	hosts, cands, structured *uniq
	bytes                    int
	err                      error
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
	w := &walker{ctx: ctx, hosts: newUniq(maxHosts), cands: newUniq(maxCandidates), structured: newUniq(maxCandidates)}
	if err := w.walk(v, "", 0); err != nil {
		return extracted{}, err
	}
	return extracted{hosts: w.hosts.list, candidates: w.cands.list, structured: w.structured.list}, nil
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
	return w.err
}

func (w *walker) fail(err error) {
	if w.err == nil {
		w.err = err
	}
}

func (w *walker) addHost(h string) {
	h = canonicalHost(h)
	if h == "" {
		return
	}
	if !w.hosts.add(h) {
		w.fail(errTooMany)
	}
}

// canonicalHost folds a host to the form the allowlist is stored in: lower
// case, no trailing dots, and one spelling for addresses that are the same
// number (decimal, hex, octal, and IPv4-mapped IPv6).
func canonicalHost(h string) string {
	h = strings.ToLower(strings.TrimSpace(h))
	for strings.HasSuffix(h, ".") {
		h = strings.TrimSuffix(h, ".")
	}
	if len(h) >= 2 && h[0] == '[' && h[len(h)-1] == ']' {
		h = h[1 : len(h)-1]
	}
	if ip, ok := looseIPv4(h); ok {
		return ip
	}
	if addr, err := netip.ParseAddr(h); err == nil {
		return addr.Unmap().String()
	}
	return h
}

func (w *walker) addCandidate(p string) {
	if !w.cands.add(p) {
		w.fail(errTooMany)
	}
}

func (w *walker) scan(key, s string) {
	if pathKeys[strings.ToLower(key)] && s != "" {
		if !w.structured.add(s) {
			w.fail(errTooMany)
		}
		w.addCandidate(s)
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

	var (
		netCmd      string // the network command whose operands we are reading
		gitCtx      bool
		skipNext    bool
		operandSeen bool
	)
	for i, tok := range tokenize(s) {
		if i%ctxEvery == 0 {
			if err := w.ctx.Err(); err != nil {
				w.fail(err)
				return
			}
		}
		if w.err != nil {
			return
		}
		if tok == "" { // separator: a new command begins
			netCmd, gitCtx, skipNext, operandSeen = "", false, false, false
			continue
		}
		base := tok
		if j := strings.LastIndexByte(base, '/'); j >= 0 && j < len(base)-1 {
			base = base[j+1:]
		}
		if skipNext {
			skipNext = false
			continue
		}
		if netCommands[base] {
			netCmd, operandSeen = base, false
			continue
		}
		if base == "git" {
			gitCtx = true
			continue
		}
		if netCmd != "" && valueOptions[netCmd][tok] {
			skipNext = true
			continue
		}
		if looksLikePath(tok) {
			w.addCandidate(tok)
		}
		if strings.Contains(tok, "://") {
			continue // handled by urlRe
		}
		if ip, ok := numericIPv4(tok); ok && (netCmd != "" || ip == metadataIP) {
			w.addHost(ip)
			continue
		}

		if netCmd != "" {
			if a, err := netip.ParseAddr(tok); err == nil && a.Is6() {
				w.addHost(a.Unmap().String())
				continue
			}
		}
		hasColon := strings.Contains(tok, ":")
		parts := strings.Split(tok, ":")
		for pi, part := range parts {
			if part == "" || allDigits(part) {
				continue // empty or a port
			}
			if ip, ok := numericIPv4(part); ok {
				if netCmd != "" || ip == metadataIP {
					w.addHost(ip)
				}
				continue
			}
			if h, ok := hostToken(part); ok {
				last := h[strings.LastIndexByte(h, '.')+1:]
				switch {
				case tlds[last]:
					w.addHost(h)
				case netCmd != "" && (!localFileCommands[netCmd] || hasColon):
					w.addHost(h)
				case gitCtx && hasColon && pi == 0:
					w.addHost(h) // git clone evil.example:org/repo.git
				}
				operandSeen = true
				continue
			}
			// Dotless names: localhost, internal-svc, user@host.
			if netCmd != "" && !strings.HasPrefix(part, "-") {
				if h, ok := bareHost(part); ok && (h == "localhost" || !operandSeen || strings.Contains(part, "@") || (hasColon && pi == 0)) {
					w.addHost(h)
					operandSeen = true
				}
			}
		}
	}
}

// numericIPv4 recognises an address spelled as an integer or dotted numeric parts. A lone small
// number (a port, a count) is not an address.
func numericIPv4(tok string) (string, bool) {
	ip, ok := looseIPv4(tok)
	if !ok {
		return "", false
	}
	if !strings.Contains(tok, ".") && !isBigInt(tok) {
		return "", false
	}
	return ip, true
}

func isBigInt(tok string) bool {
	return allDigitsOrHex(tok) && len(tok) >= 8
}

func allDigitsOrHex(s string) bool {
	s = strings.TrimPrefix(strings.ToLower(s), "0x")
	for i := 0; i < len(s); i++ {
		c := s[i]
		if !(c >= '0' && c <= '9' || c >= 'a' && c <= 'f') {
			return false
		}
	}
	return s != ""
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
	if strings.HasPrefix(t, "/") || strings.HasPrefix(t, "~") || strings.HasPrefix(t, "./") ||
		strings.HasPrefix(t, "../") || t == ".." || strings.HasPrefix(t, "proc/") {
		return true
	}
	for _, seg := range strings.Split(t, "/") {
		if seg == ".ssh" || seg == ".env" || strings.HasPrefix(seg, ".env.") {
			return true
		}
	}
	return false
}

// hostToken reports whether t (optionally followed by /path, ?query or #fragment) is a dotted
// hostname. user@host.com is an email address and does not qualify.
func hostToken(t string) (string, bool) {
	if i := strings.IndexAny(t, "/?#"); i >= 0 {
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

// bareHost accepts dotless names (localhost, internal-svc) and user@host in a network command.
func bareHost(t string) (string, bool) {
	if i := strings.LastIndexByte(t, '@'); i >= 0 {
		t = t[i+1:]
	}
	t = strings.ToLower(t)
	if t == "" || allDigits(t) || !validHost(t) {
		return "", false
	}
	return t, true
}
