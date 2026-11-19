package audit

import (
	"bytes"
	"encoding/json"
	"math"
	"regexp"
	"strings"
	"unicode/utf8"
)

const (
	redacted        = "[REDACTED]"
	previewInputMax = 64 << 10 // larger inputs get a placeholder; the hash is still recorded
)

var (
	secretKey = regexp.MustCompile(`(?i)(key|token|secret|passw|authorization|credential|cookie|bearer|auth)`)
	// Known credential shapes.
	tokenPatterns = []*regexp.Regexp{
		regexp.MustCompile(`sk-[A-Za-z0-9_\-]{16,}`),
		regexp.MustCompile(`(?:ghp|gho|ghu|ghs|ghr)_[A-Za-z0-9]{20,}`),
		regexp.MustCompile(`github_pat_[A-Za-z0-9_]{20,}`),
		regexp.MustCompile(`\b(?:AKIA|ASIA)[0-9A-Z]{16}\b`),
		regexp.MustCompile(`xox[baprs]-[A-Za-z0-9\-]{10,}`),
		regexp.MustCompile(`eyJ[A-Za-z0-9_\-]{8,}\.[A-Za-z0-9_\-]{8,}\.[A-Za-z0-9_\-]{8,}`),
		regexp.MustCompile(`(?i)\bbearer\s+[A-Za-z0-9._\-~+/]{8,}=*`),
		regexp.MustCompile(`-----BEGIN [A-Z ]*PRIVATE KEY-----`),
	}
	basicAuth = regexp.MustCompile(`(?i)\bbasic\s+[A-Za-z0-9+/]{8,}=*`)
	// --password x, --token=x, curl -u user:pass: common credential-bearing options.
	credOption = regexp.MustCompile(`(?i)(--?(?:password|passwd|pass|token|secret|api-?key|auth)(?:=|\s+))\S+`)
	curlUser   = regexp.MustCompile(`(\s-u\s*)\S+`)
	// userinfo is everything between "://" and the last "@" of the authority, so a password may
	// contain "@" and the user may be empty. It stops at the first character that ends an
	// authority or a quoted token.
	userinfo = regexp.MustCompile(`(://)[^\s/?#"'<>\\]*@`)
	// assignName finds a secret-looking name and its separator: NAME=, NAME = and NAME: . The name
	// pattern also matches inside a word, so prose such as "token: enabled" is redacted too.
	// redactAssignments decides where the value ends.
	assignName = regexp.MustCompile(`(?i)\b([A-Z0-9_]*(?:KEY|TOKEN|SECRET|PASSWORD|PASSWD|CREDENTIAL)[A-Z0-9_]*)([ \t]*[=:][ \t]*)`)
	// headerValue finds a credential header name and its separator; headerEnd decides where the value stops.
	headerValue = regexp.MustCompile(`(?i)\b((?:proxy-)?authorization|x-api-key)(["']?[ \t]*[:=][ \t]*)`)
	wordSplit   = regexp.MustCompile(`[\s"'=:,;()<>\[\]{}/\\]+`)
)

// redactString removes credentials from free text: known token shapes, URL userinfo, secret-looking
// shell assignments, and long mixed letter/digit words with high entropy (unknown formats).
func redactString(s string) string { return redactWithCanaries(s, nil) }

// redactWithCanaries is redactString plus literal substring redaction of configured canaries.
func redactWithCanaries(s string, canaries []string) string {
	for _, c := range canaries {
		if c != "" {
			s = strings.ReplaceAll(s, c, redacted)
		}
	}
	for _, re := range tokenPatterns {
		s = re.ReplaceAllString(s, redacted)
	}
	s = basicAuth.ReplaceAllString(s, redacted)
	s = redactHeaders(s)
	s = credOption.ReplaceAllString(s, "${1}"+redacted)
	s = curlUser.ReplaceAllString(s, "${1}"+redacted)
	s = userinfo.ReplaceAllString(s, "${1}"+redacted+"@")
	s = redactAssignments(s)
	s = redactBase64Secrets(s)
	var out strings.Builder
	last := 0
	for _, loc := range wordLocs(s) {
		w := s[loc[0]:loc[1]]
		if looksRandom(w) {
			out.WriteString(s[last:loc[0]])
			out.WriteString(redacted)
			last = loc[1]
		}
	}
	out.WriteString(s[last:])
	return out.String()
}

// valueScanner finds where a credential value ends. A value inside quotes runs to the next
// unescaped copy of the quote, even across lines (a shell string may span lines). If there is no
// such quote the value runs to the end of the line, or to whitespace when spaceEnds is set. The
// scanner remembers that a quote character has no closer left, so a string with many unclosed
// quotes is scanned once, not once per match. Calls must come in increasing order of start.
type valueScanner struct {
	s        string
	noCloser map[byte]bool
}

func newValueScanner(s string) *valueScanner { return &valueScanner{s: s, noCloser: map[byte]bool{}} }

func (v *valueScanner) end(start int, stop byte, spaceEnds bool) int {
	s := v.s
	if stop != 0 && !v.noCloser[stop] {
		for i := start; i < len(s); i++ {
			if s[i] == stop && (i == 0 || s[i-1] != '\\') {
				return i
			}
		}
		v.noCloser[stop] = true
	}
	end := start
	for end < len(s) && s[end] != '\n' && s[end] != '\r' {
		if spaceEnds && stop == 0 && (s[end] == ' ' || s[end] == '\t') {
			break
		}
		end++
	}
	return end
}

func isAlnum(r rune) bool {
	return r >= 'a' && r <= 'z' || r >= 'A' && r <= 'Z' || r >= '0' && r <= '9'
}

// quoteAt returns the quote character at s[i], or 0.
func quoteAt(s string, i int) byte {
	if i >= 0 && i < len(s) && (s[i] == '"' || s[i] == '\'') {
		return s[i]
	}
	return 0
}

// redactHeaders replaces the value of an Authorization, Proxy-Authorization or X-Api-Key header
// with the redaction marker, whatever its scheme or length. Where the value ends depends on the
// quoting around it: a quote just before the header name ends the value at the next unescaped
// copy of that quote (so a Digest value with escaped inner quotes is covered whole); a quote that
// opens the value ends it at the next copy; otherwise the value runs to the end of the line.
func redactHeaders(s string) string {
	locs := headerValue.FindAllStringSubmatchIndex(s, -1)
	if locs == nil {
		return s
	}
	var out strings.Builder
	sc := newValueScanner(s)
	last := 0
	for _, loc := range locs {
		if loc[0] < last {
			continue
		}
		start := loc[1]
		stop := quoteAt(s, loc[0]-1)
		if q := quoteAt(s, start); q != 0 {
			stop = q
			start++
		}
		end := sc.end(start, stop, false)
		if end == start {
			continue
		}
		out.WriteString(s[last:start])
		out.WriteString(redacted)
		last = end
	}
	out.WriteString(s[last:])
	return out.String()
}

// redactAssignments replaces the value of NAME=value, NAME = value and NAME: value for a
// secret-looking NAME. The value must not start with "=" (so "key := f()" and "a == b" are left
// alone). A value that opens with a quote runs to the closing quote, so it may contain spaces;
// any other value runs to whitespace. A value that is already the redaction marker is kept as is.
func redactAssignments(s string) string {
	locs := assignName.FindAllStringSubmatchIndex(s, -1)
	if locs == nil {
		return s
	}
	var out strings.Builder
	sc := newValueScanner(s)
	last := 0
	for _, loc := range locs {
		if loc[0] < last {
			continue
		}
		start := loc[1]
		if start >= len(s) || s[start] == '=' || s[start] == ' ' || s[start] == '\t' || s[start] == '\n' || s[start] == '\r' {
			continue
		}
		stop := quoteAt(s, start)
		valueStart := start
		if stop != 0 {
			valueStart++
		}
		end := sc.end(valueStart, stop, true)
		if stop != 0 && end < len(s) && s[end] == stop {
			end++
		}
		if rest, ok := strings.CutPrefix(s[start:end], redacted); ok && !strings.ContainsFunc(rest, isAlnum) {
			continue // already redacted by an earlier rule; keep any closing quote
		}
		out.WriteString(s[last:start])
		out.WriteString(redacted)
		last = end
	}
	out.WriteString(s[last:])
	return out.String()
}

func isBase64Byte(c byte) bool {
	return c >= 'A' && c <= 'Z' || c >= 'a' && c <= 'z' || c >= '0' && c <= '9' || c == '+' || c == '/'
}

// redactBase64Secrets replaces a run of exactly 40 characters from A-Za-z0-9/+, the format of an
// AWS secret access key. The word heuristic cannot see such a key when "/" splits it into pieces
// under 20 characters. A run is taken only when it has an upper-case letter, a lower-case letter
// and a digit, at most 3 "/", does not start with "/", and is not touching "." "_" or "-"
// (slugs, UUIDs and JWT parts). An unusual 40-character relative path or other unpadded base64
// or mixed-case hex string of that shape is redacted too. A key that starts with "/", has four or
// more "/" or has no digit (about one key in a thousand) is not found here; a NAME=value context
// still catches it.
func redactBase64Secrets(s string) string {
	var out strings.Builder
	last := 0
	for i := 0; i < len(s); {
		if !isBase64Byte(s[i]) {
			i++
			continue
		}
		j := i
		for j < len(s) && isBase64Byte(s[j]) {
			j++
		}
		if j-i == 40 && !strings.ContainsRune("._-", rune(byteAt(s, i-1))) && !strings.ContainsRune("._-", rune(byteAt(s, j))) && base64SecretShape(s[i:j]) {
			out.WriteString(s[last:i])
			out.WriteString(redacted)
			last = j
		}
		i = j
	}
	out.WriteString(s[last:])
	return out.String()
}

// byteAt returns s[i], or 0 outside the string.
func byteAt(s string, i int) byte {
	if i < 0 || i >= len(s) {
		return 0
	}
	return s[i]
}

func base64SecretShape(w string) bool {
	if w[0] == '/' || strings.Count(w, "/") > 3 {
		return false
	}
	var upper, lower, digit bool
	for i := 0; i < len(w); i++ {
		switch c := w[i]; {
		case c >= 'A' && c <= 'Z':
			upper = true
		case c >= 'a' && c <= 'z':
			lower = true
		case c >= '0' && c <= '9':
			digit = true
		}
	}
	return upper && lower && digit
}

// wordLocs returns the [start,end) of each word between separators.
func wordLocs(s string) [][2]int {
	var locs [][2]int
	seps := wordSplit.FindAllStringIndex(s, -1)
	prev := 0
	for _, sp := range seps {
		if sp[0] > prev {
			locs = append(locs, [2]int{prev, sp[0]})
		}
		prev = sp[1]
	}
	if prev < len(s) {
		locs = append(locs, [2]int{prev, len(s)})
	}
	return locs
}

// looksRandom flags words of 20+ characters that mix letters and digits with Shannon entropy of
// at least 3.5 bits per character: tokens, keys, hashes.
func looksRandom(w string) bool {
	if len(w) < 20 {
		return false
	}
	var letter, digit bool
	counts := map[rune]int{}
	n := 0
	for _, r := range w {
		switch {
		case r >= '0' && r <= '9':
			digit = true
		case r >= 'a' && r <= 'z' || r >= 'A' && r <= 'Z':
			letter = true
		}
		counts[r]++
		n++
	}
	if !letter || !digit {
		return false
	}
	var h float64
	for _, c := range counts {
		p := float64(c) / float64(n)
		h -= p * math.Log2(p)
	}
	return h >= 3.5
}

func redactValue(v any, canaries []string) any {
	switch t := v.(type) {
	case map[string]any:
		out := make(map[string]any, len(t))
		for k, val := range t {
			if secretKey.MatchString(k) {
				out[k] = redacted
			} else {
				out[k] = redactValue(val, canaries)
			}
		}
		return out
	case []any:
		out := make([]any, len(t))
		for i, e := range t {
			out[i] = redactValue(e, canaries)
		}
		return out
	case string:
		return redactWithCanaries(t, canaries)
	}
	return v
}

// preview renders the tool input as compact, redacted JSON of at most max bytes.
func preview(input json.RawMessage, max int, canaries []string) string {
	if len(input) > previewInputMax {
		return "[too large to preview]" // bound CPU and memory on the request path
	}
	dec := json.NewDecoder(bytes.NewReader(input))
	dec.UseNumber()
	var v any
	if err := dec.Decode(&v); err != nil {
		return "[unparseable]"
	}
	b, err := json.Marshal(redactValue(v, canaries))
	if err != nil {
		return "[unparseable]"
	}
	return truncate(string(b), max)
}

// truncate cuts s to at most max bytes on a rune boundary, marking the cut.
func truncate(s string, max int) string {
	if len(s) <= max {
		return s
	}
	cut := max - 3
	if cut < 0 {
		cut = 0
	}
	for cut > 0 && !utf8.RuneStart(s[cut]) {
		cut--
	}
	return s[:cut] + "..."
}
