package audit

import (
	"bytes"
	"encoding/json"
	"math"
	"regexp"
	"strings"
	"unicode/utf8"
)

const redacted = "[REDACTED]"

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
	userinfo  = regexp.MustCompile(`(://)[^\s/@:]+(:[^\s/@]*)?@`)
	envAssign = regexp.MustCompile(`(?i)\b([A-Z0-9_]*(?:KEY|TOKEN|SECRET|PASSWORD|PASSWD|CREDENTIAL)[A-Z0-9_]*)=\S+`)
	wordSplit = regexp.MustCompile(`[\s"'=:,;()<>\[\]{}]+`)
)

// redactString removes credentials from free text: known token shapes, URL userinfo, secret-looking
// shell assignments, and long mixed letter/digit words with high entropy (unknown formats).
func redactString(s string) string {
	for _, re := range tokenPatterns {
		s = re.ReplaceAllString(s, redacted)
	}
	s = userinfo.ReplaceAllString(s, "${1}"+redacted+"@")
	s = envAssign.ReplaceAllString(s, "${1}="+redacted)
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

func redactValue(v any) any {
	switch t := v.(type) {
	case map[string]any:
		out := make(map[string]any, len(t))
		for k, val := range t {
			if secretKey.MatchString(k) {
				out[k] = redacted
			} else {
				out[k] = redactValue(val)
			}
		}
		return out
	case []any:
		out := make([]any, len(t))
		for i, e := range t {
			out[i] = redactValue(e)
		}
		return out
	case string:
		return redactString(t)
	}
	return v
}

// preview renders the tool input as compact, redacted JSON of at most max bytes.
func preview(input json.RawMessage, max int) string {
	dec := json.NewDecoder(bytes.NewReader(input))
	dec.UseNumber()
	var v any
	if err := dec.Decode(&v); err != nil {
		return "[unparseable]"
	}
	b, err := json.Marshal(redactValue(v))
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
