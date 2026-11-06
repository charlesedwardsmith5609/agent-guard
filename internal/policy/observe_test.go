package policy

import (
	"strings"
	"testing"
)

func TestSafeID(t *testing.T) {
	cases := map[string]string{
		"Bash":                   "Bash",
		"mcp__github__list":      "mcp__github__list",
		"toolu_01A:b/c-d.e":      "toolu_01A:b/c-d.e",
		"bad\nname":              "bad_name",
		"esc\x1b[31m":            "esc__31m",
		"héllo":                  "h__llo",
		"":                       "-",
		strings.Repeat("a", 500): strings.Repeat("a", 128),
	}
	for in, want := range cases {
		if got := SafeID(in); got != want {
			t.Errorf("SafeID(%q) = %q, want %q", in, got, want)
		}
	}
}
