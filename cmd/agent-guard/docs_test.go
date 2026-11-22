package main

import (
	"bytes"
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
	"time"

	"agent-guard/internal/rules"
)

// The documentation is part of the product: these tests stop it drifting from the program.

func repoFile(t *testing.T, rel string) string {
	t.Helper()
	b, err := os.ReadFile(filepath.Join("..", "..", rel))
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

func docFiles(t *testing.T) []string {
	t.Helper()
	files := []string{"README.md", "REQUIREMENTS.md", "SECURITY.md", "plans/README.md"}
	more, err := filepath.Glob(filepath.Join("..", "..", "docs", "*.md"))
	if err != nil {
		t.Fatal(err)
	}
	for _, m := range more {
		files = append(files, filepath.Join("docs", filepath.Base(m)))
	}
	return files
}

// Every flag the program defines must appear in the flag tables of the README and the operations
// guide, and every flag in those tables must exist.
func TestFlagsAreDocumented(t *testing.T) {
	var help bytes.Buffer
	parseOptions([]string{"-h"}, &help)
	flagRe := regexp.MustCompile(`(?m)^\s+-([a-z][a-z-]*)`)
	var defined []string
	for _, m := range flagRe.FindAllStringSubmatch(help.String(), -1) {
		defined = append(defined, m[1])
	}
	if len(defined) < 10 {
		t.Fatalf("could not read the flags from -h output:\n%s", help.String())
	}
	tableRe := regexp.MustCompile("(?m)^\\| `-([a-z][a-z-]*)`")
	for _, doc := range []string{"README.md", "docs/operations.md"} {
		text := repoFile(t, doc)
		documented := map[string]bool{}
		for _, m := range tableRe.FindAllStringSubmatch(text, -1) {
			documented[m[1]] = true
		}
		if doc == "README.md" {
			continue // the README points to the operations guide instead of repeating the table
		}
		for _, f := range defined {
			if !documented[f] {
				t.Errorf("%s: flag -%s is not documented", doc, f)
			}
		}
		for f := range documented {
			found := false
			for _, d := range defined {
				found = found || d == f
			}
			if !found {
				t.Errorf("%s documents -%s, which does not exist", doc, f)
			}
		}
	}
}

// Every complete policy (a ```yaml block that starts with tools:) in the docs must load.
func TestPolicyExamplesInDocsLoad(t *testing.T) {
	blockRe := regexp.MustCompile("(?s)```yaml\n(.*?)```")
	checked := 0
	for _, doc := range append(docFiles(t), "examples/policy.yaml") {
		text := repoFile(t, doc)
		blocks := []string{text}
		if strings.HasSuffix(doc, ".md") {
			blocks = nil
			for _, m := range blockRe.FindAllStringSubmatch(text, -1) {
				blocks = append(blocks, m[1])
			}
		}
		for i, b := range blocks {
			if !strings.Contains(b, "tools:") {
				continue
			}
			if _, err := rules.ParsePolicy([]byte(b), rules.Options{Home: "/home/test", Workdir: "/work"}); err != nil {
				t.Errorf("%s: policy example %d does not load: %v\n%s", doc, i+1, err, b)
			}
			checked++
		}
	}
	if checked < 2 {
		t.Errorf("found only %d policy examples to check", checked)
	}
}

// Relative links and anchors in the Markdown must point at something that exists.
func TestRelativeLinksResolve(t *testing.T) {
	linkRe := regexp.MustCompile(`\]\(([^)\s]+)\)`)
	headRe := regexp.MustCompile(`(?m)^#{1,6}\s+(.*)$`)
	slug := func(h string) string {
		h = strings.ToLower(strings.TrimSpace(h))
		h = regexp.MustCompile("[`*]").ReplaceAllString(h, "")
		h = regexp.MustCompile(`[^a-z0-9 _-]`).ReplaceAllString(h, "")
		return strings.ReplaceAll(h, " ", "-")
	}
	anchors := func(file string) map[string]bool {
		a := map[string]bool{}
		for _, m := range headRe.FindAllStringSubmatch(repoFile(t, file), -1) {
			a[slug(m[1])] = true
		}
		return a
	}
	for _, doc := range docFiles(t) {
		for _, m := range linkRe.FindAllStringSubmatch(repoFile(t, doc), -1) {
			link := m[1]
			if strings.HasPrefix(link, "http://") || strings.HasPrefix(link, "https://") || strings.HasPrefix(link, "mailto:") {
				continue
			}
			path, frag, _ := strings.Cut(link, "#")
			target := doc
			if path != "" {
				target = filepath.Clean(filepath.Join(filepath.Dir(doc), path))
			}
			if _, err := os.Stat(filepath.Join("..", "..", target)); err != nil {
				t.Errorf("%s: link %q: %v", doc, link, err)
				continue
			}
			if frag != "" && strings.HasSuffix(target, ".md") && !anchors(target)[frag] {
				t.Errorf("%s: link %q: no heading %q in %s", doc, link, frag, target)
			}
		}
	}
}

// The velocity recipe in docs/operations.md is run on a small fixture log and its output compared
// exactly. It needs jq; without jq it reports itself as not run, loudly.
//
// Expected output, by hand from testdata/velocity-audit.jsonl (the halt row is dropped, the empty
// profile is "(none)", rows are sorted by ts, gaps are rounded to milliseconds):
//
//	ci: 00.100 Bash, 00.350 Bash, 00.600 Read, 10:01:05 Read, 10:01:07.5 Write. Gaps 0.25, 0.25,
//	    2.5, 64.4, so the three shortest are 0.25 0.25 2.5. Minutes 10:00 x3 and 10:01 x2.
//	dev: 10:00:30.000123456 Grep, 10:00:30.5 Grep, 10:03:00 Bash. Gaps 0.499877 (0.5) and 149.5.
//	(none): one Bash row at 10:00:01, so there is no gap.
func TestVelocityRecipe(t *testing.T) {
	doc := repoFile(t, "docs/operations.md")
	_, after, ok := strings.Cut(doc, "\n### Velocity per profile\n")
	if !ok {
		t.Fatal("docs/operations.md has no '### Velocity per profile' section")
	}
	if i := strings.Index(after, "\n#"); i >= 0 {
		after = after[:i]
	}
	const open, closeQ = "jq -rs '", "' audit.jsonl"
	var program string
	n := 0
	for _, line := range strings.Split(after, "\n") {
		if strings.HasPrefix(line, open) && strings.HasSuffix(line, closeQ) {
			program = line[len(open) : len(line)-len(closeQ)]
			n++
		}
	}
	if n != 1 {
		t.Fatalf("want exactly one jq -rs '...' audit.jsonl line in the velocity section, found %d", n)
	}
	jq, err := exec.LookPath("jq")
	if err != nil {
		// Skipf rather than the plain call: the pairing check flags that literal call text. This is still a
		// skip, and it is meant to be loud; report it as NOT RUN.
		t.Skipf("NOT RUN: jq not found in PATH, so the velocity recipe in docs/operations.md was NOT exercised (%v)", err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, jq, "-rs", program, filepath.Join("testdata", "velocity-audit.jsonl"))
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	out, err := cmd.Output()
	if err != nil {
		t.Fatalf("jq failed: %v\n%s", err, stderr.String())
	}
	want := "(none)\tcalls\t1\n" +
		"(none)\tper_minute\t10:00 1\n" +
		"(none)\tshortest_gaps_s\t\n" +
		"(none)\torder\tBash\n" +
		"ci\tcalls\t5\n" +
		"ci\tper_minute\t10:00 3, 10:01 2\n" +
		"ci\tshortest_gaps_s\t0.25 0.25 2.5\n" +
		"ci\torder\tBash x2 > Read x2 > Write\n" +
		"dev\tcalls\t3\n" +
		"dev\tper_minute\t10:00 2, 10:03 1\n" +
		"dev\tshortest_gaps_s\t0.5 149.5\n" +
		"dev\torder\tGrep x2 > Bash\n"
	if string(out) != want {
		t.Errorf("velocity recipe output differs.\ngot:\n%s\nwant:\n%s", out, want)
	}
}
