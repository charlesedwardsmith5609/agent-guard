// Package rules implements the policy engine: it decides ALLOW, BLOCK or ASK for a tool call
// from a YAML configuration.
package rules

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"net/netip"
	"os"
	"path"
	"regexp"
	"strings"

	"gopkg.in/yaml.v3"

	"agent-guard/internal/policy"
)

type fileConfig struct {
	Tools *[]string `yaml:"tools"`
	Hosts *[]string `yaml:"hosts"`
	Paths *struct {
		Workdir string    `yaml:"workdir"`
		Allow   *[]string `yaml:"allow"`
	} `yaml:"paths"`
	Sensitive  map[string]string `yaml:"sensitive"`
	Canaries   *[]string         `yaml:"canaries"`
	ForumTools *[]string         `yaml:"forum_tools"`
}

// Sensitive classes, usable as keys under `sensitive:` in the config.
const (
	ClassProcEnviron = "proc_environ"
	ClassSSH         = "ssh"
	ClassDotenv      = "dotenv"
	ClassMetadata    = "metadata"
)

var classes = []string{ClassProcEnviron, ClassSSH, ClassDotenv, ClassMetadata}

// Options carries environment values so tests do not depend on the machine.
type Options struct {
	Home    string // expansion of ~; defaults to os.UserHomeDir
	Workdir string // default for paths.workdir; defaults to os.Getwd
}

// Engine implements policy.Decider. It is immutable after Parse and safe for concurrent use.
type Engine struct {
	toolsExact  map[string]bool
	toolsPrefix []string
	hostsExact  map[string]bool
	hostSuffix  []string // ".example.com" for "*.example.com"
	allow       []string // cleaned absolute directory prefixes
	workdir     string
	home        string
	sensitive   map[string]policy.Verdict
	canaries    []string // opaque tokens; substring-matched in tool input strings
	forumExact  map[string]bool
	forumPrefix []string
}

const (
	maxConfigBytes = 1 << 20
	minCanaryBytes = 16
	maxCanaryBytes = 256
	maxCanaries    = 64
	maxForumTools  = 64
)

var hostLabel = regexp.MustCompile(`^[a-z0-9]([a-z0-9-]*[a-z0-9])?$`)

// Load reads and parses a config file.
func Load(file string) (*Engine, error) {
	f, err := os.Open(file)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	b, err := io.ReadAll(io.LimitReader(f, maxConfigBytes+1))
	if err != nil {
		return nil, err
	}
	if len(b) > maxConfigBytes {
		return nil, fmt.Errorf("config is larger than %d bytes", maxConfigBytes)
	}
	return Parse(b, Options{})
}

// Parse validates a YAML config. Any problem is an error; nothing is defaulted silently.
func Parse(data []byte, opt Options) (*Engine, error) {
	var fc fileConfig
	dec := yaml.NewDecoder(bytes.NewReader(data))
	dec.KnownFields(true)
	if err := dec.Decode(&fc); err != nil {
		if errors.Is(err, io.EOF) {
			return nil, errors.New("config is empty")
		}
		return nil, fmt.Errorf("config: %w", err)
	}
	var extra any
	if err := dec.Decode(&extra); !errors.Is(err, io.EOF) {
		return nil, errors.New("config: exactly one YAML document is allowed")
	}
	if fc.Tools == nil || fc.Hosts == nil || fc.Paths == nil || fc.Paths.Allow == nil {
		return nil, errors.New("config: tools, hosts and paths.allow are required (use [] to allow nothing)")
	}
	if opt.Home == "" {
		h, err := os.UserHomeDir()
		if err != nil {
			return nil, fmt.Errorf("config: cannot determine home directory: %w", err)
		}
		opt.Home = h
	}
	e := &Engine{
		toolsExact: map[string]bool{}, hostsExact: map[string]bool{}, forumExact: map[string]bool{},
		home: path.Clean(opt.Home), sensitive: map[string]policy.Verdict{},
	}

	for _, t := range *fc.Tools {
		exact, prefix, err := parseNamePattern(t, "tool")
		if err != nil {
			return nil, err
		}
		if prefix != "" {
			e.toolsPrefix = append(e.toolsPrefix, prefix)
		} else {
			e.toolsExact[exact] = true
		}
	}
	for _, h := range *fc.Hosts {
		h = strings.ToLower(strings.TrimSuffix(strings.TrimSpace(h), "."))
		if rest, ok := strings.CutPrefix(h, "*."); ok {
			if !validHost(rest) {
				return nil, fmt.Errorf("config: invalid host pattern %q", h)
			}
			e.hostSuffix = append(e.hostSuffix, "."+rest)
			continue
		}
		if !validHost(h) {
			return nil, fmt.Errorf("config: invalid host %q", h)
		}
		e.hostsExact[h] = true
	}

	e.workdir = fc.Paths.Workdir
	if e.workdir == "" {
		wd := opt.Workdir
		if wd == "" {
			var err error
			if wd, err = os.Getwd(); err != nil {
				return nil, fmt.Errorf("config: cannot determine working directory: %w", err)
			}
		}
		e.workdir = wd
	}
	var err error
	if e.workdir, err = e.absolute(e.workdir); err != nil {
		return nil, fmt.Errorf("config: paths.workdir: %w", err)
	}
	for _, a := range *fc.Paths.Allow {
		a = strings.TrimSuffix(strings.TrimSuffix(a, "/**"), "/*")
		p, err := e.absolute(a)
		if err != nil {
			return nil, fmt.Errorf("config: paths.allow %q: %w", a, err)
		}
		e.allow = append(e.allow, p)
	}

	for _, c := range classes {
		e.sensitive[c] = policy.Ask
	}
	for class, v := range fc.Sensitive {
		if _, ok := e.sensitive[class]; !ok {
			return nil, fmt.Errorf("config: unknown sensitive class %q (want one of %v)", class, classes)
		}
		switch strings.ToLower(v) {
		case "ask":
			e.sensitive[class] = policy.Ask
		case "block":
			e.sensitive[class] = policy.Block
		default:
			return nil, fmt.Errorf("config: sensitive.%s must be ask or block, got %q", class, v)
		}
	}

	if fc.Canaries != nil {
		if len(*fc.Canaries) > maxCanaries {
			return nil, fmt.Errorf("config: at most %d canaries are allowed", maxCanaries)
		}
		seen := map[string]bool{}
		for _, c := range *fc.Canaries {
			if c == "" || strings.TrimSpace(c) != c {
				return nil, fmt.Errorf("config: canary must be non-empty and must not have leading or trailing whitespace")
			}
			if len(c) < minCanaryBytes || len(c) > maxCanaryBytes {
				return nil, fmt.Errorf("config: canary length must be %d–%d bytes, got %d", minCanaryBytes, maxCanaryBytes, len(c))
			}
			if seen[c] {
				return nil, fmt.Errorf("config: duplicate canary")
			}
			seen[c] = true
			e.canaries = append(e.canaries, c)
		}
	}
	if fc.ForumTools != nil {
		if len(*fc.ForumTools) > maxForumTools {
			return nil, fmt.Errorf("config: at most %d forum_tools patterns are allowed", maxForumTools)
		}
		for _, t := range *fc.ForumTools {
			exact, prefix, err := parseNamePattern(t, "forum_tools")
			if err != nil {
				return nil, err
			}
			if prefix != "" {
				e.forumPrefix = append(e.forumPrefix, prefix)
			} else {
				e.forumExact[exact] = true
			}
		}
	}
	return e, nil
}

// Canaries returns a copy of the configured canary tokens for audit redaction.
// The Engine remains the owner of the authoritative list; callers must not mutate the result
// in a way that is shared back (the slice is a shallow copy of immutable strings).
func (e *Engine) Canaries() []string {
	if len(e.canaries) == 0 {
		return nil
	}
	out := make([]string, len(e.canaries))
	copy(out, e.canaries)
	return out
}

// parseNamePattern accepts an exact name or a trailing-* prefix (literal prefix ≥ 3 chars).
func parseNamePattern(t, kind string) (exact, prefix string, err error) {
	if t == "" || strings.TrimSpace(t) != t {
		return "", "", fmt.Errorf("config: invalid %s name %q", kind, t)
	}
	if strings.HasSuffix(t, "*") {
		p := strings.TrimSuffix(t, "*")
		if len(p) < 3 || strings.Contains(p, "*") {
			return "", "", fmt.Errorf("config: %s pattern %q needs a literal prefix of at least 3 characters", kind, t)
		}
		return "", p, nil
	}
	if strings.Contains(t, "*") {
		return "", "", fmt.Errorf("config: %s pattern %q: * is only allowed at the end", kind, t)
	}
	return t, "", nil
}

// absolute returns a cleaned absolute path for config entries: absolute or ~-prefixed only.
func (e *Engine) absolute(p string) (string, error) {
	p = e.expandHome(p)
	if !strings.HasPrefix(p, "/") {
		return "", errors.New("must be absolute or start with ~")
	}
	return path.Clean(p), nil
}

func (e *Engine) expandHome(p string) string {
	if p == "~" {
		return e.home
	}
	if rest, ok := strings.CutPrefix(p, "~/"); ok {
		return path.Join(e.home, rest)
	}
	return p
}

func validHost(h string) bool {
	if h == "" || len(h) > 253 {
		return false
	}
	if _, err := netip.ParseAddr(h); err == nil {
		return true
	}
	for _, l := range strings.Split(h, ".") {
		if len(l) > 63 || !hostLabel.MatchString(l) {
			return false
		}
	}
	return true
}
