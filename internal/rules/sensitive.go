package rules

import (
	"path"
	"regexp"
	"strconv"
	"strings"
)

const metadataIP = "169.254.169.254"

var procEnviron = regexp.MustCompile(`^/proc/[^/]+(/task/[^/]+)?/environ$`)

// pathClass returns the sensitive class of a path-like token, or "" if it is not sensitive.
// The path is cleaned lexically (so /ok/../home/x/.ssh/id is caught); symlinks are not followed.
// A relative path is checked both as written and resolved against workdir, because the shell's
// real working directory is unknown.
func (e *Engine) pathClass(p string) string {
	p = e.expandHome(p)
	forms := []string{path.Clean(p)}
	if !strings.HasPrefix(p, "/") {
		// As written, against workdir, and against / (the shell may have done `cd /`).
		forms = []string{path.Clean(strings.TrimPrefix(p, "./")), path.Clean(e.workdir + "/" + p), path.Clean("/" + p)}
	}
	for _, f := range forms {
		if c := classifyClean(f); c != "" {
			return c
		}
	}
	return ""
}

func classifyClean(p string) string {
	if procEnviron.MatchString(p) {
		return ClassProcEnviron
	}
	for _, seg := range strings.Split(p, "/") {
		if seg == ".ssh" {
			return ClassSSH
		}
	}
	base := path.Base(p)
	if base == ".env" || strings.HasPrefix(base, ".env.") {
		return ClassDotenv
	}
	return ""
}

// hostClass returns ClassMetadata for the cloud metadata endpoint. Hosts arrive canonicalised
// (numeric spellings are already rewritten to dotted form by the extractor).
func hostClass(h string) string {
	h = strings.ToLower(strings.TrimSuffix(h, "."))
	if h == metadataIP || h == "metadata.google.internal" || h == "fd00:ec2::254" {
		return ClassMetadata
	}
	return ""
}

// looseIPv4 parses every spelling that inet_aton accepts: one to four parts, each decimal,
// 0x-hex or 0-octal, where the last part fills all remaining bytes (so 169.254.43518 and
// 2852039166 both mean 169.254.169.254). It returns the canonical dotted form.
func looseIPv4(s string) (string, bool) {
	parts := strings.Split(s, ".")
	if len(parts) > 4 {
		return "", false
	}
	var n uint64
	for i, p := range parts {
		if p == "" {
			return "", false
		}
		v, err := strconv.ParseUint(p, 0, 33)
		if err != nil {
			return "", false
		}
		if i < len(parts)-1 {
			if v > 255 {
				return "", false
			}
			n |= v << (8 * uint(3-i))
			continue
		}
		if v >= 1<<(8*uint(4-i)) { // the last part must fit in the bytes that remain
			return "", false
		}
		n |= v
	}
	return strconv.Itoa(int(n>>24&255)) + "." + strconv.Itoa(int(n>>16&255)) + "." +
		strconv.Itoa(int(n>>8&255)) + "." + strconv.Itoa(int(n&255)), true
}

// cleanAbs cleans an absolute slash path lexically.
func cleanAbs(p string) string { return path.Clean(p) }
