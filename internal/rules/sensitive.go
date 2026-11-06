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
func (e *Engine) pathClass(p string) string {
	p = e.expandHome(p)
	if strings.HasPrefix(p, "/") {
		p = path.Clean(p)
	} else {
		p = path.Clean(strings.TrimPrefix(p, "./"))
	}
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

// looseIPv4 parses the spellings that C resolvers accept for an IPv4 address: a single 32-bit
// integer, or four parts each decimal, 0x-hex or 0-octal. It returns the canonical dotted form.
func looseIPv4(s string) (string, bool) {
	parts := strings.Split(s, ".")
	if len(parts) != 1 && len(parts) != 4 {
		return "", false
	}
	var vals []uint64
	for _, p := range parts {
		if p == "" {
			return "", false
		}
		v, err := strconv.ParseUint(p, 0, 33)
		if err != nil {
			return "", false
		}
		vals = append(vals, v)
	}
	var n uint64
	if len(vals) == 1 {
		n = vals[0]
		if n > 0xffffffff {
			return "", false
		}
	} else {
		for _, v := range vals {
			if v > 255 {
				return "", false
			}
			n = n<<8 | v
		}
	}
	return strconv.Itoa(int(n>>24&255)) + "." + strconv.Itoa(int(n>>16&255)) + "." +
		strconv.Itoa(int(n>>8&255)) + "." + strconv.Itoa(int(n&255)), true
}

// cleanAbs cleans an absolute slash path lexically.
func cleanAbs(p string) string { return path.Clean(p) }
