//go:build !unix

package audit

// Without O_NOFOLLOW the protections Open promises cannot be provided, so Open refuses to run.
const (
	noFollow          = 0
	nonBlock          = 0
	safeOpenSupported = false
)
