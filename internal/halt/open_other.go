//go:build !unix

package halt

// Without O_NOFOLLOW the control file cannot be opened safely, so it is never read
// and the proxy stays halted (fail closed).
const (
	noFollow          = 0
	nonBlock          = 0
	safeOpenSupported = false
)

func isLoop(error) bool { return false }
