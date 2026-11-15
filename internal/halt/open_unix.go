//go:build unix

package halt

import "syscall"

const (
	noFollow          = syscall.O_NOFOLLOW
	nonBlock          = syscall.O_NONBLOCK
	safeOpenSupported = true
)

func isLoop(err error) bool { return err == syscall.ELOOP }
