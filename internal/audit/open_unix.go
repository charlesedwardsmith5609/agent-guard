//go:build unix

package audit

import "syscall"

// Never follow a symlink at the final path component, and never block opening a FIFO.
const (
	noFollow          = syscall.O_NOFOLLOW
	nonBlock          = syscall.O_NONBLOCK
	safeOpenSupported = true
)
