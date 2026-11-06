//go:build unix

package audit

import (
	"path/filepath"
	"syscall"
	"testing"
)

func TestOpenRejectsFIFOWithoutBlocking(t *testing.T) {
	p := filepath.Join(t.TempDir(), "fifo")
	if err := syscall.Mkfifo(p, 0o600); err != nil {
		t.Skip("mkfifo unavailable")
	}
	res := make(chan error, 1)
	go func() { _, err := Open(p, Options{}); res <- err }()
	if err := recv(t, res); err == nil {
		t.Fatal("expected an error")
	}
}
