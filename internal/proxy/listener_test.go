package proxy

import (
	"bufio"
	"context"
	"errors"
	"io"
	"net"
	"net/http"
	"sync/atomic"
	"testing"
)

type accepted struct {
	c   net.Conn
	err error
}

func acceptAsync(l net.Listener) <-chan accepted {
	ch := make(chan accepted, 1)
	go func() {
		c, err := l.Accept()
		ch <- accepted{c, err}
	}()
	return ch
}

func limited(t *testing.T, n int) (net.Listener, string) {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	ll, err := LimitListener(ln, n)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ll.Close() })
	return ll, ln.Addr().String()
}

func TestLimitListenerRejectsBadLimit(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	for _, n := range []int{0, -1} {
		if _, err := LimitListener(ln, n); err == nil {
			t.Errorf("n=%d: expected error", n)
		}
	}
}

func TestLimitListenerBlocksUntilClose(t *testing.T) {
	ll, addr := limited(t, 1)
	dial(t, addr)
	first := recv(t, acceptAsync(ll))
	if first.err != nil {
		t.Fatal(first.err)
	}
	dial(t, addr)
	second := acceptAsync(ll)
	select {
	case a := <-second:
		t.Fatalf("second Accept returned while the cap was full: %v", a.err)
	default:
	}
	first.c.Close()
	if a := recv(t, second); a.err != nil {
		t.Fatal(a.err)
	} else {
		a.c.Close()
	}
}

func TestLimitListenerDoubleCloseReleasesOnce(t *testing.T) {
	ll, addr := limited(t, 1)
	dial(t, addr)
	first := recv(t, acceptAsync(ll))
	first.c.Close()
	first.c.Close()
	dial(t, addr)
	second := recv(t, acceptAsync(ll))
	if second.err != nil {
		t.Fatal(second.err)
	}
	dial(t, addr)
	third := acceptAsync(ll)
	select {
	case a := <-third:
		t.Fatalf("third Accept returned while one connection was open: %v", a.err)
	default:
	}
	second.c.Close()
	if a := recv(t, third); a.err != nil {
		t.Fatal(a.err)
	} else {
		a.c.Close()
	}
}

func TestLimitListenerCloseUnblocksAccept(t *testing.T) {
	ll, addr := limited(t, 1)
	dial(t, addr)
	first := recv(t, acceptAsync(ll))
	defer first.c.Close()
	blocked := acceptAsync(ll)
	ll.Close()
	if a := recv(t, blocked); !errors.Is(a.err, net.ErrClosed) {
		t.Fatalf("got %v, want net.ErrClosed", a.err)
	}
}

type flakyListener struct {
	net.Listener
	failed atomic.Bool
}

func (f *flakyListener) Accept() (net.Conn, error) {
	if f.failed.CompareAndSwap(false, true) {
		return nil, errors.New("scripted accept failure")
	}
	return f.Listener.Accept()
}

func TestLimitListenerReleasesSlotOnAcceptError(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	ll, err := LimitListener(&flakyListener{Listener: ln}, 1)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ll.Close() })
	if a := recv(t, acceptAsync(ll)); a.err == nil {
		t.Fatal("expected the scripted failure")
	}
	dial(t, ln.Addr().String())
	if a := recv(t, acceptAsync(ll)); a.err != nil {
		t.Fatalf("slot leaked after Accept error: %v", a.err)
	} else {
		a.c.Close()
	}
}

// Shutdown must finish even when the cap is full and another Accept is parked.
func TestLimitListenerShutdownWhileFull(t *testing.T) {
	ll, addr := limited(t, 1)
	srv := &http.Server{Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { io.WriteString(w, "ok") })}
	served := make(chan error, 1)
	go func() { served <- srv.Serve(ll) }()

	conn := dial(t, addr) // takes the only slot and goes idle after one keep-alive request
	io.WriteString(conn, "GET / HTTP/1.1\r\nHost: t\r\n\r\n")
	resp, err := http.ReadResponse(bufio.NewReader(conn), nil)
	if err != nil {
		t.Fatal(err)
	}
	io.Copy(io.Discard, resp.Body)
	resp.Body.Close()
	dial(t, addr) // queued behind the cap; the server's Accept is now parked

	ctx, cancel := context.WithTimeout(context.Background(), testTimeout)
	defer cancel()
	if err := srv.Shutdown(ctx); err != nil {
		t.Fatalf("Shutdown with a full cap: %v", err)
	}
	if err := recv(t, served); !errors.Is(err, http.ErrServerClosed) {
		t.Fatalf("Serve returned %v", err)
	}
}
