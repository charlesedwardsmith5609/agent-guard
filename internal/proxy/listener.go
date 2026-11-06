package proxy

import (
	"errors"
	"net"
	"sync"
)

// LimitListener returns a listener that allows at most n accepted connections open at once.
//
// Ownership: sem is a buffered channel used as a counting semaphore. Accept acquires a slot;
// the slot is released when the returned connection is closed (exactly once) or when the
// underlying Accept fails. done is closed once by Close and unblocks a full Accept.
func LimitListener(l net.Listener, n int) (net.Listener, error) {
	if n <= 0 {
		return nil, errors.New("proxy: connection limit must be positive")
	}
	return &limitListener{Listener: l, sem: make(chan struct{}, n), done: make(chan struct{})}, nil
}

type limitListener struct {
	net.Listener
	sem  chan struct{}
	done chan struct{}
	once sync.Once
}

func (l *limitListener) Accept() (net.Conn, error) {
	select {
	case l.sem <- struct{}{}:
	case <-l.done:
		return nil, net.ErrClosed
	}
	c, err := l.Listener.Accept()
	if err != nil {
		<-l.sem
		return nil, err
	}
	return &limitConn{Conn: c, release: func() { <-l.sem }}, nil
}

func (l *limitListener) Close() error {
	l.once.Do(func() { close(l.done) })
	return l.Listener.Close()
}

type limitConn struct {
	net.Conn
	once    sync.Once
	release func()
}

func (c *limitConn) Close() error {
	err := c.Conn.Close()
	c.once.Do(c.release)
	return err
}
