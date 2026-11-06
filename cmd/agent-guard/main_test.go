package main

import (
	"bufio"
	"fmt"
	"io"
	"net"
	"net/http"
	"strings"
	"testing"
	"time"
)

func TestParseOptions(t *testing.T) {
	cases := []struct {
		name string
		args []string
		ok   bool
	}{
		{"defaults", nil, true},
		{"custom", []string{"-max-conns", "3", "-max-inflight", "2", "-max-response", "1m"}, true},
		{"zero conns", []string{"-max-conns", "0"}, false},
		{"negative inflight", []string{"-max-inflight", "-1"}, false},
		{"zero response", []string{"-max-response", "0s"}, false},
		{"unknown flag", []string{"-nope"}, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := parseOptions(tc.args, io.Discard)
			if (err == nil) != tc.ok {
				t.Fatalf("err = %v, want ok=%v", err, tc.ok)
			}
		})
	}
}

// TestProductionServer builds the real server the way main does and checks the wiring.
func TestProductionServer(t *testing.T) {
	o, err := parseOptions([]string{"-listen", "127.0.0.1:0", "-upstream", "http://127.0.0.1:1"}, io.Discard)
	if err != nil {
		t.Fatal(err)
	}
	srv, ln, err := newServer(o, nil)
	if err != nil {
		t.Fatal(err)
	}
	if got := fmt.Sprintf("%T", ln); got != "*proxy.limitListener" {
		t.Errorf("listener is %s, want the connection-limited listener", got)
	}
	if srv.MaxHeaderBytes != 64<<10 {
		t.Errorf("MaxHeaderBytes = %d", srv.MaxHeaderBytes)
	}
	go srv.Serve(ln)
	t.Cleanup(func() { srv.Close() })
	addr := ln.Addr().String()

	status := func(request string) int {
		t.Helper()
		conn, err := net.DialTimeout("tcp", addr, 5*time.Second)
		if err != nil {
			t.Fatal(err)
		}
		defer conn.Close()
		conn.SetDeadline(time.Now().Add(5 * time.Second))
		io.WriteString(conn, request)
		resp, err := http.ReadResponse(bufio.NewReader(conn), nil)
		if err != nil {
			t.Fatal(err)
		}
		resp.Body.Close()
		return resp.StatusCode
	}
	if got := status("GET / HTTP/1.1\r\nHost: t\r\nConnection: close\r\n\r\n"); got != 404 {
		t.Errorf("GET / = %d, want 404 from the proxy", got)
	}
	big := "GET / HTTP/1.1\r\nHost: t\r\nConnection: close\r\nX-Big: " + strings.Repeat("a", 70<<10) + "\r\n\r\n"
	if got := status(big); got != http.StatusRequestHeaderFieldsTooLarge {
		t.Errorf("oversized header = %d, want 431", got)
	}
}
