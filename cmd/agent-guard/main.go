// Command agent-guard runs the policy proxy.
package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/signal"
	"syscall"
	"time"

	"agent-guard/internal/policy"
	"agent-guard/internal/proxy"
)

type options struct {
	listen          string
	upstream        string
	decideTimeout   time.Duration
	upstreamTimeout time.Duration
	maxResponse     time.Duration
	maxInflight     int
	maxConns        int
}

func parseOptions(args []string, out io.Writer) (options, error) {
	var o options
	fs := flag.NewFlagSet("agent-guard", flag.ContinueOnError)
	fs.SetOutput(out)
	fs.StringVar(&o.listen, "listen", "127.0.0.1:8787", "address to listen on")
	fs.StringVar(&o.upstream, "upstream", "https://api.anthropic.com", "upstream API base URL")
	fs.DurationVar(&o.decideTimeout, "decide-timeout", 5*time.Second, "per-decision timeout")
	fs.DurationVar(&o.upstreamTimeout, "upstream-timeout", 30*time.Second, "wait for upstream response headers")
	fs.DurationVar(&o.maxResponse, "max-response", 10*time.Minute, "absolute limit on one upstream exchange")
	fs.IntVar(&o.maxInflight, "max-inflight", 64, "concurrent requests before answering 503")
	fs.IntVar(&o.maxConns, "max-conns", 256, "concurrent accepted connections")
	if err := fs.Parse(args); err != nil {
		return options{}, err
	}
	if o.maxInflight <= 0 || o.maxConns <= 0 || o.maxResponse <= 0 {
		return options{}, errors.New("-max-inflight, -max-conns and -max-response must be positive")
	}
	return o, nil
}

// newServer builds the production server and its listener. The caller serves and shuts it down.
func newServer(o options, log *slog.Logger) (*http.Server, net.Listener, error) {
	u, err := url.Parse(o.upstream)
	if err != nil {
		return nil, nil, fmt.Errorf("bad -upstream: %w", err)
	}
	// Phase 2: no rules engine yet, so every tool call is denied (fail closed).
	p, err := proxy.New(proxy.Config{
		Upstream:            u,
		Decider:             policy.DenyAll{},
		Logger:              log,
		DecideTimeout:       o.decideTimeout,
		UpstreamTimeout:     o.upstreamTimeout,
		MaxResponseDuration: o.maxResponse,
		MaxInflightRequests: o.maxInflight,
	})
	if err != nil {
		return nil, nil, err
	}
	ln, err := net.Listen("tcp", o.listen)
	if err != nil {
		return nil, nil, err
	}
	ln, err = proxy.LimitListener(ln, o.maxConns)
	if err != nil {
		return nil, nil, err
	}
	srv := &http.Server{
		Handler:           p,
		ReadHeaderTimeout: 10 * time.Second,
		IdleTimeout:       2 * time.Minute,
		MaxHeaderBytes:    64 << 10,
	}
	return srv, ln, nil
}

func main() {
	log := slog.New(slog.NewTextHandler(os.Stderr, nil))
	o, err := parseOptions(os.Args[1:], os.Stderr)
	if err != nil {
		if errors.Is(err, flag.ErrHelp) {
			os.Exit(0)
		}
		os.Exit(2)
	}
	srv, ln, err := newServer(o, log)
	if err != nil {
		log.Error("startup", "err", err)
		os.Exit(1)
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	errc := make(chan error, 1)
	go func() { errc <- srv.Serve(ln) }()
	log.Info("listening", "addr", ln.Addr().String(), "upstream", o.upstream)

	select {
	case err := <-errc:
		log.Error("serve", "err", err)
		os.Exit(1)
	case <-ctx.Done():
	}
	sctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if err := srv.Shutdown(sctx); err != nil && !errors.Is(err, http.ErrServerClosed) {
		log.Error("shutdown", "err", err)
		os.Exit(1)
	}
}
