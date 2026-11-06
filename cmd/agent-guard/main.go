// Command agent-guard runs the policy proxy.
package main

import (
	"context"
	"errors"
	"flag"
	"log/slog"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/signal"
	"time"

	"agent-guard/internal/policy"
	"agent-guard/internal/proxy"
)

func main() {
	listen := flag.String("listen", "127.0.0.1:8787", "address to listen on")
	upstream := flag.String("upstream", "https://api.anthropic.com", "upstream API base URL")
	decideTimeout := flag.Duration("decide-timeout", 5*time.Second, "per-decision timeout")
	upstreamTimeout := flag.Duration("upstream-timeout", 30*time.Second, "wait for upstream response headers")
	flag.Parse()

	log := slog.New(slog.NewTextHandler(os.Stderr, nil))
	u, err := url.Parse(*upstream)
	if err != nil {
		log.Error("bad -upstream", "err", err)
		os.Exit(2)
	}
	// Phase 2: no rules engine yet, so every tool call is denied (fail closed).
	p, err := proxy.New(proxy.Config{
		Upstream:        u,
		Decider:         policy.DenyAll{},
		Logger:          log,
		DecideTimeout:   *decideTimeout,
		UpstreamTimeout: *upstreamTimeout,
	})
	if err != nil {
		log.Error("config", "err", err)
		os.Exit(2)
	}
	ln, err := net.Listen("tcp", *listen)
	if err != nil {
		log.Error("listen", "err", err)
		os.Exit(1)
	}
	srv := &http.Server{Handler: p, ReadHeaderTimeout: 10 * time.Second, IdleTimeout: 2 * time.Minute}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt)
	defer stop()
	errc := make(chan error, 1)
	go func() { errc <- srv.Serve(ln) }()
	log.Info("listening", "addr", ln.Addr().String(), "upstream", u.Redacted())

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
