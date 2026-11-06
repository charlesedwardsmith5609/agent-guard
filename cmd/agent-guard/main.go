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

	"agent-guard/internal/audit"
	"agent-guard/internal/proxy"
	"agent-guard/internal/rules"
	"agent-guard/internal/telemetry"
)

type options struct {
	config          string
	auditLog        string
	auditPreview    bool
	otel            string
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
	fs.StringVar(&o.config, "config", "", "path to the YAML policy file (required)")
	fs.StringVar(&o.auditLog, "audit-log", "", "path of the JSONL audit log (required; created with mode 0600)")
	fs.BoolVar(&o.auditPreview, "audit-preview", true, "include a redacted argument preview in audit records (false: hash only)")
	fs.StringVar(&o.otel, "otel", "none", "span output: none or stdout (stderr)")
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
	if o.config == "" {
		return options{}, errors.New("-config is required")
	}
	if o.auditLog == "" {
		return options{}, errors.New("-audit-log is required")
	}
	if o.otel != "none" && o.otel != "stdout" {
		return options{}, errors.New("-otel must be none or stdout")
	}
	if o.maxInflight <= 0 || o.maxConns <= 0 || o.maxResponse <= 0 {
		return options{}, errors.New("-max-inflight, -max-conns and -max-response must be positive")
	}
	return o, nil
}

// newServer builds the production server and its listener. The returned shutdown function
// drains the audit log and flushes telemetry; call it after the server has stopped.
func newServer(o options, log *slog.Logger, spans io.Writer) (*http.Server, net.Listener, func(context.Context) error, error) {
	u, err := url.Parse(o.upstream)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("bad -upstream: %w", err)
	}
	engine, err := rules.Load(o.config)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("loading %s: %w", o.config, err)
	}
	auditLog, err := audit.Open(o.auditLog, audit.Options{NoPreview: !o.auditPreview})
	if err != nil {
		return nil, nil, nil, err
	}
	tp, flushSpans, err := telemetry.Setup(o.otel, spans)
	if err != nil {
		auditLog.Close(context.Background())
		return nil, nil, nil, err
	}
	shutdown := func(ctx context.Context) error {
		return errors.Join(auditLog.Close(ctx), flushSpans(ctx))
	}
	fail := func(err error) (*http.Server, net.Listener, func(context.Context) error, error) {
		shutdown(context.Background())
		return nil, nil, nil, err
	}
	cfg := proxy.Config{
		Upstream:            u,
		Decider:             engine,
		Audit:               auditLog,
		Logger:              log,
		DecideTimeout:       o.decideTimeout,
		UpstreamTimeout:     o.upstreamTimeout,
		MaxResponseDuration: o.maxResponse,
		MaxInflightRequests: o.maxInflight,
	}
	if o.otel != "none" {
		cfg.Telemetry = telemetry.NewObserver(tp)
	}
	p, err := proxy.New(cfg)
	if err != nil {
		return fail(err)
	}
	ln, err := net.Listen("tcp", o.listen)
	if err != nil {
		return fail(err)
	}
	limited, err := proxy.LimitListener(ln, o.maxConns)
	if err != nil {
		ln.Close()
		return fail(err)
	}
	srv := &http.Server{
		Handler:           p,
		ReadHeaderTimeout: 10 * time.Second,
		IdleTimeout:       2 * time.Minute,
		MaxHeaderBytes:    64 << 10,
	}
	return srv, limited, shutdown, nil
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
	srv, ln, closeSinks, err := newServer(o, log, os.Stderr)
	if err != nil {
		log.Error("startup", "err", err)
		os.Exit(1)
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	errc := make(chan error, 1)
	go func() { errc <- srv.Serve(ln) }()
	// Log scheme and host only: the URL could carry credentials in its userinfo or query.
	upstreamHost := "(unparsed)"
	if u, err := url.Parse(o.upstream); err == nil {
		upstreamHost = u.Scheme + "://" + u.Host
	}
	log.Info("listening", "addr", ln.Addr().String(), "upstream", upstreamHost)

	exit := 0
	select {
	case err := <-errc:
		log.Error("serve", "err", err)
		exit = 1
	case <-ctx.Done():
	}
	// Stop the server first, force-closing stragglers after the deadline, then drain the audit
	// log and flush spans under a fresh deadline so a slow shutdown cannot starve the drain.
	sctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	if err := srv.Shutdown(sctx); err != nil && !errors.Is(err, http.ErrServerClosed) {
		log.Error("shutdown", "err", err)
		srv.Close()
		exit = 1
	}
	cancel()
	dctx, dcancel := context.WithTimeout(context.Background(), 10*time.Second)
	if err := closeSinks(dctx); err != nil {
		log.Error("closing audit log or telemetry", "err", err)
		exit = 1
	}
	dcancel()
	os.Exit(exit)
}
