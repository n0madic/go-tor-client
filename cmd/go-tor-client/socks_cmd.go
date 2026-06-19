package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"net"

	tor "github.com/n0madic/go-tor-client"
	"github.com/n0madic/go-tor-client/pkg/socks"
)

// runSocks runs the SOCKS5 proxy subcommand: it bootstraps a default Tor client,
// builds a per-identity client pool for SOCKS-auth isolation, and serves until
// ctx is cancelled.
func runSocks(ctx context.Context, args []string) error {
	fs := flag.NewFlagSet("socks", flag.ContinueOnError)
	listen := fs.String("listen", "127.0.0.1:1080", "address to listen on for SOCKS5 connections")
	dataDir := fs.String("datadir", "", "directory for guard persistence and on-disk directory cache (empty = no persistence)")
	logLevel := fs.String("log-level", "info", "log level: debug|info|warn|error")
	if err := fs.Parse(args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return nil
		}
		return err
	}

	logger := buildLogger(*logLevel)
	cfg := &tor.Config{DataDir: *dataDir, Logger: logger}

	// Bootstrap a default client up front so a bootstrap failure surfaces before
	// we start listening.
	logger.Info("bootstrapping Tor client")
	base, err := tor.NewClient(ctx, cfg)
	if err != nil {
		return fmt.Errorf("bootstrap tor client: %w", err)
	}

	pool := newClientPool(cfg, base)
	defer pool.closeAll()

	ln, err := net.Listen("tcp", *listen)
	if err != nil {
		return fmt.Errorf("listen on %s: %w", *listen, err)
	}
	defer ln.Close()
	logger.Info("SOCKS5 proxy listening", "addr", ln.Addr())
	warnIfPublicListener(logger, ln.Addr())

	srv := &socks.Server{Factory: pool.dialer, Logger: logger}
	return srv.Serve(ctx, ln)
}
