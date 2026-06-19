// Command go-tor-client is a command-line front end for the pure-Go Tor client.
// It offers two subcommands:
//
//	socks     run a local SOCKS5 proxy that tunnels TCP through Tor
//	request   fetch an HTTP(S) URL directly through Tor (curl-like)
//
// Logs are written to stderr so a request body printed to stdout stays clean.
package main

import (
	"context"
	"fmt"
	"log/slog"
	"net"
	"os"
	"os/signal"
	"strings"
	"syscall"
)

func main() {
	if len(os.Args) < 2 {
		usage()
		os.Exit(2)
	}

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	var err error
	switch os.Args[1] {
	case "socks":
		err = runSocks(ctx, os.Args[2:])
	case "http":
		err = runHTTP(ctx, os.Args[2:])
	case "request":
		err = runRequestCmd(ctx, os.Args[2:])
	case "-h", "--help", "help":
		usage()
		return
	default:
		fmt.Fprintf(os.Stderr, "unknown subcommand %q\n\n", os.Args[1])
		usage()
		os.Exit(2)
	}
	if err != nil {
		fmt.Fprintln(os.Stderr, "error:", err)
		os.Exit(1)
	}
}

func usage() {
	fmt.Fprint(os.Stderr, `go-tor-client — pure-Go Tor client CLI

Usage:
  go-tor-client socks   [-listen 127.0.0.1:1080] [-datadir DIR] [-log-level info]
  go-tor-client http    [-listen 127.0.0.1:8080] [-datadir DIR] [-log-level info]
  go-tor-client request [-X METHOD] [-H 'K: V']... [-d DATA|@file] [-o FILE] [-i]
                        [-timeout 60s] [-datadir DIR] [-log-level info]  URL

Subcommands:
  socks     run a local SOCKS5 proxy that tunnels TCP through Tor
  http      run a local HTTP proxy (CONNECT + forwarding) through Tor
  request   fetch an HTTP(S) URL directly through Tor (curl-like)

Run "go-tor-client <subcommand> -h" for per-subcommand flags.
`)
}

// warnIfPublicListener logs a prominent warning when a proxy is bound to a
// non-loopback address. The proxies perform NO client authentication (the
// credentials are isolation tokens, not validated secrets), so a non-loopback
// bind is an open proxy that anyone who can reach the address may use to route
// traffic through the host's Tor circuits.
func warnIfPublicListener(logger *slog.Logger, addr net.Addr) {
	host, _, err := net.SplitHostPort(addr.String())
	if err != nil {
		return
	}
	if ip := net.ParseIP(host); ip == nil || ip.IsLoopback() {
		return
	}
	logger.Warn("proxy bound to a non-loopback address with NO authentication: "+
		"anyone who can reach this address can route traffic through your Tor circuits",
		"addr", addr.String())
}

// buildLogger returns a stderr text logger at the named level (debug|info|warn|
// error), defaulting to info for an unrecognized name.
func buildLogger(level string) *slog.Logger {
	var lvl slog.Level
	switch strings.ToLower(level) {
	case "debug":
		lvl = slog.LevelDebug
	case "warn", "warning":
		lvl = slog.LevelWarn
	case "error":
		lvl = slog.LevelError
	default:
		lvl = slog.LevelInfo
	}
	return slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: lvl}))
}
