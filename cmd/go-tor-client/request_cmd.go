package main

import (
	"bytes"
	"context"
	"crypto/tls"
	"errors"
	"flag"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"

	tor "github.com/n0madic/go-tor-client"
)

// onionDefaultTimeout is the implicit timeout for a .onion request when the user
// does not pass -timeout. The onion flow (HSDir hash-ring over the full
// microdescriptor set, descriptor fetch, intro + rendezvous) is much slower than
// a clearnet dial — especially cold, without a warm -datadir cache — so it needs
// far more headroom than the 60s clearnet default.
const onionDefaultTimeout = 3 * time.Minute

// headerList collects repeatable -H flags into a slice.
type headerList []string

func (h *headerList) String() string { return strings.Join(*h, ", ") }

func (h *headerList) Set(v string) error {
	*h = append(*h, v)
	return nil
}

// httpOptions is the transport-agnostic input to runRequest.
type httpOptions struct {
	url            string
	method         string
	headers        []string
	body           []byte
	includeHeaders bool
	timeout        time.Duration
}

// runRequestCmd runs the curl-like request subcommand: it parses flags, builds a
// default Tor client, and performs the request directly through Tor.
func runRequestCmd(ctx context.Context, args []string) error {
	fs := flag.NewFlagSet("request", flag.ContinueOnError)
	method := fs.String("X", "", "HTTP method (default GET, or POST when -d is given)")
	var headers headerList
	fs.Var(&headers, "H", "extra request header 'Key: Value' (repeatable)")
	data := fs.String("d", "", "request body; @file reads the body from a file")
	output := fs.String("o", "", "write the response body to FILE instead of stdout")
	include := fs.Bool("i", false, "include the response status line and headers in the output")
	timeout := fs.Duration("timeout", 60*time.Second, "overall request timeout (0 = none); .onion URLs default to 3m")
	dataDir := fs.String("datadir", "", "directory for guard persistence and on-disk directory cache (empty = no persistence)")
	logLevel := fs.String("log-level", "info", "log level: debug|info|warn|error")
	if err := fs.Parse(args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return nil
		}
		return err
	}
	if fs.NArg() < 1 {
		return errors.New("request: missing URL argument")
	}

	body, err := resolveBody(*data)
	if err != nil {
		return err
	}
	m := *method
	if m == "" {
		if body != nil {
			m = http.MethodPost
		} else {
			m = http.MethodGet
		}
	}

	logger := buildLogger(*logLevel)

	// The onion flow is far slower than a clearnet dial, so give .onion URLs a
	// larger implicit timeout — but only when the user did not set -timeout.
	to := *timeout
	if !flagSet(fs, "timeout") && isOnionURL(fs.Arg(0)) && to > 0 && to < onionDefaultTimeout {
		to = onionDefaultTimeout
		logger.Info("onion URL: using extended default timeout", "timeout", to)
	}

	opts := httpOptions{
		url:            fs.Arg(0),
		method:         m,
		headers:        headers,
		body:           body,
		includeHeaders: *include,
		timeout:        to,
	}

	logger.Info("bootstrapping Tor client")
	client, err := tor.NewClient(ctx, &tor.Config{DataDir: *dataDir, Logger: logger})
	if err != nil {
		return fmt.Errorf("bootstrap tor client: %w", err)
	}
	defer client.Close()

	out := io.Writer(os.Stdout)
	if *output != "" {
		f, err := os.Create(*output)
		if err != nil {
			return fmt.Errorf("create output file: %w", err)
		}
		defer f.Close()
		out = f
	}

	return runRequest(ctx, client.DialContext, opts, out)
}

// flagSet reports whether the named flag was explicitly provided on the command
// line (as opposed to left at its default).
func flagSet(fs *flag.FlagSet, name string) bool {
	found := false
	fs.Visit(func(f *flag.Flag) {
		if f.Name == name {
			found = true
		}
	})
	return found
}

// isOnionURL reports whether raw is an HTTP(S) URL whose host is a .onion
// address.
func isOnionURL(raw string) bool {
	u, err := url.Parse(raw)
	if err != nil {
		return false
	}
	return strings.HasSuffix(strings.ToLower(u.Hostname()), ".onion")
}

// resolveBody returns the request body for the -d flag value: nil if empty, the
// file contents for "@path", otherwise the literal string.
func resolveBody(d string) ([]byte, error) {
	if d == "" {
		return nil, nil
	}
	if strings.HasPrefix(d, "@") {
		b, err := os.ReadFile(d[1:])
		if err != nil {
			return nil, fmt.Errorf("read body file: %w", err)
		}
		return b, nil
	}
	return []byte(d), nil
}

// runRequest performs an HTTP request using dial as the transport's DialContext,
// writing the response body — and, when o.includeHeaders, the status line and
// headers first — to out. It is transport-agnostic and offline-testable: the
// caller supplies dial (e.g. *tor.Client.DialContext). The transport mirrors the
// one in the library's live tests.
func runRequest(
	ctx context.Context,
	dial func(ctx context.Context, network, address string) (net.Conn, error),
	o httpOptions,
	out io.Writer,
) error {
	if o.timeout > 0 {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, o.timeout)
		defer cancel()
	}

	transport := &http.Transport{
		DialContext:           dial,
		TLSClientConfig:       &tls.Config{MinVersion: tls.VersionTLS12},
		TLSHandshakeTimeout:   o.timeout,
		ResponseHeaderTimeout: o.timeout,
		DisableKeepAlives:     true,
	}

	var bodyReader io.Reader
	if o.body != nil {
		bodyReader = bytes.NewReader(o.body)
	}
	req, err := http.NewRequestWithContext(ctx, o.method, o.url, bodyReader)
	if err != nil {
		return fmt.Errorf("build request: %w", err)
	}
	for _, h := range o.headers {
		key, value, ok := strings.Cut(h, ":")
		if !ok {
			return fmt.Errorf("invalid header %q (want 'Key: Value')", h)
		}
		key, value = strings.TrimSpace(key), strings.TrimSpace(value)
		// The Host header must be set on req.Host; Header.Set is ignored for it.
		if strings.EqualFold(key, "Host") {
			req.Host = value
			continue
		}
		req.Header.Set(key, value)
	}

	resp, err := (&http.Client{Transport: transport}).Do(req)
	if err != nil {
		return fmt.Errorf("request: %w", err)
	}
	defer resp.Body.Close()

	if o.includeHeaders {
		if err := writeStatusAndHeaders(out, resp); err != nil {
			return err
		}
	}
	if _, err := io.Copy(out, resp.Body); err != nil {
		return fmt.Errorf("read response body: %w", err)
	}
	return nil
}

// writeStatusAndHeaders writes the HTTP status line and response headers to w,
// followed by a blank line, mirroring `curl -i`.
func writeStatusAndHeaders(w io.Writer, resp *http.Response) error {
	var b strings.Builder
	fmt.Fprintf(&b, "%s %s\r\n", resp.Proto, resp.Status)
	if err := resp.Header.Write(&b); err != nil {
		return err
	}
	b.WriteString("\r\n")
	_, err := io.WriteString(w, b.String())
	return err
}
