package main

import (
	"context"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// loopbackDial dials directly over loopback (no Tor), so runRequest is exercised
// fully offline.
func loopbackDial(ctx context.Context, network, address string) (net.Conn, error) {
	return (&net.Dialer{}).DialContext(ctx, network, address)
}

func TestRunRequestGET(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		fmt.Fprint(w, "hello tor")
	}))
	defer srv.Close()

	var out strings.Builder
	err := runRequest(context.Background(), loopbackDial, httpOptions{
		url:     srv.URL,
		method:  http.MethodGet,
		timeout: 10 * time.Second,
	}, &out)
	if err != nil {
		t.Fatalf("runRequest: %v", err)
	}
	if got := out.String(); got != "hello tor" {
		t.Fatalf("body = %q, want %q", got, "hello tor")
	}
}

func TestRunRequestIncludeHeaders(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("X-Test", "yes")
		fmt.Fprint(w, "body")
	}))
	defer srv.Close()

	var out strings.Builder
	err := runRequest(context.Background(), loopbackDial, httpOptions{
		url:            srv.URL,
		method:         http.MethodGet,
		includeHeaders: true,
		timeout:        10 * time.Second,
	}, &out)
	if err != nil {
		t.Fatalf("runRequest: %v", err)
	}
	s := out.String()
	if !strings.HasPrefix(s, "HTTP/1.1 200 OK") {
		t.Fatalf("output does not start with status line:\n%s", s)
	}
	if !strings.Contains(s, "X-Test: yes") {
		t.Fatalf("output missing header X-Test:\n%s", s)
	}
	if !strings.HasSuffix(s, "body") {
		t.Fatalf("output does not end with body:\n%s", s)
	}
}

func TestRunRequestPostData(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			t.Errorf("method = %s, want POST", r.Method)
		}
		b, _ := io.ReadAll(r.Body)
		w.Write(b)
	}))
	defer srv.Close()

	var out strings.Builder
	err := runRequest(context.Background(), loopbackDial, httpOptions{
		url:     srv.URL,
		method:  http.MethodPost,
		body:    []byte("payload"),
		timeout: 10 * time.Second,
	}, &out)
	if err != nil {
		t.Fatalf("runRequest: %v", err)
	}
	if got := out.String(); got != "payload" {
		t.Fatalf("echoed body = %q, want payload", got)
	}
}

func TestRunRequestOutputFile(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		fmt.Fprint(w, "filebody")
	}))
	defer srv.Close()

	path := filepath.Join(t.TempDir(), "out.txt")
	f, err := os.Create(path)
	if err != nil {
		t.Fatalf("create file: %v", err)
	}
	err = runRequest(context.Background(), loopbackDial, httpOptions{
		url:     srv.URL,
		method:  http.MethodGet,
		timeout: 10 * time.Second,
	}, f)
	_ = f.Close()
	if err != nil {
		t.Fatalf("runRequest: %v", err)
	}
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read file: %v", err)
	}
	if string(data) != "filebody" {
		t.Fatalf("file content = %q, want filebody", data)
	}
}

func TestRunRequestNon2xxStreamsBody(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusNotFound)
		fmt.Fprint(w, "not found")
	}))
	defer srv.Close()

	var out strings.Builder
	err := runRequest(context.Background(), loopbackDial, httpOptions{
		url:     srv.URL,
		method:  http.MethodGet,
		timeout: 10 * time.Second,
	}, &out)
	// Non-2xx is not a transport error: the body is streamed, no error returned.
	if err != nil {
		t.Fatalf("runRequest: %v", err)
	}
	if got := out.String(); got != "not found" {
		t.Fatalf("body = %q, want %q", got, "not found")
	}
}

func TestRunRequestCustomHeader(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, r.Header.Get("X-Foo"))
	}))
	defer srv.Close()

	var out strings.Builder
	err := runRequest(context.Background(), loopbackDial, httpOptions{
		url:     srv.URL,
		method:  http.MethodGet,
		headers: []string{"X-Foo: bar"},
		timeout: 10 * time.Second,
	}, &out)
	if err != nil {
		t.Fatalf("runRequest: %v", err)
	}
	if got := out.String(); got != "bar" {
		t.Fatalf("reflected header = %q, want bar", got)
	}
}

func TestRunRequestInvalidHeader(t *testing.T) {
	err := runRequest(context.Background(), loopbackDial, httpOptions{
		url:     "http://127.0.0.1:1/",
		method:  http.MethodGet,
		headers: []string{"no-colon-here"},
		timeout: time.Second,
	}, io.Discard)
	if err == nil {
		t.Fatal("want error for malformed header, got nil")
	}
}

func TestIsOnionURL(t *testing.T) {
	cases := []struct {
		url  string
		want bool
	}{
		{"https://duckduckgogg42xjoc72x3sjasowoarfbgcmvfimaftt6twagswzczad.onion/", true},
		{"http://EXAMPLE.ONION/path", true},
		{"http://example.onion:8080/", true},
		{"https://check.torproject.org/", false},
		{"https://onion.example.com/", false},
		{"not a url", false},
	}
	for _, tc := range cases {
		if got := isOnionURL(tc.url); got != tc.want {
			t.Errorf("isOnionURL(%q) = %v, want %v", tc.url, got, tc.want)
		}
	}
}

func TestResolveBody(t *testing.T) {
	if b, err := resolveBody(""); err != nil || b != nil {
		t.Fatalf("resolveBody(\"\") = (%v, %v), want (nil, nil)", b, err)
	}
	if b, err := resolveBody("hello"); err != nil || string(b) != "hello" {
		t.Fatalf("resolveBody literal = (%q, %v), want (hello, nil)", b, err)
	}
	path := filepath.Join(t.TempDir(), "body.txt")
	if err := os.WriteFile(path, []byte("filedata"), 0o600); err != nil {
		t.Fatalf("write file: %v", err)
	}
	if b, err := resolveBody("@" + path); err != nil || string(b) != "filedata" {
		t.Fatalf("resolveBody @file = (%q, %v), want (filedata, nil)", b, err)
	}
	if _, err := resolveBody("@/nonexistent/path/body.txt"); err == nil {
		t.Fatal("want error for missing body file, got nil")
	}
}
