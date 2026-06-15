package directory

import (
	"bytes"
	"os"
	"path/filepath"
	"testing"
)

func TestDiskCacheRoundTrip(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	dc, err := NewDiskCache(dir)
	if err != nil {
		t.Fatalf("NewDiskCache: %v", err)
	}

	cases := map[string][]byte{
		"consensus":            bytes.Repeat([]byte{0x01}, 100),
		"certs":                []byte("cert data"),
		"md/AbC+d/eF12":        []byte("microdesc-1"), // base64-ish key with / and +
		"md/zzz999AAAbbbCCCdd": []byte("microdesc-2"),
	}
	for k, v := range cases {
		dc.Put(k, v)
	}
	for k, want := range cases {
		got, ok := dc.Get(k)
		if !ok {
			t.Errorf("Get(%q) miss", k)
			continue
		}
		if !bytes.Equal(got, want) {
			t.Errorf("Get(%q) = %q, want %q", k, got, want)
		}
	}

	if _, ok := dc.Get("absent"); ok {
		t.Error("Get(absent) should miss")
	}

	// "md/" keys must live in an md/ subdirectory, sanitized.
	if entries, _ := os.ReadDir(filepath.Join(dir, "md")); len(entries) != 2 {
		t.Errorf("md subdir has %d entries, want 2", len(entries))
	}
	// No leftover temp files.
	top, _ := os.ReadDir(dir)
	for _, e := range top {
		if filepath.Ext(e.Name()) == ".tmp" {
			t.Errorf("leftover temp file %s", e.Name())
		}
	}
}

// mapCache is an in-memory Cache for testing the client cache paths.
type mapCache struct{ m map[string][]byte }

func newMapCache() *mapCache { return &mapCache{m: map[string][]byte{}} }

func (c *mapCache) Get(k string) ([]byte, bool) { v, ok := c.m[k]; return v, ok }
func (c *mapCache) Put(k string, v []byte)      { c.m[k] = append([]byte(nil), v...) }

func TestMicrodescCacheServesAndStores(t *testing.T) {
	t.Parallel()
	// A minimal valid microdescriptor (only ntor-onion-key is required to parse).
	md := "onion-key\nntor-onion-key " +
		"WBdr+sXgyfVasjhOAxJZRf6/c7C4nN7C9aaW/n8RbV0\n"
	mds := ParseMicrodescriptors([]byte(md))
	if len(mds) != 1 {
		t.Fatalf("fixture parse produced %d microdescs", len(mds))
	}
	hash := mds[0].Digest

	cache := newMapCache()
	cache.Put("md/"+hash, mds[0].Raw)

	c := NewClient(nil, nil)
	c.UseCache(cache)

	// Cache hit must avoid the network entirely (no authorities reachable here).
	out, err := c.FetchMicrodescriptors(t.Context(), []string{hash})
	if err != nil {
		t.Fatalf("FetchMicrodescriptors (cached): %v", err)
	}
	if _, ok := out[hash]; !ok {
		t.Fatalf("cached microdescriptor not returned")
	}
}
