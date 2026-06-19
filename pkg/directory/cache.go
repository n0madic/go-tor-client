package directory

import (
	"os"
	"path/filepath"
	"strings"
	"sync"
)

// Cache is a best-effort key/value store for directory documents (the
// consensus, authority certificates, and microdescriptors) used to speed up
// bootstrap across runs. Keys are opaque, slash-delimited strings such as
// "consensus", "certs", or "md/<hash>". Implementations must be safe for
// concurrent use; Put is best-effort and may silently drop writes.
type Cache interface {
	Get(key string) ([]byte, bool)
	Put(key string, data []byte)
}

// DiskCache implements Cache on the local filesystem, one file per key.
type DiskCache struct {
	dir string
	mu  sync.Mutex
}

// NewDiskCache returns a DiskCache rooted at dir, creating it if needed.
func NewDiskCache(dir string) (*DiskCache, error) {
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return nil, err
	}
	return &DiskCache{dir: filepath.Clean(dir)}, nil
}

// Get returns the cached bytes for key, or (nil, false) if absent.
func (d *DiskCache) Get(key string) ([]byte, bool) {
	p, ok := d.path(key)
	if !ok {
		return nil, false
	}
	b, err := os.ReadFile(p)
	if err != nil {
		return nil, false
	}
	return b, true
}

// Put atomically writes data for key (best effort: write errors are ignored).
func (d *DiskCache) Put(key string, data []byte) {
	d.mu.Lock()
	defer d.mu.Unlock()
	p, ok := d.path(key)
	if !ok {
		return
	}
	if err := os.MkdirAll(filepath.Dir(p), 0o700); err != nil {
		return
	}
	tmp := p + ".tmp"
	if err := os.WriteFile(tmp, data, 0o600); err != nil {
		return
	}
	_ = os.Rename(tmp, p)
}

// path maps a key to its on-disk file, returning ok=false if the result would
// escape the cache root (defense in depth against a crafted key).
func (d *DiskCache) path(key string) (string, bool) {
	prefix, rest, ok := strings.Cut(key, "/")
	var p string
	if !ok {
		p = filepath.Join(d.dir, sanitizeKey(key))
	} else {
		p = filepath.Join(d.dir, sanitizeKey(prefix), sanitizeKey(rest))
	}
	// Confirm the cleaned path stays within d.dir, never above or outside it.
	if p != d.dir && !strings.HasPrefix(p, d.dir+string(filepath.Separator)) {
		return "", false
	}
	return p, true
}

// sanitizeKey maps a key segment to a filesystem-safe name (microdescriptor
// hashes are base64 and may contain '/' and '+'). Path separators and parent
// references are neutralized so a segment can never traverse directories.
func sanitizeKey(s string) string {
	return strings.NewReplacer(
		"/", "_",
		`\`, "_",
		"+", "-",
		"..", "__",
	).Replace(s)
}
