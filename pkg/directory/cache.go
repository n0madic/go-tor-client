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
	return &DiskCache{dir: dir}, nil
}

// Get returns the cached bytes for key, or (nil, false) if absent.
func (d *DiskCache) Get(key string) ([]byte, bool) {
	b, err := os.ReadFile(d.path(key))
	if err != nil {
		return nil, false
	}
	return b, true
}

// Put atomically writes data for key (best effort: write errors are ignored).
func (d *DiskCache) Put(key string, data []byte) {
	d.mu.Lock()
	defer d.mu.Unlock()
	p := d.path(key)
	if err := os.MkdirAll(filepath.Dir(p), 0o700); err != nil {
		return
	}
	tmp := p + ".tmp"
	if err := os.WriteFile(tmp, data, 0o600); err != nil {
		return
	}
	_ = os.Rename(tmp, p)
}

func (d *DiskCache) path(key string) string {
	prefix, rest, ok := strings.Cut(key, "/")
	if !ok {
		return filepath.Join(d.dir, sanitizeKey(key))
	}
	return filepath.Join(d.dir, sanitizeKey(prefix), sanitizeKey(rest))
}

// sanitizeKey maps a key segment to a filesystem-safe name (microdescriptor
// hashes are base64 and may contain '/' and '+').
func sanitizeKey(s string) string {
	return strings.NewReplacer("/", "_", "+", "-", "..", "__").Replace(s)
}
