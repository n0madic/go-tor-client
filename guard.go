package tor

import (
	"encoding/hex"
	"log/slog"
	"os"
	"path/filepath"
	"strings"

	"github.com/n0madic/go-tor-client/pkg/directory"
)

// resolveCache picks the directory cache for a client: an explicit Config.Cache
// wins; otherwise a DataDir yields an on-disk cache; otherwise caching is off.
func resolveCache(cfg *Config, log *slog.Logger) directory.Cache {
	if cfg.Cache != nil {
		return cfg.Cache
	}
	if cfg.DataDir == "" {
		return nil
	}
	dc, err := directory.NewDiskCache(filepath.Join(cfg.DataDir, "cache"))
	if err != nil {
		log.Warn("tor: disk cache unavailable", "err", err)
		return nil
	}
	return dc
}

const guardFileName = "guard"

// loadGuard reads a persisted guard identity (hex) from the data dir, or "".
func loadGuard(dataDir string) string {
	if dataDir == "" {
		return ""
	}
	b, err := os.ReadFile(filepath.Join(dataDir, guardFileName))
	if err != nil {
		return ""
	}
	return strings.TrimSpace(string(b))
}

// saveGuard persists the guard identity (hex) to the data dir; errors are
// ignored since guard persistence is best-effort.
func saveGuard(dataDir string, identity []byte) {
	if dataDir == "" {
		return
	}
	_ = os.MkdirAll(dataDir, 0o700)
	_ = os.WriteFile(filepath.Join(dataDir, guardFileName), []byte(hex.EncodeToString(identity)), 0o600)
}
