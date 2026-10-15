package main

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strconv"
	"sync"
)

// SystemProxy points the whole computer at Sift and puts the old settings back afterwards.
// The previous settings are kept in ~/.sift/proxy-backup.json so they survive a crash.
type SystemProxy struct {
	mu     sync.Mutex
	backup string
}

func NewSystemProxy(home string) *SystemProxy {
	return &SystemProxy{backup: filepath.Join(home, "proxy-backup.json")}
}

func (sp *SystemProxy) Enable(port int, bypass string) error {
	sp.mu.Lock()
	defer sp.mu.Unlock()
	if _, err := os.Stat(sp.backup); err != nil {
		data, _ := json.Marshal(readProxySettings())
		if err := os.WriteFile(sp.backup, data, 0o644); err != nil {
			return err
		}
	}
	return platformEnableProxy("127.0.0.1", port, bypass)
}

// Disable restores whatever was configured before Sift switched the proxy on.
func (sp *SystemProxy) Disable() bool {
	sp.mu.Lock()
	defer sp.mu.Unlock()
	data, err := os.ReadFile(sp.backup)
	if err != nil {
		return false
	}
	prev := map[string]any{}
	_ = json.Unmarshal(data, &prev)
	if platformRestoreProxy(prev) == nil {
		_ = os.Remove(sp.backup)
	}
	return true
}

func itoa(n int) string { return strconv.Itoa(n) }
