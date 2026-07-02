package conf

import "testing"

func TestDefaultConfigCdnIndexRefreshInterval(t *testing.T) {
	cfg := DefaultConfig(t.TempDir())
	if cfg.CdnIndexRefreshInterval != 60 {
		t.Fatalf("expected default CDN index refresh interval to be 60, got %d", cfg.CdnIndexRefreshInterval)
	}
}
