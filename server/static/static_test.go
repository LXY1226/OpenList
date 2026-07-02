package static

import (
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/OpenListTeam/OpenList/v4/drivers/base"
	"github.com/OpenListTeam/OpenList/v4/internal/conf"
	"github.com/OpenListTeam/OpenList/v4/internal/model"
	"github.com/OpenListTeam/OpenList/v4/internal/op"
	"github.com/go-resty/resty/v2"
)

func setupStaticTest(t *testing.T) {
	t.Helper()

	oldConf := conf.Conf
	oldURL := conf.URL
	oldRawIndex := conf.RawIndexHtml
	oldManageHtml := conf.ManageHtml
	oldIndexHtml := conf.IndexHtml
	oldWebVersion := conf.WebVersion
	oldRestyClient := base.RestyClient
	oldLastAttempt := cdnIndexLastAttempt
	oldRefreshing := cdnIndexRefreshing

	conf.Conf = &conf.Config{CdnIndexRefreshInterval: 60}
	conf.URL = &url.URL{Path: "/"}
	conf.WebVersion = "v1.2.3"
	base.RestyClient = resty.New()
	cdnIndexLastAttempt = time.Time{}
	cdnIndexRefreshing = false
	op.SettingCacheUpdate()
	cacheSetting(conf.Favicon, "favicon")
	cacheSetting(conf.Logo, "logo")
	cacheSetting(conf.SiteTitle, "title")
	cacheSetting(conf.CustomizeHead, "head")
	cacheSetting(conf.CustomizeBody, "body")
	cacheSetting(conf.MainColor, "#1890ff")

	t.Cleanup(func() {
		conf.Conf = oldConf
		conf.URL = oldURL
		conf.RawIndexHtml = oldRawIndex
		conf.ManageHtml = oldManageHtml
		conf.IndexHtml = oldIndexHtml
		conf.WebVersion = oldWebVersion
		base.RestyClient = oldRestyClient
		cdnIndexLastAttempt = oldLastAttempt
		cdnIndexRefreshing = oldRefreshing
		op.SettingCacheUpdate()
	})
}

func cacheSetting(key, value string) {
	op.Cache.SetSetting(key, &model.SettingItem{Key: key, Value: value})
}

func waitFor(t *testing.T, condition func() bool) {
	t.Helper()
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		if condition() {
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatal("condition was not met before timeout")
}

func testIndex(mark string) string {
	return `<html><head><link rel="manifest" href="/manifest.json"><script>cdn: undefined;base_path: undefined;main_color: undefined;</script><!-- customize head --></head><body>` +
		mark + ` Loading... https://res.oplist.org/logo/logo.svg https://res.oplist.org/logo/logo.png <!-- customize body --></body></html>`
}

func TestInitIndexFetchesCdnForReleaseVersion(t *testing.T) {
	setupStaticTest(t)

	var requests atomic.Int32
	var badPath atomic.Bool
	cdn := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requests.Add(1)
		if r.URL.Path != "/index.html" {
			badPath.Store(true)
		}
		_, _ = w.Write([]byte(testIndex("remote-startup")))
	}))
	defer cdn.Close()

	conf.Conf.Cdn = cdn.URL
	siteConfig := getSiteConfig()
	initIndex(siteConfig)

	if requests.Load() != 1 {
		t.Fatalf("expected 1 CDN request, got %d", requests.Load())
	}
	if badPath.Load() {
		t.Fatal("expected CDN request path to be /index.html")
	}
	if !strings.Contains(conf.IndexHtml, "remote-startup") {
		t.Fatalf("expected CDN index to be cached, got %q", conf.IndexHtml)
	}
	if !strings.Contains(conf.IndexHtml, "cdn: '"+cdn.URL+"'") {
		t.Fatalf("expected CDN placeholder to be replaced, got %q", conf.IndexHtml)
	}
}

func TestRuntimeRefreshUpdatesCachedIndex(t *testing.T) {
	setupStaticTest(t)

	cdn := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(testIndex("remote-refresh")))
	}))
	defer cdn.Close()

	conf.Conf.Cdn = cdn.URL
	conf.Conf.CdnIndexRefreshInterval = 1
	siteConfig := getSiteConfig()
	applyBaseIndex(siteConfig, testIndex("old-index"))
	cdnIndexLastAttempt = time.Now().Add(-2 * time.Second)

	maybeRefreshCdnIndex(siteConfig)

	waitFor(t, func() bool {
		return strings.Contains(currentIndexHtml("/"), "remote-refresh")
	})
}

func TestRuntimeRefreshFailureKeepsCachedIndex(t *testing.T) {
	setupStaticTest(t)

	cdn := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "nope", http.StatusBadGateway)
	}))
	defer cdn.Close()

	conf.Conf.Cdn = cdn.URL
	conf.Conf.CdnIndexRefreshInterval = 1
	siteConfig := getSiteConfig()
	applyBaseIndex(siteConfig, testIndex("old-index"))
	cdnIndexLastAttempt = time.Now().Add(-2 * time.Second)

	maybeRefreshCdnIndex(siteConfig)

	waitFor(t, func() bool {
		cdnIndexRefreshMu.Lock()
		defer cdnIndexRefreshMu.Unlock()
		return !cdnIndexRefreshing
	})
	if !strings.Contains(currentIndexHtml("/"), "old-index") {
		t.Fatalf("expected old index to remain cached, got %q", currentIndexHtml("/"))
	}
}

func TestRuntimeRefreshIntervalAndSingleflight(t *testing.T) {
	setupStaticTest(t)

	started := make(chan struct{})
	release := make(chan struct{})
	var requests atomic.Int32
	cdn := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if requests.Add(1) == 1 {
			close(started)
		}
		<-release
		_, _ = w.Write([]byte(testIndex("remote-refresh")))
	}))
	defer cdn.Close()

	conf.Conf.Cdn = cdn.URL
	conf.Conf.CdnIndexRefreshInterval = 60
	siteConfig := getSiteConfig()
	applyBaseIndex(siteConfig, testIndex("old-index"))
	cdnIndexLastAttempt = time.Now().Add(-61 * time.Second)

	for i := 0; i < 20; i++ {
		maybeRefreshCdnIndex(siteConfig)
	}

	select {
	case <-started:
	case <-time.After(2 * time.Second):
		t.Fatal("refresh request did not start")
	}
	for i := 0; i < 20; i++ {
		maybeRefreshCdnIndex(siteConfig)
	}
	if requests.Load() != 1 {
		t.Fatalf("expected a single in-flight refresh request, got %d", requests.Load())
	}
	close(release)

	waitFor(t, func() bool {
		return strings.Contains(currentIndexHtml("/"), "remote-refresh")
	})
	if requests.Load() != 1 {
		t.Fatalf("expected refresh interval to suppress duplicate requests, got %d", requests.Load())
	}
}
