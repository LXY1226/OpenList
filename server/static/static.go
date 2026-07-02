package static

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"net/http"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/OpenListTeam/OpenList/v4/drivers/base"
	"github.com/OpenListTeam/OpenList/v4/internal/conf"
	"github.com/OpenListTeam/OpenList/v4/internal/setting"
	"github.com/OpenListTeam/OpenList/v4/pkg/utils"
	"github.com/OpenListTeam/OpenList/v4/public"
	"github.com/gin-gonic/gin"
)

type ManifestIcon struct {
	Src   string `json:"src"`
	Sizes string `json:"sizes"`
	Type  string `json:"type"`
}

type Manifest struct {
	Display  string         `json:"display"`
	Scope    string         `json:"scope"`
	StartURL string         `json:"start_url"`
	Name     string         `json:"name"`
	Icons    []ManifestIcon `json:"icons"`
}

var (
	static fs.FS

	indexMu             sync.RWMutex
	cdnIndexRefreshMu   sync.Mutex
	cdnIndexLastAttempt time.Time
	cdnIndexRefreshing  bool
)

func initStatic() {
	utils.Log.Debug("Initializing static file system...")
	if conf.Conf.DistDir == "" {
		dist, err := fs.Sub(public.Public, "dist")
		if err != nil {
			utils.Log.Fatalf("failed to read dist dir: %v", err)
		}
		static = dist
		utils.Log.Debug("Using embedded dist directory")
		return
	}
	static = os.DirFS(conf.Conf.DistDir)
	utils.Log.Infof("Using custom dist directory: %s", conf.Conf.DistDir)
}

func replaceStrings(content string, replacements map[string]string) string {
	for old, new := range replacements {
		content = strings.Replace(content, old, new, 1)
	}
	return content
}

func shouldUseCdnIndex() bool {
	return conf.Conf.DistDir == "" && conf.Conf.Cdn != ""
}

func fetchCdnIndex(siteConfig SiteConfig) (string, error) {
	resp, err := base.RestyClient.R().
		SetHeader("Accept", "text/html").
		Get(fmt.Sprintf("%s/index.html", siteConfig.Cdn))
	if err != nil {
		return "", err
	}
	if resp.StatusCode() != http.StatusOK {
		return "", fmt.Errorf("status code: %d", resp.StatusCode())
	}
	return string(resp.Body()), nil
}

func readStaticIndex() (string, error) {
	indexFile, err := static.Open("index.html")
	if err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			return "", errors.New("index.html not exist, you may forget to put dist of frontend to public/dist")
		}
		return "", err
	}
	defer func() {
		_ = indexFile.Close()
	}()
	index, err := io.ReadAll(indexFile)
	if err != nil {
		return "", errors.New("failed to read dist/index.html")
	}
	return string(index), nil
}

func applyBaseIndex(siteConfig SiteConfig, index string) {
	utils.Log.Debug("Replacing placeholders in index.html...")
	// Construct the correct manifest path based on basePath
	manifestPath := "/manifest.json"
	if siteConfig.BasePath != "/" {
		manifestPath = siteConfig.BasePath + "/manifest.json"
	}
	replaceMap := map[string]string{
		"cdn: undefined":        fmt.Sprintf("cdn: '%s'", siteConfig.Cdn),
		"base_path: undefined":  fmt.Sprintf("base_path: '%s'", siteConfig.BasePath),
		`href="/manifest.json"`: fmt.Sprintf(`href="%s"`, manifestPath),
	}
	indexMu.Lock()
	defer indexMu.Unlock()
	conf.RawIndexHtml = replaceStrings(index, replaceMap)
	updateIndexLocked()
}

func initIndex(siteConfig SiteConfig) {
	utils.Log.Debug("Initializing index.html...")
	if shouldUseCdnIndex() {
		utils.Log.Infof("Fetching index.html from CDN: %s/index.html...", siteConfig.Cdn)
		index, err := fetchCdnIndex(siteConfig)
		markCdnIndexAttempt()
		if err != nil {
			utils.Log.Fatalf("failed to fetch index.html from CDN: %v", err)
		}
		applyBaseIndex(siteConfig, index)
		utils.Log.Info("Successfully fetched index.html from CDN")
		return
	}

	utils.Log.Debug("Reading index.html from static files system...")
	index, err := readStaticIndex()
	if err != nil {
		utils.Log.Fatalf("failed to read index.html: %v", err)
	}
	applyBaseIndex(siteConfig, index)
	utils.Log.Debug("Successfully read index.html from static files system")
}

func UpdateIndex() {
	indexMu.Lock()
	defer indexMu.Unlock()
	updateIndexLocked()
}

func updateIndexLocked() {
	utils.Log.Debug("Updating index.html with settings...")
	favicon := setting.GetStr(conf.Favicon)
	logo := strings.Split(setting.GetStr(conf.Logo), "\n")[0]
	title := setting.GetStr(conf.SiteTitle)
	customizeHead := setting.GetStr(conf.CustomizeHead)
	customizeBody := setting.GetStr(conf.CustomizeBody)
	mainColor := setting.GetStr(conf.MainColor)
	utils.Log.Debug("Applying replacements for default pages...")
	replaceMap1 := map[string]string{
		"https://res.oplist.org/logo/logo.svg": favicon,
		"https://res.oplist.org/logo/logo.png": logo,
		"Loading...":                           title,
		"main_color: undefined":                fmt.Sprintf("main_color: '%s'", mainColor),
	}
	conf.ManageHtml = replaceStrings(conf.RawIndexHtml, replaceMap1)
	utils.Log.Debug("Applying replacements for manage pages...")
	replaceMap2 := map[string]string{
		"<!-- customize head -->": customizeHead,
		"<!-- customize body -->": customizeBody,
	}
	conf.IndexHtml = replaceStrings(conf.ManageHtml, replaceMap2)
	utils.Log.Debug("Index.html update completed")
}

func markCdnIndexAttempt() {
	cdnIndexRefreshMu.Lock()
	cdnIndexLastAttempt = time.Now()
	cdnIndexRefreshMu.Unlock()
}

func maybeRefreshCdnIndex(siteConfig SiteConfig) {
	if !shouldUseCdnIndex() || conf.Conf.CdnIndexRefreshInterval <= 0 {
		return
	}

	interval := time.Duration(conf.Conf.CdnIndexRefreshInterval) * time.Second
	cdnIndexRefreshMu.Lock()
	if cdnIndexRefreshing || time.Since(cdnIndexLastAttempt) < interval {
		cdnIndexRefreshMu.Unlock()
		return
	}
	cdnIndexRefreshing = true
	cdnIndexLastAttempt = time.Now()
	cdnIndexRefreshMu.Unlock()

	go func() {
		defer func() {
			cdnIndexRefreshMu.Lock()
			cdnIndexRefreshing = false
			cdnIndexRefreshMu.Unlock()
		}()

		utils.Log.Debugf("Refreshing index.html from CDN: %s/index.html...", siteConfig.Cdn)
		index, err := fetchCdnIndex(siteConfig)
		if err != nil {
			utils.Log.Errorf("failed to refresh index.html from CDN: %v", err)
			return
		}
		applyBaseIndex(siteConfig, index)
		utils.Log.Debug("Successfully refreshed index.html from CDN")
	}()
}

func currentIndexHtml(path string) string {
	indexMu.RLock()
	defer indexMu.RUnlock()
	if strings.HasPrefix(path, "/@manage") {
		return conf.ManageHtml
	}
	return conf.IndexHtml
}

func ManifestJSON(c *gin.Context) {
	// Get site configuration to ensure consistent base path handling
	siteConfig := getSiteConfig()

	// Get site title from settings
	siteTitle := setting.GetStr(conf.SiteTitle)

	// Get logo from settings, use the first line (light theme logo)
	logoSetting := setting.GetStr(conf.Logo)
	logoUrl := strings.Split(logoSetting, "\n")[0]

	// Use base path from site config for consistency
	basePath := siteConfig.BasePath

	// Determine scope and start_url
	// PWA scope and start_url should always point to our application's base path
	// regardless of whether static resources come from CDN or local server
	scope := basePath
	startURL := basePath

	manifest := Manifest{
		Display:  "standalone",
		Scope:    scope,
		StartURL: startURL,
		Name:     siteTitle,
		Icons: []ManifestIcon{
			{
				Src:   logoUrl,
				Sizes: "512x512",
				Type:  "image/png",
			},
		},
	}

	c.Header("Content-Type", "application/json")
	c.Header("Cache-Control", "public, max-age=3600") // cache for 1 hour

	if err := json.NewEncoder(c.Writer).Encode(manifest); err != nil {
		utils.Log.Errorf("Failed to encode manifest.json: %v", err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to generate manifest"})
		return
	}
}

func Static(r *gin.RouterGroup, noRoute func(handlers ...gin.HandlerFunc)) {
	utils.Log.Debug("Setting up static routes...")
	siteConfig := getSiteConfig()
	initStatic()
	initIndex(siteConfig)
	folders := []string{"assets", "images", "streamer", "static"}

	if conf.Conf.Cdn == "" {
		utils.Log.Debug("Setting up static file serving...")
		r.Use(func(c *gin.Context) {
			for _, folder := range folders {
				if strings.HasPrefix(c.Request.RequestURI, fmt.Sprintf("/%s/", folder)) {
					c.Header("Cache-Control", "public, max-age=15552000")
				}
			}
		})
		for _, folder := range folders {
			sub, err := fs.Sub(static, folder)
			if err != nil {
				utils.Log.Fatalf("can't find folder: %s", folder)
			}
			utils.Log.Debugf("Setting up route for folder: %s", folder)
			r.StaticFS(fmt.Sprintf("/%s/", folder), http.FS(sub))
		}
	} else {
		// Ensure static file redirected to CDN
		for _, folder := range folders {
			r.GET(fmt.Sprintf("/%s/*filepath", folder), func(c *gin.Context) {
				filepath := c.Param("filepath")
				c.Redirect(http.StatusFound, fmt.Sprintf("%s/%s%s", siteConfig.Cdn, folder, filepath))
			})
		}
	}

	utils.Log.Debug("Setting up catch-all route...")
	noRoute(func(c *gin.Context) {
		if c.Request.Method != "GET" && c.Request.Method != "POST" {
			c.Status(405)
			return
		}
		c.Header("Content-Type", "text/html")
		c.Status(200)
		maybeRefreshCdnIndex(siteConfig)
		_, _ = c.Writer.WriteString(currentIndexHtml(c.Request.URL.Path))
		c.Writer.Flush()
		c.Writer.WriteHeaderNow()
	})
}
