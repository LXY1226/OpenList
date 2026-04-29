package main

import (
	"bytes"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"net/http"
	"os"
	stdpath "path"
	"strings"
	"time"

	cryptname "github.com/OpenListTeam/OpenList/v4/drivers/crypt/filename"
	"github.com/rclone/rclone/fs/config/obscure"
)

const obfuscatedPrefix = "___Obfuscated___"

type config struct {
	BaseURL        string       `json:"base_url"`
	Token          string       `json:"token"`
	CryptMountPath string       `json:"crypt_mount_path"`
	RemotePath     string       `json:"remote_path"`
	DryRun         bool         `json:"dry_run"`
	Overwrite      bool         `json:"overwrite"`
	SkipErrors     bool         `json:"skip_errors"`
	Old            nameOverride `json:"old"`
	New            nameOverride `json:"new"`
}

type nameOverride struct {
	FileNameEncryption      string `json:"filename_encryption"`
	DirectoryNameEncryption *bool  `json:"directory_name_encryption"`
	FileNameEncoding        string `json:"filename_encoding"`
	EncryptedSuffix         string `json:"encrypted_suffix"`
	Password                string `json:"password"`
	Salt                    string `json:"salt"`
	StripOrigExt            *bool  `json:"strip_orig_ext"`
	LegacyStreamIV          bool   `json:"legacy_stream_iv"`
}

type storage struct {
	ID        uint   `json:"id"`
	MountPath string `json:"mount_path"`
	Driver    string `json:"driver"`
	Addition  string `json:"addition"`
	Disabled  bool   `json:"disabled"`
}

type cryptAddition struct {
	FileNameEncryption      string `json:"filename_encryption"`
	DirectoryNameEncryption string `json:"directory_name_encryption"`
	RemotePath              string `json:"remote_path"`
	Password                string `json:"password"`
	Salt                    string `json:"salt"`
	EncryptedSuffix         string `json:"encrypted_suffix"`
	FileNameEncoding        string `json:"filename_encoding"`
	StripOrigExt            bool   `json:"strip_orig_ext"`
}

type listResp struct {
	Content []object `json:"content"`
	Total   int64    `json:"total"`
}

type object struct {
	Name  string `json:"name"`
	IsDir bool   `json:"is_dir"`
}

type apiResp[T any] struct {
	Code    int    `json:"code"`
	Message string `json:"message"`
	Data    T      `json:"data"`
}

type client struct {
	baseURL string
	token   string
	http    *http.Client
}

func main() {
	configPath := flag.String("config", "config.json", "migration config json")
	flag.Parse()

	cfg, err := loadConfig(*configPath)
	if err != nil {
		fatal(err)
	}
	api := &client{
		baseURL: strings.TrimRight(cfg.BaseURL, "/"),
		token:   cfg.Token,
		http:    &http.Client{Timeout: 60 * time.Second},
	}

	storages, err := api.listStorages()
	if err != nil {
		fatal(err)
	}
	cryptStorage, addition, err := findCryptStorage(storages, cfg.CryptMountPath)
	if err != nil {
		fatal(err)
	}
	if cfg.RemotePath != "" {
		addition.RemotePath = cfg.RemotePath
	}
	realStorage, realRoot, err := findRealStorage(storages, addition.RemotePath)
	if err != nil {
		fatal(err)
	}

	oldCipher, err := buildCipher(addition, cfg.Old)
	if err != nil {
		fatal(fmt.Errorf("old filename cipher: %w", err))
	}
	newCipher, err := buildCipher(addition, cfg.New)
	if err != nil {
		fatal(fmt.Errorf("new filename cipher: %w", err))
	}

	fmt.Printf("crypt storage: %s (id=%d)\n", cryptStorage.MountPath, cryptStorage.ID)
	fmt.Printf("real storage:  %s (id=%d)\n", realStorage.MountPath, realStorage.ID)
	fmt.Printf("real root:     %s\n", realRoot)
	fmt.Printf("dry run:       %v\n", cfg.DryRun)

	stats := &migrationStats{}
	if err := migrateDir(api, cfg, oldCipher, newCipher, realRoot, stats); err != nil {
		fatal(err)
	}
	fmt.Printf("done: visited=%d renamed=%d skipped=%d failed=%d\n", stats.Visited, stats.Renamed, stats.Skipped, stats.Failed)
}

func loadConfig(path string) (config, error) {
	var cfg config
	b, err := os.ReadFile(path)
	if err != nil {
		return cfg, err
	}
	var raw map[string]json.RawMessage
	if err := json.Unmarshal(b, &raw); err != nil {
		return cfg, err
	}
	if err := json.Unmarshal(b, &cfg); err != nil {
		return cfg, err
	}
	if _, ok := raw["dry_run"]; !ok {
		cfg.DryRun = true
	}
	if _, ok := raw["skip_errors"]; !ok {
		cfg.SkipErrors = true
	}
	if cfg.BaseURL == "" {
		return cfg, fmt.Errorf("base_url is required")
	}
	if cfg.Token == "" {
		return cfg, fmt.Errorf("token is required")
	}
	return cfg, nil
}

func findCryptStorage(storages []storage, mountPath string) (storage, cryptAddition, error) {
	for _, s := range storages {
		if s.Driver != "Crypt" || s.Disabled {
			continue
		}
		if mountPath != "" && cleanPath(s.MountPath) != cleanPath(mountPath) {
			continue
		}
		var addition cryptAddition
		if err := json.Unmarshal([]byte(s.Addition), &addition); err != nil {
			return storage{}, cryptAddition{}, err
		}
		if addition.RemotePath == "" {
			return storage{}, cryptAddition{}, fmt.Errorf("crypt storage %s has empty remote_path", s.MountPath)
		}
		return s, addition, nil
	}
	if mountPath == "" {
		return storage{}, cryptAddition{}, fmt.Errorf("no enabled Crypt storage found")
	}
	return storage{}, cryptAddition{}, fmt.Errorf("enabled Crypt storage %s not found", mountPath)
}

func findRealStorage(storages []storage, remotePath string) (storage, string, error) {
	remotePath = cleanPath(remotePath)
	var best storage
	bestMountLen := -1
	for _, s := range storages {
		if s.Driver == "Crypt" || s.Disabled {
			continue
		}
		mount := cleanPath(s.MountPath)
		if mount == "/" || remotePath == mount || strings.HasPrefix(remotePath, mount+"/") {
			if len(mount) > bestMountLen {
				best = s
				bestMountLen = len(mount)
			}
		}
	}
	if best.MountPath == "" {
		return storage{}, "", fmt.Errorf("real storage for remote_path %s not found", remotePath)
	}
	root := strings.TrimPrefix(remotePath, cleanPath(best.MountPath))
	root = "/" + strings.Trim(root, "/")
	if root == "/" {
		root = cleanPath(best.MountPath)
	} else {
		root = stdpath.Join(cleanPath(best.MountPath), root)
	}
	return best, root, nil
}

func buildCipher(addition cryptAddition, override nameOverride) (*cryptname.Cipher, error) {
	password, err := secretValue(firstNonEmpty(override.Password, addition.Password))
	if err != nil {
		return nil, fmt.Errorf("password: %w", err)
	}
	salt, err := secretValue(firstNonEmpty(override.Salt, addition.Salt))
	if err != nil {
		return nil, fmt.Errorf("salt: %w", err)
	}
	dirNameEncryption := strings.EqualFold(addition.DirectoryNameEncryption, "true")
	if override.DirectoryNameEncryption != nil {
		dirNameEncryption = *override.DirectoryNameEncryption
	}
	stripOrigExt := addition.StripOrigExt
	if override.StripOrigExt != nil {
		stripOrigExt = *override.StripOrigExt
	}
	return cryptname.New(cryptname.Config{
		Password:                password,
		Salt:                    salt,
		FileNameEncryption:      firstNonEmpty(override.FileNameEncryption, addition.FileNameEncryption),
		DirectoryNameEncryption: dirNameEncryption,
		FileNameEncoding:        firstNonEmpty(override.FileNameEncoding, addition.FileNameEncoding),
		EncryptedSuffix:         firstNonEmpty(override.EncryptedSuffix, addition.EncryptedSuffix),
		StripOrigExt:            stripOrigExt,
		LegacyStreamIV:          override.LegacyStreamIV,
	})
}

type migrationStats struct {
	Visited int
	Renamed int
	Skipped int
	Failed  int
}

func migrateDir(api *client, cfg config, oldCipher, newCipher *cryptname.Cipher, dir string, stats *migrationStats) error {
	objs, err := api.list(dir)
	if err != nil {
		return err
	}
	for _, obj := range objs {
		stats.Visited++
		oldPath := stdpath.Join(dir, obj.Name)
		if obj.IsDir {
			if err := migrateDir(api, cfg, oldCipher, newCipher, oldPath, stats); err != nil {
				if !cfg.SkipErrors {
					return err
				}
				stats.Failed++
				fmt.Printf("ERR  %s: %v\n", oldPath, err)
			}
		}
		newName, err := renameTarget(oldCipher, newCipher, obj.Name, obj.IsDir)
		if err != nil {
			if !cfg.SkipErrors {
				return fmt.Errorf("%s: %w", oldPath, err)
			}
			stats.Failed++
			fmt.Printf("ERR  %s: %v\n", oldPath, err)
			continue
		}
		if newName == obj.Name {
			stats.Skipped++
			continue
		}
		if cfg.DryRun {
			stats.Renamed++
			fmt.Printf("DRY  %s -> %s\n", oldPath, newName)
			continue
		}
		if err := api.rename(oldPath, newName, cfg.Overwrite); err != nil {
			if !cfg.SkipErrors {
				return err
			}
			stats.Failed++
			fmt.Printf("ERR  %s -> %s: %v\n", oldPath, newName, err)
			continue
		}
		stats.Renamed++
		fmt.Printf("REN  %s -> %s\n", oldPath, newName)
	}
	return nil
}

func renameTarget(oldCipher, newCipher *cryptname.Cipher, encrypted string, isDir bool) (string, error) {
	if isDir {
		plain, err := oldCipher.DecryptDirName(encrypted)
		if err != nil {
			return "", err
		}
		return newCipher.EncryptDirName(plain), nil
	}
	plain, err := oldCipher.DecryptFileName(encrypted)
	if err != nil {
		return "", err
	}
	return newCipher.EncryptFileName(plain), nil
}

func (c *client) listStorages() ([]storage, error) {
	var resp apiResp[struct {
		Content []storage `json:"content"`
		Total   int64     `json:"total"`
	}]
	if err := c.do(http.MethodGet, "/api/admin/storage/list?page=1&per_page=-1", nil, &resp); err != nil {
		return nil, err
	}
	return resp.Data.Content, nil
}

func (c *client) list(path string) ([]object, error) {
	var resp apiResp[listResp]
	req := map[string]any{
		"path":     path,
		"page":     1,
		"per_page": -1,
		"refresh":  true,
	}
	if err := c.do(http.MethodPost, "/api/fs/list", req, &resp); err != nil {
		return nil, err
	}
	return resp.Data.Content, nil
}

func (c *client) rename(path, name string, overwrite bool) error {
	req := map[string]any{
		"path":      path,
		"name":      name,
		"overwrite": overwrite,
	}
	var resp apiResp[json.RawMessage]
	return c.do(http.MethodPost, "/api/fs/rename", req, &resp)
}

func (c *client) do(method, apiPath string, body any, out any) error {
	var reader io.Reader
	if body != nil {
		b, err := json.Marshal(body)
		if err != nil {
			return err
		}
		reader = bytes.NewReader(b)
	}
	req, err := http.NewRequest(method, c.baseURL+apiPath, reader)
	if err != nil {
		return err
	}
	req.Header.Set("Authorization", c.token)
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	res, err := c.http.Do(req)
	if err != nil {
		return err
	}
	defer res.Body.Close()
	b, err := io.ReadAll(res.Body)
	if err != nil {
		return err
	}
	if res.StatusCode < 200 || res.StatusCode >= 300 {
		return fmt.Errorf("%s %s: http %d: %s", method, apiPath, res.StatusCode, strings.TrimSpace(string(b)))
	}
	var status struct {
		Code    int    `json:"code"`
		Message string `json:"message"`
	}
	if err := json.Unmarshal(b, &status); err != nil {
		return fmt.Errorf("%s %s: %w: %s", method, apiPath, err, strings.TrimSpace(string(b)))
	}
	if status.Code != 200 {
		return fmt.Errorf("%s %s: api %d: %s", method, apiPath, status.Code, status.Message)
	}
	if err := json.Unmarshal(b, out); err != nil {
		return fmt.Errorf("%s %s: %w: %s", method, apiPath, err, strings.TrimSpace(string(b)))
	}
	return nil
}

func firstNonEmpty(values ...string) string {
	for _, v := range values {
		if v != "" {
			return v
		}
	}
	return ""
}

func secretValue(s string) (string, error) {
	if !strings.HasPrefix(s, obfuscatedPrefix) {
		return s, nil
	}
	return obscure.Reveal(strings.TrimPrefix(s, obfuscatedPrefix))
}

func cleanPath(p string) string {
	p = "/" + strings.Trim(p, "/")
	if p == "/" {
		return "/"
	}
	return stdpath.Clean(p)
}

func fatal(err error) {
	fmt.Fprintf(os.Stderr, "fatal: %v\n", err)
	os.Exit(1)
}
