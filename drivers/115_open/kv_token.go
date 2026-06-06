package _115_open

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"time"

	sdk "github.com/OpenListTeam/115-sdk-go"
	"github.com/OpenListTeam/OpenList/v4/drivers/base"
	"github.com/go-resty/resty/v2"
)

const kvVersionHeader = "X-KV-Version"

var errKVTokenNotFound = errors.New("115 open kv token not found")

type kvToken struct {
	Token   sdk.TokenValue
	Version string
}

type open115KV struct {
	baseURL string
	cookie  string
	key     string
	version string
}

func new115OpenKV(baseURL, auth, key string) *open115KV {
	cookie := strings.TrimSpace(auth)
	if !strings.Contains(cookie, "=") {
		cookie = "__Host-Auth=" + cookie
	}
	return &open115KV{
		baseURL: strings.TrimRight(strings.TrimSpace(baseURL), "/"),
		cookie:  cookie,
		key:     strings.Trim(strings.TrimSpace(key), "/"),
	}
}

func (p *open115KV) InitToken(ctx context.Context, local sdk.TokenValue) (sdk.TokenValue, error) {
	token, err := p.get(ctx)
	if err == nil {
		p.version = token.Version
		return token.Token, nil
	}
	if !errors.Is(err, errKVTokenNotFound) {
		return sdk.TokenValue{}, err
	}
	if !local.Valid() {
		return sdk.TokenValue{}, fmt.Errorf("invalid local 115 open token")
	}
	if err := p.SaveToken(ctx, local); err != nil {
		return sdk.TokenValue{}, err
	}
	return local, nil
}

func (p *open115KV) SaveToken(ctx context.Context, token sdk.TokenValue) error {
	saved, err := p.post(ctx, http.MethodPost, token)
	if err != nil {
		return err
	}
	p.version = saved.Version
	return nil
}

func (p *open115KV) BeforeTokenRefresh(ctx context.Context) (*sdk.TokenValue, error) {
	for {
		token, locked, err := p.lock(ctx)
		if err != nil {
			return nil, err
		}
		if token != nil {
			p.version = token.Version
			return &token.Token, nil
		}
		if locked {
			return nil, nil
		}
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		case <-time.After(500 * time.Millisecond):
		}
	}
}

func (p *open115KV) AfterTokenRefresh(ctx context.Context, token sdk.TokenValue) error {
	saved, err := p.post(ctx, "UNLOCK", token)
	if err != nil {
		return err
	}
	p.version = saved.Version
	return nil
}

func (p *open115KV) get(ctx context.Context) (*kvToken, error) {
	res, err := p.request(ctx, http.MethodGet, "", nil)
	if err != nil {
		return nil, err
	}
	if res.StatusCode() == http.StatusNotFound {
		return nil, errKVTokenNotFound
	}
	if res.IsError() {
		return nil, fmt.Errorf("functions-kv GET failed: %s", res.String())
	}
	return parseKVToken(res.Body(), res.Header().Get(kvVersionHeader))
}

func (p *open115KV) lock(ctx context.Context) (*kvToken, bool, error) {
	if p.version == "" {
		token, err := p.get(ctx)
		if err != nil {
			return nil, false, err
		}
		p.version = token.Version
	}
	res, err := p.request(ctx, "LOCK", "?t="+url.QueryEscape(p.version), nil)
	if err != nil {
		return nil, false, err
	}
	switch res.StatusCode() {
	case http.StatusOK:
		token, err := parseKVToken(res.Body(), res.Header().Get(kvVersionHeader))
		return token, false, err
	case http.StatusCreated:
		return nil, true, nil
	case http.StatusLocked:
		return nil, false, nil
	case http.StatusNotFound:
		return nil, false, errKVTokenNotFound
	default:
		return nil, false, fmt.Errorf("functions-kv LOCK failed: %s", res.String())
	}
}

func (p *open115KV) post(ctx context.Context, method string, token sdk.TokenValue) (*kvToken, error) {
	token = token.WithRefreshTime(time.Now())
	body, err := json.Marshal(token)
	if err != nil {
		return nil, err
	}
	res, err := p.request(ctx, method, "", body)
	if err != nil {
		return nil, err
	}
	if res.IsError() {
		return nil, fmt.Errorf("functions-kv %s failed: %s", method, res.String())
	}
	version := res.Header().Get(kvVersionHeader)
	if version == "" {
		return nil, fmt.Errorf("functions-kv %s missing %s", method, kvVersionHeader)
	}
	return &kvToken{Token: token, Version: version}, nil
}

func (p *open115KV) request(ctx context.Context, method, suffix string, body []byte) (*resty.Response, error) {
	req := base.RestyClient.R().
		SetContext(ctx).
		SetHeader("Cookie", p.cookie)
	if body != nil {
		req.SetHeader("Content-Type", "application/json")
		req.SetBody(body)
	}
	return req.Execute(method, p.baseURL+"/"+url.PathEscape(p.key)+suffix)
}

func parseKVToken(body []byte, version string) (*kvToken, error) {
	if version == "" {
		return nil, fmt.Errorf("functions-kv response missing %s", kvVersionHeader)
	}
	var token sdk.TokenValue
	if err := json.Unmarshal(body, &token); err != nil {
		return nil, err
	}
	if !token.Valid() {
		return nil, fmt.Errorf("invalid 115 open token from functions-kv")
	}
	return &kvToken{Token: token, Version: version}, nil
}
