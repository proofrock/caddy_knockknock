package caddy_knockknock

import (
	"errors"
	"net/http"
	"strings"

	"github.com/caddyserver/caddy/v2"
	"github.com/caddyserver/caddy/v2/caddyconfig/caddyfile"
	"github.com/caddyserver/caddy/v2/caddyconfig/httpcaddyfile"
	"github.com/caddyserver/caddy/v2/modules/caddyhttp"
	"go.uber.org/zap"
)

const VERSION = "v0.1.0"

var cookey string = "kkkey" + genRandomString(4)

func init() {
	caddy.RegisterModule(CaddyKnockKnock{})
	httpcaddyfile.RegisterHandlerDirective("caddy_knockknock", parseCaddyfile)
}

type CaddyKnockKnock struct {
	HashedKey string `json:"key_hash,omitempty"`
	logger    *zap.Logger
}

func (CaddyKnockKnock) CaddyModule() caddy.ModuleInfo {
	return caddy.ModuleInfo{
		ID:  "http.handlers.caddy_knockknock",
		New: func() caddy.Module { return new(CaddyKnockKnock) },
	}
}

func (m *CaddyKnockKnock) Provision(ctx caddy.Context) error {
	m.logger = ctx.Logger()

	m.logger.Sugar().Infof("KnockKnock %s: init'd", VERSION)

	return nil
}

func cutToColon(input string) string {
	index := strings.Index(input, ":")

	if index != -1 {
		return input[:index]
	}
	return input
}

func (m CaddyKnockKnock) ServeHTTP(w http.ResponseWriter, r *http.Request, next caddyhttp.Handler) error {
	var ip = cutToColon(r.RemoteAddr)
	var key = r.URL.Query().Get("kkkey")

	if key != "" {
		q := r.URL.Query()
		q.Del("kkkey")
		r.URL.RawQuery = q.Encode()

		if ok, _ := comparePasswordAndHash(key, m.HashedKey); !ok {
			return caddyhttp.Error(403, errors.New("wrong key"))
		}
	}

	cookie, _ := r.Cookie(cookey)
	if cookie != nil {
		if cookie.Value != getSession(ip) {
			return caddyhttp.Error(403, errors.New("wrong cookie"))
		}
	} else {
		if key == "" {
			return caddyhttp.Error(403, errors.New("key or cookie must be provided"))
		} else {
			http.SetCookie(w, &http.Cookie{
				Name:     cookey,
				Value:    newSession(ip),
				Path:     "/",
				HttpOnly: true,
				Secure:   true,
			})
		}
	}

	return next.ServeHTTP(w, r)
}

func (m *CaddyKnockKnock) UnmarshalCaddyfile(d *caddyfile.Dispenser) error {
	for d.Next() {
		for d.NextBlock(0) {
			switch d.Val() {
			case "key_hash":
				if !d.Args(&m.HashedKey) {
					return d.Err("invalid key_hash configuration")
				}
			default:
				return d.Errf("unknown directive: %s", d.Val())
			}
		}
	}
	return nil
}

func parseCaddyfile(h httpcaddyfile.Helper) (caddyhttp.MiddlewareHandler, error) {
	var m CaddyKnockKnock
	err := m.UnmarshalCaddyfile(h.Dispenser)
	return m, err
}

// func (m *CaddySmallShield) Validate() error {
// 	if m.xyz == nil {
// 		return fmt.Errorf("no xyz")
// 	}
// 	return nil
// }

// Interface guards
var (
	_ caddy.Provisioner           = (*CaddyKnockKnock)(nil)
	_ caddyhttp.MiddlewareHandler = (*CaddyKnockKnock)(nil)
	_ caddyfile.Unmarshaler       = (*CaddyKnockKnock)(nil)
	// _ caddy.Validator             = (*CaddySmallShield)(nil)
)
