package caddy_knockknock

import (
	"errors"
	"net/http"
	"strings"
	"sync"

	"github.com/caddyserver/caddy/v2"
	"github.com/caddyserver/caddy/v2/caddyconfig/caddyfile"
	"github.com/caddyserver/caddy/v2/caddyconfig/httpcaddyfile"
	"github.com/caddyserver/caddy/v2/modules/caddyhttp"
	"go.uber.org/zap"
)

const VERSION = "v0.0.1"

var mutex sync.RWMutex
var authorisedIPs map[string]any = make(map[string]any)

func init() {
	caddy.RegisterModule(CaddyKnockKnock{})
	httpcaddyfile.RegisterHandlerDirective("caddy_knockknock", parseCaddyfile)
}

type CaddyKnockKnock struct {
	HashedKey string `json:"key_hash,omitempty"`
	IsKeyHole string `json:"key_hole,omitempty"`

	isKeyHole bool

	logger *zap.Logger
}

func (CaddyKnockKnock) CaddyModule() caddy.ModuleInfo {
	return caddy.ModuleInfo{
		ID:  "http.handlers.caddy_knockknock",
		New: func() caddy.Module { return new(CaddyKnockKnock) },
	}
}

func (m *CaddyKnockKnock) Provision(ctx caddy.Context) error {
	m.logger = ctx.Logger()

	m.isKeyHole = strings.ToLower(m.IsKeyHole) == "true"

	if m.isKeyHole && m.HashedKey == "" {
		return errors.New("this node is a keyhole but doesn't specify a key_hash")
	}

	if m.isKeyHole {
		m.logger.Sugar().Infof("KnockKnock %s: init'd as keyhole", VERSION)
	} else {
		m.logger.Sugar().Infof("KnockKnock %s: init'd", VERSION)
	}

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
	if m.isKeyHole {
		url := r.URL.String()
		password := url[(strings.LastIndex(url, "/") + 1):]
		if ok, _ := comparePasswordAndHash(password, m.HashedKey); ok {
			mutex.Lock()
			defer mutex.Unlock()
			authorisedIPs[ip] = true
			return next.ServeHTTP(w, r)
		}
		return caddyhttp.Error(403, errors.New("wrong key"))
	}
	mutex.RLock()
	defer mutex.RUnlock()
	if _, ok := authorisedIPs[ip]; ok {
		return next.ServeHTTP(w, r)
	}
	return caddyhttp.Error(403, errors.New("blocked IP"))
}

func (m *CaddyKnockKnock) UnmarshalCaddyfile(d *caddyfile.Dispenser) error {
	for d.Next() {
		for d.NextBlock(0) {
			switch d.Val() {
			case "key_hash":
				if !d.Args(&m.HashedKey) {
					return d.Err("invalid key_hash configuration")
				}
			case "key_hole":
				if !d.Args(&m.IsKeyHole) {
					return d.Err("invalid key_hole configuration")
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
