package main

import (
	"encoding/json"
	"errors"
	"log"
	"net"
	"net/http"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

// Panel-level IP access control. The panel is reachable from the public
// internet, so an allowlist (plus an escape hatch that cannot lock the operator
// out) is a cheap way to shrink the attack surface to a handful of addresses.
const (
	ipAccessOff   = "off"
	ipAccessAllow = "allow"
	ipAccessDeny  = "deny"
)

// IPAccessPolicy is the persisted, non-secret view of the panel IP rules.
type IPAccessPolicy struct {
	Mode      string   `json:"mode"`
	Networks  []string `json:"networks"`
	Countries []string `json:"countries"`
	Redirect  string   `json:"redirect_url"`
	// Escaped holds addresses that passed the /entry escape hatch. They always
	// bypass the filter so a misconfigured allowlist cannot lock the panel out.
	Escaped []string `json:"escaped_networks"`
}

func defaultIPAccessPolicy() IPAccessPolicy {
	return IPAccessPolicy{Mode: ipAccessOff}
}

func normalizeIPAccessPolicy(policy IPAccessPolicy) (IPAccessPolicy, error) {
	switch policy.Mode {
	case "", ipAccessOff:
		policy.Mode = ipAccessOff
	case ipAccessAllow, ipAccessDeny:
	default:
		return policy, errors.New("ip access mode must be off, allow or deny")
	}
	var cleanErr error
	clean := func(values []string) []string {
		out := make([]string, 0, len(values))
		seen := map[string]struct{}{}
		for _, raw := range values {
			value := strings.TrimSpace(raw)
			if value == "" {
				continue
			}
			// A bare address becomes a /32 or /128 so every entry parses as CIDR.
			if ip := net.ParseIP(value); ip != nil {
				if ip.To4() != nil {
					value += "/32"
				} else {
					value += "/128"
				}
			}
			if _, _, err := net.ParseCIDR(value); err != nil {
				cleanErr = errors.New("invalid IP or CIDR: " + raw)
				return nil
			}
			if _, dup := seen[value]; dup {
				continue
			}
			seen[value] = struct{}{}
			out = append(out, value)
		}
		return out
	}
	policy.Networks = clean(policy.Networks)
	if cleanErr != nil {
		return policy, cleanErr
	}
	policy.Escaped = clean(policy.Escaped)
	if cleanErr != nil {
		return policy, cleanErr
	}
	countries := make([]string, 0, len(policy.Countries))
	for _, raw := range policy.Countries {
		code := strings.ToUpper(strings.TrimSpace(raw))
		if len(code) != 2 {
			continue
		}
		countries = append(countries, code)
	}
	policy.Countries = countries
	policy.Redirect = strings.TrimSpace(policy.Redirect)
	if policy.Redirect != "" && !strings.HasPrefix(policy.Redirect, "https://") && !strings.HasPrefix(policy.Redirect, "http://") {
		return policy, errors.New("redirect url must start with http:// or https://")
	}
	return policy, nil
}

// compiled form for cheap per-request checks
type compiledIPAccess struct {
	mode      string
	networks  []*net.IPNet
	escaped   []*net.IPNet
	countries map[string]struct{}
	redirect  string
}

func compileIPAccess(policy IPAccessPolicy) *compiledIPAccess {
	compiled := &compiledIPAccess{mode: policy.Mode, countries: map[string]struct{}{}, redirect: policy.Redirect}
	parse := func(list []string) []*net.IPNet {
		out := make([]*net.IPNet, 0, len(list))
		for _, value := range list {
			if _, network, err := net.ParseCIDR(value); err == nil {
				out = append(out, network)
			}
		}
		return out
	}
	compiled.networks = parse(policy.Networks)
	compiled.escaped = parse(policy.Escaped)
	for _, code := range policy.Countries {
		compiled.countries[code] = struct{}{}
	}
	return compiled
}

func (c *compiledIPAccess) contains(list []*net.IPNet, ip net.IP) bool {
	if ip == nil {
		return false
	}
	for _, network := range list {
		if network.Contains(ip) {
			return true
		}
	}
	return false
}

// allowed decides whether the request may reach the panel. Escaped and loopback
// addresses always pass; country rules apply only when the edge proxy supplied
// a country header.
func (c *compiledIPAccess) allowed(ip net.IP, country string) bool {
	if c == nil || c.mode == ipAccessOff {
		return true
	}
	if ip != nil && (ip.IsLoopback() || c.contains(c.escaped, ip)) {
		return true
	}
	matched := c.contains(c.networks, ip)
	if country != "" {
		if _, ok := c.countries[strings.ToUpper(country)]; ok {
			matched = true
		}
	}
	if c.mode == ipAccessAllow {
		return matched
	}
	return !matched
}

// ipAccessStore caches the compiled policy between settings writes.
type ipAccessStore struct {
	mu     sync.RWMutex
	policy IPAccessPolicy
}

var panelIPAccess atomic.Pointer[compiledIPAccess]

func (d *DB) saveIPAccessPolicy(policy IPAccessPolicy) error {
	normalized, err := normalizeIPAccessPolicy(policy)
	if err != nil {
		return err
	}
	payload, err := json.Marshal(normalized)
	if err != nil {
		return err
	}
	if _, err := d.db.Exec(`UPDATE system_settings SET ip_access=?, updated_at=CURRENT_TIMESTAMP WHERE id=1`, string(payload)); err != nil {
		return err
	}
	panelIPAccess.Store(compileIPAccess(normalized))
	return nil
}

func (d *DB) loadIPAccessPolicy() IPAccessPolicy {
	var raw string
	if err := d.db.QueryRow(`SELECT ip_access FROM system_settings WHERE id=1`).Scan(&raw); err != nil {
		return defaultIPAccessPolicy()
	}
	var policy IPAccessPolicy
	if strings.TrimSpace(raw) == "" || json.Unmarshal([]byte(raw), &policy) != nil {
		return defaultIPAccessPolicy()
	}
	normalized, err := normalizeIPAccessPolicy(policy)
	if err != nil {
		return defaultIPAccessPolicy()
	}
	return normalized
}

// rememberEscapeIP appends the address that passed /entry to the bypass list.
func (d *DB) rememberEscapeIP(ip net.IP) error {
	if ip == nil {
		return nil
	}
	policy := d.loadIPAccessPolicy()
	value := ip.String()
	if ip.To4() != nil {
		value += "/32"
	} else {
		value += "/128"
	}
	for _, existing := range policy.Escaped {
		if existing == value {
			return nil
		}
	}
	policy.Escaped = append(policy.Escaped, value)
	return d.saveIPAccessPolicy(policy)
}

// requestCountry reads the two-letter country code an edge proxy may supply.
func requestCountry(r *http.Request) string {
	if r == nil {
		return ""
	}
	for _, header := range []string{"Cf-Ipcountry", "X-Country", "X-Country-Code"} {
		if value := strings.TrimSpace(r.Header.Get(header)); len(value) == 2 {
			return strings.ToUpper(value)
		}
	}
	return ""
}

// ipAccessMiddleware enforces the panel IP policy. Paths starting with /api/ are
// intentionally included: the API is the valuable target, not the HTML shell.
func (a *App) ipAccessMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		policy := panelIPAccess.Load()
		if policy == nil || policy.mode == ipAccessOff {
			next.ServeHTTP(w, r)
			return
		}
		// The escape endpoint must stay reachable or a bad allowlist becomes a
		// permanent lockout.
		if r.URL.Path == "/entry" || r.URL.Path == "/api/entry" {
			next.ServeHTTP(w, r)
			return
		}
		ip := remoteAddressIP(requestClientKey(r, a.trustedProxies))
		if policy.allowed(ip, requestCountry(r)) {
			next.ServeHTTP(w, r)
			return
		}
		if policy.redirect != "" {
			http.Redirect(w, r, policy.redirect, http.StatusFound)
			return
		}
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		w.WriteHeader(http.StatusForbidden)
		_, _ = w.Write([]byte("<!doctype html><meta charset=utf-8><title>已禁用</title><body style=\"font-family:system-ui;padding:40px\"><h1>你的 IP 已被禁用</h1><p>如需恢复访问，请联系管理员。</p></body>"))
	})
}

// handleIPAccess serves GET/POST of the panel IP policy.
func (a *App) handleIPAccess(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		policy := a.db.loadIPAccessPolicy()
		a.jsonOK(w, policy)
	case http.MethodPost:
		var policy IPAccessPolicy
		if err := decodeJSONBody(w, r, &policy); err != nil {
			a.jsonErr(w, http.StatusBadRequest, "invalid request")
			return
		}
		// Escaped networks are managed by /entry only, never by this form, so a
		// compromised session cannot silently remove its own escape route.
		policy.Escaped = a.db.loadIPAccessPolicy().Escaped
		if err := a.db.saveIPAccessPolicy(policy); err != nil {
			a.jsonErr(w, http.StatusBadRequest, err.Error())
			return
		}
		a.jsonOK(w, a.db.loadIPAccessPolicy())
	default:
		a.jsonErr(w, http.StatusMethodNotAllowed, "method not allowed")
	}
}

// handleEntryEscape is the lockout-avoidance endpoint: it accepts the panel
// password (never the session cookie, so a stolen cookie cannot widen access)
// and permanently adds the caller's address to the bypass list.
func (a *App) handleEntryEscape(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		w.Header().Set("Allow", "POST")
		a.jsonErr(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}
	client := requestClientKey(r, a.trustedProxies)
	if allowed, retryAfter := a.limiter().allow(client, time.Now()); !allowed {
		a.authRateLimitErr(w, "too many attempts; try again later", retryAfter)
		return
	}
	var req struct {
		Username string `json:"username"`
		Password string `json:"password"` // #nosec G117 -- request-only credential DTO.
	}
	if err := decodeJSONBody(w, r, &req); err != nil {
		a.jsonErr(w, http.StatusBadRequest, "invalid request")
		return
	}
	if _, err := a.db.VerifyUser(strings.TrimSpace(req.Username), req.Password); err != nil {
		if blocked, retryAfter := a.limiter().recordFailure(client, time.Now()); blocked {
			a.authRateLimitErr(w, "too many attempts; try again later", retryAfter)
			return
		}
		a.jsonErr(w, http.StatusUnauthorized, "用户名或密码错误")
		return
	}
	ip := remoteAddressIP(client)
	if err := a.db.rememberEscapeIP(ip); err != nil {
		a.jsonErr(w, http.StatusInternalServerError, "无法保存逃生地址")
		return
	}
	log.Printf("panel ip access: escape entry accepted from %s", ip)
	a.jsonOK(w, map[string]any{"escaped": true, "ip": ip.String()})
}
