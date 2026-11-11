package main

import (
	"context"
	"errors"
	"net"
	"sort"
	"strings"
	"time"
)

// Site/global IP family preference for upstream connections.
const (
	ipFamilyAuto = "auto"
	ipFamilyV4   = "ipv4"
	ipFamilyV6   = "ipv6"
)

func normalizeIPFamily(value string) string {
	switch strings.ToLower(strings.TrimSpace(value)) {
	case ipFamilyV4, "v4", "4", "ipv4":
		return ipFamilyV4
	case ipFamilyV6, "v6", "6", "ipv6":
		return ipFamilyV6
	default:
		return ipFamilyAuto
	}
}

// ipFamilyDialer resolves the host itself so it can reorder or filter addresses
// by family before dialing. Some Emby origins have a fast IPv6 path and a
// congested IPv4 one (or the reverse), and Go's default happy-eyeballs picks by
// measured RTT per connection rather than by operator intent.
type ipFamilyDialer struct {
	family  string
	resolve func(ctx context.Context, host string) ([]net.IPAddr, error)
	dial    func(ctx context.Context, network, address string) (net.Conn, error)
}

func newIPFamilyDialer(family string) *ipFamilyDialer {
	resolver := &net.Resolver{}
	return &ipFamilyDialer{
		family:  normalizeIPFamily(family),
		resolve: resolver.LookupIPAddr,
		dial: (&net.Dialer{
			Timeout:   30 * time.Second,
			KeepAlive: 30 * time.Second,
		}).DialContext,
	}
}

// DialContext keeps the original hostname for TLS SNI and the Host header; only
// the connection address is rewritten.
func (d *ipFamilyDialer) DialContext(ctx context.Context, network, address string) (net.Conn, error) {
	if d == nil || d.family == ipFamilyAuto {
		return d.dial(ctx, network, address)
	}
	host, port, err := net.SplitHostPort(address)
	if err != nil {
		return d.dial(ctx, network, address)
	}
	// Literal IPs are respected as configured: the operator already chose a
	// family there.
	if net.ParseIP(strings.Trim(host, "[]")) != nil {
		return d.dial(ctx, network, address)
	}
	addrs, err := d.resolve(ctx, host)
	if err != nil || len(addrs) == 0 {
		return d.dial(ctx, network, address)
	}
	preferred, other := splitByFamily(addrs, d.family)
	if len(preferred) == 0 {
		// No address in the requested family: fall back instead of failing the
		// site outright, matching the "auto" behaviour for single-stack origins.
		preferred, other = other, nil
	}
	if len(preferred) == 0 {
		return d.dial(ctx, network, address)
	}
	var lastErr error
	for _, addr := range append(preferred, other...) {
		conn, dialErr := d.dial(ctx, network, net.JoinHostPort(addr.String(), port))
		if dialErr == nil {
			return conn, nil
		}
		lastErr = dialErr
	}
	if lastErr == nil {
		lastErr = errors.New("no usable upstream address")
	}
	return nil, lastErr
}

func splitByFamily(addrs []net.IPAddr, family string) (preferred, other []net.IPAddr) {
	for _, addr := range addrs {
		isV4 := addr.IP.To4() != nil
		if (family == ipFamilyV4 && isV4) || (family == ipFamilyV6 && !isV4) {
			preferred = append(preferred, addr)
			continue
		}
		other = append(other, addr)
	}
	// Deterministic order keeps connection behaviour reproducible across runs.
	sortAddrs := func(list []net.IPAddr) {
		sort.SliceStable(list, func(i, j int) bool { return list[i].String() < list[j].String() })
	}
	sortAddrs(preferred)
	sortAddrs(other)
	return preferred, other
}

// ipFamilyPreference reads the global family preference from system settings.
// A missing database or an unreadable value falls back to "auto".
func (pm *ProxyManager) ipFamilyPreference() string {
	if pm == nil || pm.database == nil {
		return ipFamilyAuto
	}
	return normalizeIPFamily(pm.database.currentSystemSettings().IPFamily)
}
