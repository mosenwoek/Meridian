package main

import (
	"net"
	"testing"
	"time"
)

func mustCompile(t *testing.T, policy IPAccessPolicy) *compiledIPAccess {
	t.Helper()
	normalized, err := normalizeIPAccessPolicy(policy)
	if err != nil {
		t.Fatalf("normalize: %v", err)
	}
	return compileIPAccess(normalized)
}

func TestIPAccessOffAllowsEverything(t *testing.T) {
	c := mustCompile(t, IPAccessPolicy{Mode: ipAccessOff})
	if !c.allowed(net.ParseIP("203.0.113.9"), "") {
		t.Fatal("off mode must allow all addresses")
	}
}

func TestIPAccessAllowListBlocksOutsiders(t *testing.T) {
	c := mustCompile(t, IPAccessPolicy{Mode: ipAccessAllow, Networks: []string{"10.1.2.3", "192.168.0.0/16"}})
	if !c.allowed(net.ParseIP("10.1.2.3"), "") {
		t.Fatal("listed address must pass")
	}
	if !c.allowed(net.ParseIP("192.168.44.5"), "") {
		t.Fatal("address inside CIDR must pass")
	}
	if c.allowed(net.ParseIP("203.0.113.9"), "") {
		t.Fatal("unlisted address must be blocked")
	}
}

func TestIPAccessDenyListBlocksListed(t *testing.T) {
	c := mustCompile(t, IPAccessPolicy{Mode: ipAccessDeny, Networks: []string{"198.51.100.0/24"}})
	if c.allowed(net.ParseIP("198.51.100.7"), "") {
		t.Fatal("denied address must be blocked")
	}
	if !c.allowed(net.ParseIP("203.0.113.9"), "") {
		t.Fatal("unlisted address must pass in deny mode")
	}
}

// The escape list must always win, otherwise a bad allowlist locks the operator
// out of their own panel with no recovery path.
func TestIPAccessEscapeAlwaysAllowed(t *testing.T) {
	c := mustCompile(t, IPAccessPolicy{Mode: ipAccessAllow, Networks: []string{"10.0.0.1"}, Escaped: []string{"203.0.113.50"}})
	if !c.allowed(net.ParseIP("203.0.113.50"), "") {
		t.Fatal("escaped address must bypass the allowlist")
	}
}

func TestIPAccessLoopbackAlwaysAllowed(t *testing.T) {
	c := mustCompile(t, IPAccessPolicy{Mode: ipAccessAllow, Networks: []string{"10.0.0.1"}})
	if !c.allowed(net.ParseIP("127.0.0.1"), "") {
		t.Fatal("loopback must be allowed for local health checks")
	}
}

func TestIPAccessCountryRules(t *testing.T) {
	c := mustCompile(t, IPAccessPolicy{Mode: ipAccessAllow, Countries: []string{"hk"}})
	if !c.allowed(net.ParseIP("203.0.113.9"), "HK") {
		t.Fatal("allow mode must pass a listed country")
	}
	deny := mustCompile(t, IPAccessPolicy{Mode: ipAccessDeny, Countries: []string{"CN"}})
	if deny.allowed(net.ParseIP("203.0.113.9"), "cn") {
		t.Fatal("deny mode must block a listed country")
	}
}

func TestIPAccessRejectsInvalidNetwork(t *testing.T) {
	if _, err := normalizeIPAccessPolicy(IPAccessPolicy{Mode: ipAccessAllow, Networks: []string{"not-an-ip"}}); err == nil {
		t.Fatal("invalid CIDR must be rejected")
	}
}

func TestSplitByFamilyPrefersRequested(t *testing.T) {
	v4 := net.ParseIP("192.0.2.1")
	v6 := net.ParseIP("2001:db8::1")
	addrs := []net.IPAddr{{IP: v4}, {IP: v6}}
	preferred, other := splitByFamily(addrs, ipFamilyV6)
	if len(preferred) != 1 || preferred[0].IP.String() != v6.String() {
		t.Fatalf("v6 preference: got %v", preferred)
	}
	if len(other) != 1 || other[0].IP.String() != v4.String() {
		t.Fatalf("v6 fallback: got %v", other)
	}
}

// Playback series must emit one point per interval, including empty intervals,
// so the chart does not visually compress idle days.
func TestPlaybackRangeStartBuckets(t *testing.T) {
	now := time.Date(2026, 11, 12, 10, 30, 0, 0, time.UTC)
	start, step := playbackRangeStart("7d", now)
	if step != 24*time.Hour {
		t.Fatalf("7d step = %v", step)
	}
	if got := now.Sub(start); got < 7*24*time.Hour {
		t.Fatalf("7d window too short: %v", got)
	}
	_, hourStep := playbackRangeStart("24h", now)
	if hourStep != playbackEventBucketMinutes*time.Minute {
		t.Fatalf("24h step = %v", hourStep)
	}
}
