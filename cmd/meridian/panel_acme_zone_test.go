package main

import (
	"errors"
	"strings"
	"testing"
)

func TestAcmeZoneForRoute(t *testing.T) {
	// Provider lookup succeeds for exact candidate names in this set.
	known := func(zone string) (string, error) {
		switch zone {
		case "example.com", "nbbb.kdns.fr":
			return "id-" + zone, nil
		}
		return "", errors.New("Cloudflare 中不存在 zone")
	}

	cases := []struct {
		name  string
		route string
		want  string
		fail  bool
	}{
		{"regular tld", "panel.example.com", "id-example.com", false},
		{"psl private subzone", "nbbb.kdns.fr", "id-nbbb.kdns.fr", false},
		{"deeper host on psl subzone", "panel.nbbb.kdns.fr", "id-nbbb.kdns.fr", false},
		{"no zone anywhere", "nothing.matches.here.example", "", true},
		{"bare host", "localhost", "", true},
		{"empty", "   ", "", true},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, err := acmeZoneForRoute(tc.route, known)
			if tc.fail {
				if err == nil {
					t.Fatalf("expected error for %q, got %q", tc.route, got)
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error for %q: %v", tc.route, err)
			}
			if got != tc.want {
				t.Fatalf("zone for %q = %q, want %q", tc.route, got, tc.want)
			}
		})
	}
}

func TestAcmeZoneForRouteSkipsUnknownIntermediate(t *testing.T) {
	lookupErr := errors.New("Cloudflare 中不存在 zone")
	calls := 0
	lookup := func(zone string) (string, error) {
		calls++
		if zone == "deep.sub.example.com" {
			return "id-deep", nil
		}
		return "", lookupErr
	}
	got, err := acmeZoneForRoute("host.deep.sub.example.com", lookup)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got != "id-deep" {
		t.Fatalf("got %q", got)
	}
	if calls < 2 {
		t.Fatalf("expected upward walk, %d call(s)", calls)
	}
}

// The failure message must name every candidate that was tried so operators do
// not have to guess whether the token, the domain or the zone is at fault.
func TestAcmeZoneForRouteErrorListsCandidates(t *testing.T) {
	notFound := func(string) (string, error) {
		return "", errors.New("Cloudflare 中不存在 zone")
	}
	_, err := acmeZoneForRoute("panel.nbbb.kdns.fr", notFound)
	if err == nil {
		t.Fatal("expected an error")
	}
	var zoneErr *zoneResolutionError
	if !errors.As(err, &zoneErr) {
		t.Fatalf("expected zoneResolutionError, got %T", err)
	}
	want := []string{"panel.nbbb.kdns.fr", "nbbb.kdns.fr", "kdns.fr"}
	if strings.Join(zoneErr.Tried, ",") != strings.Join(want, ",") {
		t.Fatalf("tried = %v, want %v", zoneErr.Tried, want)
	}
	msg := err.Error()
	for _, frag := range want {
		if !strings.Contains(msg, frag) {
			t.Fatalf("message missing candidate %q: %s", frag, msg)
		}
	}
	if !strings.Contains(msg, "Zone → Zone → Read") {
		t.Fatalf("message does not explain permissions: %s", msg)
	}
	if strings.Contains(strings.ToLower(msg), "not found") && !strings.Contains(msg, "已依次尝试") {
		t.Fatalf("message should not be the bare legacy wording: %s", msg)
	}
}

// A rejected API call (permissions/credential) must be described differently
// from "the zone does not exist".
func TestAcmeZoneForRouteRejectedCredential(t *testing.T) {
	rejected := func(string) (string, error) {
		return "", errors.New("Cloudflare DNS request was rejected: Authentication error")
	}
	_, err := acmeZoneForRoute("panel.example.com", rejected)
	if err == nil {
		t.Fatal("expected an error")
	}
	var zoneErr *zoneResolutionError
	if !errors.As(err, &zoneErr) {
		t.Fatalf("expected zoneResolutionError, got %T", err)
	}
	if !zoneErr.Rejected {
		t.Fatal("Rejected flag should be set for credential/permission failures")
	}
	if !strings.Contains(err.Error(), "Token 权限") {
		t.Fatalf("message should point at token permissions: %s", err.Error())
	}
}
