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
		case "kdns.fr", "nbbb.kdns.fr", "example.com":
			return zone, nil
		}
		return "", errors.New("not found")
	}

	cases := []struct {
		name  string
		route string
		want  string
		fail  bool
	}{
		{"regular tld", "panel.example.com", "example.com", false},
		{"psl private subzone", "nbbb.kdns.fr", "nbbb.kdns.fr", false},
		{"deeper host on psl subzone", "panel.nbbb.kdns.fr", "nbbb.kdns.fr", false},
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
	// simulates: etld+1 exists but the account only manages the deeper zone
	lookupErr := errors.New("zone not found")
	calls := 0
	lookup := func(zone string) (string, error) {
		calls++
		if zone == "deep.sub.example.com" {
			return zone, nil
		}
		return "", lookupErr
	}
	got, err := acmeZoneForRoute("host.deep.sub.example.com", lookup)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got != "deep.sub.example.com" {
		t.Fatalf("got %q", got)
	}
	if calls < 2 {
		t.Fatalf("expected upward walk, %d call(s)", calls)
	}
}
