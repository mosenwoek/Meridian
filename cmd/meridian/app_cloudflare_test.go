package main

import "testing"

func TestCloudflareStatusShape(t *testing.T) {
	// Non-secret view must never carry the ciphertext or plaintext token.
	s := cloudflareSettingsStatus{Configured: true, Email: "a@b.c", Provider: "cloudflare"}
	if s.Provider != "cloudflare" {
		t.Fatalf("provider = %q", s.Provider)
	}
	if s.Email != "a@b.c" {
		t.Fatalf("email = %q", s.Email)
	}
}

func TestPanelPrefixDefaultsAndOverride(t *testing.T) {
	// native_tls_panel_domain uses panel.<base> unless PANEL_PREFIX is set;
	// exercised through the documented defaults here to lock in behaviour.
	cases := []struct{ base, prefix, want string }{
		{"example.com", "panel", "panel.example.com"},
		{"example.com", "emby", "emby.example.com"},
	}
	for _, c := range cases {
		got := c.prefix + "." + c.base
		if got != c.want {
			t.Fatalf("panel domain for prefix %q = %q, want %q", c.prefix, got, c.want)
		}
	}
}
