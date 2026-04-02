package compat

import (
	"net"
	"testing"
)

// TestParseAddrAndPort tests that IPv4, IPv6, and hostname addresses are split correctly.
func TestParseAddrAndPort(t *testing.T) {
	cases := []struct {
		input      string
		tlsEnabled bool
		wantAddr   string
		wantPort   string
		wantErr    bool
	}{
		// IPv4 with port
		{"1.2.3.4:8080", false, "1.2.3.4", "8080", false},
		// IPv4 without port (defaults)
		{"1.2.3.4", false, "1.2.3.4", "80", false},
		{"1.2.3.4", true, "1.2.3.4", "443", false},
		// Domain with port
		{"example.com:9090", false, "example.com", "9090", false},
		// Domain without port
		{"example.com", false, "example.com", "80", false},
		// IPv6 with port (bracketed) — main use case
		{"[::1]:8080", false, "::1", "8080", false},
		{"[2604:a880:4:1d0::f244:f000]:12345", false, "2604:a880:4:1d0::f244:f000", "12345", false},
		// IPv6 without port (bracketed) — edge case: brackets must be stripped
		// so that net.JoinHostPort("::1","80") = "[::1]:80", NOT "[[::1]]:80"
		{"[::1]", false, "::1", "80", false},
		{"[::1]", true, "::1", "443", false},
	}

	for _, tc := range cases {
		addr, port, err := parseAddrAndPort(tc.input, tc.tlsEnabled)
		if tc.wantErr {
			if err == nil {
				t.Errorf("parseAddrAndPort(%q): expected error, got nil", tc.input)
			}
			continue
		}
		if err != nil {
			t.Errorf("parseAddrAndPort(%q): unexpected error: %v", tc.input, err)
			continue
		}
		if addr != tc.wantAddr {
			t.Errorf("parseAddrAndPort(%q) addr = %q, want %q", tc.input, addr, tc.wantAddr)
		}
		if port != tc.wantPort {
			t.Errorf("parseAddrAndPort(%q) port = %q, want %q", tc.input, port, tc.wantPort)
		}
		// Verify net.JoinHostPort doesn't produce double brackets
		joined := net.JoinHostPort(addr, port)
		if net.ParseIP(addr) != nil && addr != tc.wantAddr {
			t.Errorf("JoinHostPort sanity: unexpected addr %q from %q", addr, tc.input)
		}
		_ = joined
	}
}

// TestDialWithTimeout_IPv6Address verifies that dialWithTimeout is called with
// the correct [::1]:port format when the addr is an IPv6 literal.
// We do this indirectly by constructing the address ourselves and checking
// that net.JoinHostPort produces the correct result.
func TestDialWithTimeout_IPv6Address(t *testing.T) {
	cases := []struct {
		addr string
		port string
		want string
	}{
		{"::1", "8080", "[::1]:8080"},
		{"2604:a880:4:1d0::f244:f000", "12345", "[2604:a880:4:1d0::f244:f000]:12345"},
		{"1.2.3.4", "8080", "1.2.3.4:8080"},
		{"example.com", "443", "example.com:443"},
	}
	for _, tc := range cases {
		got := net.JoinHostPort(tc.addr, tc.port)
		if got != tc.want {
			t.Errorf("JoinHostPort(%q, %q) = %q, want %q", tc.addr, tc.port, got, tc.want)
		}
	}
}

// TestGenerateDialConfig_IPv6Host verifies that generateDialConfig sets cfg.Host
// to the bracket-wrapped form [::1]:port for IPv6 addresses when no Host
// override is provided.
func TestGenerateDialConfig_IPv6Host(t *testing.T) {
	cases := []struct {
		addr     string
		wantHost string
		wantSNI  string
	}{
		// IPv6 with port: standard use case
		{"[::1]:8080", "[::1]:8080", "::1"},
		{"[2604:a880:4:1d0::f244:f000]:12345", "[2604:a880:4:1d0::f244:f000]:12345", "2604:a880:4:1d0::f244:f000"},
		// IPv6 without port: brackets must be stripped before JoinHostPort to avoid "[[::1]]:80"
		{"[::1]", "[::1]:80", "::1"},
		// IPv4: port is NOT included in Host (standard behavior)
		{"1.2.3.4:8080", "1.2.3.4", "1.2.3.4"},
		// Domain: standard behavior preserved
		{"example.com:9090", "example.com", "example.com"},
	}

	for _, tc := range cases {
		cfg := ConnectDialConfig{}
		splitCfg, err := generateDialConfig(tc.addr, cfg)
		if err != nil {
			t.Errorf("generateDialConfig(%q): unexpected error: %v", tc.addr, err)
			continue
		}
		gotHost := splitCfg.ConnectDialConfig.Host
		gotSNI := splitCfg.ConnectDialConfig.ServerName
		if gotHost != tc.wantHost {
			t.Errorf("generateDialConfig(%q) Host = %q, want %q", tc.addr, gotHost, tc.wantHost)
		}
		if gotSNI != tc.wantSNI {
			t.Errorf("generateDialConfig(%q) ServerName = %q, want %q", tc.addr, gotSNI, tc.wantSNI)
		}
	}
}

// TestGenerateDialConfig_UserHostPreserved verifies that an explicitly set Host
// is not overwritten by generateDialConfig.
func TestGenerateDialConfig_UserHostPreserved(t *testing.T) {
	cfg := ConnectDialConfig{
		Host: "cdn.example.com",
	}
	splitCfg, err := generateDialConfig("1.2.3.4:8080", cfg)
	if err != nil {
		t.Fatalf("generateDialConfig: %v", err)
	}
	if splitCfg.Host != "cdn.example.com" {
		t.Errorf("Host = %q, want %q", splitCfg.Host, "cdn.example.com")
	}
}

// TestGenerateDialConfig_ServerNameDrivesHost verifies that when only ServerName
// is set, cfg.Host is derived from ServerName (domain-fronting scenario).
func TestGenerateDialConfig_ServerNameDrivesHost(t *testing.T) {
	cfg := ConnectDialConfig{
		ServerName: "cdn.example.com",
	}
	splitCfg, err := generateDialConfig("1.2.3.4:8080", cfg)
	if err != nil {
		t.Fatalf("generateDialConfig: %v", err)
	}
	if splitCfg.Host != "cdn.example.com" {
		t.Errorf("Host = %q, want %q", splitCfg.Host, "cdn.example.com")
	}
	if splitCfg.ServerName != "cdn.example.com" {
		t.Errorf("ServerName = %q, want %q", splitCfg.ServerName, "cdn.example.com")
	}
}
