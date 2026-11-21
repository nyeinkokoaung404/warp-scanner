package main

import (
	"encoding/base64"
	"net"
	"strings"
	"testing"
)

func TestGetWarpParamsNoRegistration(t *testing.T) {
	params, err := getWarpParams()
	if err != nil {
		t.Fatalf("getWarpParams returned error: %v", err)
	}
	// No registered account, but the tunnel is dual-stack like every public
	// WARP config: a random address from 2606:4700:110::/48 and the
	// standard reserved bytes 0,0,0.
	ip := net.ParseIP(params.IPv6)
	if ip == nil || ip.To4() != nil {
		t.Errorf("expected a valid IPv6 address, got %q", params.IPv6)
	}
	if !strings.HasPrefix(params.IPv6, warpClientIPv6Prefix+":") {
		t.Errorf("expected IPv6 in %s::/48, got %q", warpClientIPv6Prefix, params.IPv6)
	}
	if len(params.Reserved) != 3 || params.Reserved[0] != 0 || params.Reserved[1] != 0 || params.Reserved[2] != 0 {
		t.Errorf("expected Reserved [0 0 0], got %v", params.Reserved)
	}
	// The peer must be Cloudflare's well-known WARP public key.
	if params.PublicKey != warpPeerPublicKey {
		t.Errorf("expected peer public key %q, got %q", warpPeerPublicKey, params.PublicKey)
	}
	// The private key must be a valid base64 32-byte Curve25519 key.
	raw, err := base64.StdEncoding.DecodeString(params.PrivateKey)
	if err != nil {
		t.Fatalf("private key is not valid base64: %v", err)
	}
	if len(raw) != 32 {
		t.Errorf("expected 32-byte private key, got %d bytes", len(raw))
	}
}

func TestRandomWarpIPv6Distinct(t *testing.T) {
	a := randomWarpIPv6()
	b := randomWarpIPv6()
	if a == b {
		t.Errorf("two random IPv6 addresses must differ, got %q twice", a)
	}
	if !strings.HasPrefix(a, warpClientIPv6Prefix+":") || !strings.HasPrefix(b, warpClientIPv6Prefix+":") {
		t.Errorf("addresses must be in %s::/48, got %q and %q", warpClientIPv6Prefix, a, b)
	}
}

func TestGenerateWireGuardKeyPairDistinct(t *testing.T) {
	pub1, priv1, err := GenerateWireGuardKeyPair()
	if err != nil {
		t.Fatalf("GenerateWireGuardKeyPair returned error: %v", err)
	}
	pub2, priv2, err := GenerateWireGuardKeyPair()
	if err != nil {
		t.Fatalf("GenerateWireGuardKeyPair returned error: %v", err)
	}
	if priv1 == priv2 || pub1 == pub2 {
		t.Error("two generated keypairs must differ")
	}
	if _, err := base64.StdEncoding.DecodeString(pub1); err != nil {
		t.Errorf("public key is not valid base64: %v", err)
	}
}
