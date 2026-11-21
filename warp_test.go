package main

import (
	"encoding/base64"
	"testing"
)

func TestGetWarpParamsNoRegistration(t *testing.T) {
	params, err := getWarpParams()
	if err != nil {
		t.Fatalf("getWarpParams returned error: %v", err)
	}
	// No registered account: no IPv6 address, no reserved bytes.
	if params.IPv6 != "" {
		t.Errorf("expected empty IPv6, got %q", params.IPv6)
	}
	if params.Reserved != nil {
		t.Errorf("expected nil Reserved, got %v", params.Reserved)
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
