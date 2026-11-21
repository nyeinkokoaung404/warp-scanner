// Warp credentials without account registration.
//
// The upstream scanner registered a fresh WARP account for every scan by
// POSTing to api.cloudflareclient.com, which fails with "error registering
// warp ... connection refused" on networks where that API is unreachable.
// This build never contacts the registration API: the client keypair is
// generated locally, the peer is Cloudflare's well-known WARP public key,
// and the tunnel uses the standard unregistered client address. The WARP
// data plane accepts any client that completes a valid WireGuard handshake
// to the server key, so no account is needed to test whether an endpoint
// carries traffic.
package main

import (
	"crypto/rand"
	"encoding/base64"
	"encoding/binary"
	"fmt"

	"golang.org/x/crypto/curve25519"
)

const (
	// Cloudflare's well-known WARP server public key, as published in every
	// public WARP WireGuard configuration.
	warpPeerPublicKey = "bmXOC+F1FxEMF9dyiK2H5/1SUtzH0JuVo51h2wPfgyo="
	// Standard unregistered client address inside the tunnel.
	warpClientAddress = "172.16.0.2/32"
	// Cloudflare's WARP client IPv6 range: every public WARP WireGuard
	// configuration (including plain configs that connect fine) carries an
	// address from 2606:4700:110::/48. The data plane accepts any address
	// from this range; it is not tied to a registered account.
	warpClientIPv6Prefix = "2606:4700:110"
)

type KeyPair struct {
	PrivateKey string
	PublicKey  string
}

// WarpParams carries everything a WireGuard outbound needs to talk to a
// WARP endpoint. The tunnel is dual-stack like every public WARP config:
// the standard unregistered IPv4 address plus a random address from
// Cloudflare's 2606:4700:110::/48 client range, and the standard reserved
// bytes 0,0,0.
type WarpParams struct {
	IPv6       string
	Reserved   []int
	PublicKey  string
	PrivateKey string
}

// randomWarpIPv6 returns a random address from 2606:4700:110::/48.
func randomWarpIPv6() string {
	var b [10]byte
	if _, err := rand.Read(b[:]); err != nil {
		// Extremely unlikely; fall back to a fixed address in the range.
		return warpClientIPv6Prefix + "::1"
	}
	return fmt.Sprintf("%s:%x:%x:%x:%x:%x",
		warpClientIPv6Prefix,
		binary.BigEndian.Uint16(b[0:2]),
		binary.BigEndian.Uint16(b[2:4]),
		binary.BigEndian.Uint16(b[4:6]),
		binary.BigEndian.Uint16(b[6:8]),
		binary.BigEndian.Uint16(b[8:10]),
	)
}

func GenerateWireGuardKeyPair() (publicKey, privateKey string, err error) {
	privateKeyBytes := make([]byte, curve25519.ScalarSize)
	if _, err = rand.Read(privateKeyBytes); err != nil {
		return "", "", fmt.Errorf("error generating wireguard private key: %w", err)
	}

	privateKeyBytes[0] &= 248
	privateKeyBytes[31] &= 127
	privateKeyBytes[31] |= 64

	var publicKeyBytes [32]byte
	curve25519.ScalarBaseMult(&publicKeyBytes, (*[32]byte)(privateKeyBytes))

	publicKey = base64.StdEncoding.EncodeToString(publicKeyBytes[:])
	privateKey = base64.StdEncoding.EncodeToString(privateKeyBytes)

	return publicKey, privateKey, nil
}

func getWarpParams() (WarpParams, error) {
	_, privateKey, err := GenerateWireGuardKeyPair()
	if err != nil {
		return WarpParams{}, err
	}

	return WarpParams{
		IPv6:       randomWarpIPv6(),
		Reserved:   []int{0, 0, 0},
		PublicKey:  warpPeerPublicKey,
		PrivateKey: privateKey,
	}, nil
}
