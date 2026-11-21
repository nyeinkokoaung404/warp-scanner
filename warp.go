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
	"fmt"

	"golang.org/x/crypto/curve25519"
)

const (
	// Cloudflare's well-known WARP server public key, as published in every
	// public WARP WireGuard configuration.
	warpPeerPublicKey = "bmXOC+F1FxEMF9dyiK2H5/1SUtzH0JuVo51h2wPfgyo="
	// Standard unregistered client address inside the tunnel.
	warpClientAddress = "172.16.0.2/32"
)

type KeyPair struct {
	PrivateKey string
	PublicKey  string
}

// WarpParams carries everything a WireGuard outbound needs to talk to a
// WARP endpoint. IPv6 and Reserved stay empty without a registered account;
// the tunnel address is IPv4-only (see core.go).
type WarpParams struct {
	IPv6       string
	Reserved   []int
	PublicKey  string
	PrivateKey string
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
		IPv6:       "",
		Reserved:   nil,
		PublicKey:  warpPeerPublicKey,
		PrivateKey: privateKey,
	}, nil
}
