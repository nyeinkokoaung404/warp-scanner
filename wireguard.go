// WireGuard handshake probe for Cloudflare WARP endpoints.
//
// WARP is a WireGuard service: it speaks UDP, not TCP. A raw TCP dial to a
// WARP endpoint (for example :500 or :2408) proves almost nothing — nothing
// listens on TCP there — so a TCP-only scan can report zero live endpoints
// even when the WARP servers are up. This file builds a genuine WireGuard
// handshake initiation (Noise_IKpsk2_25519_ChaChaPoly_BLAKE2s, exactly as
// wireguard-go does) encrypted to Cloudflare's well-known WARP public key.
// Only a real WARP server holding the matching private key can decrypt the
// initiation and answer with a handshake response, so any valid response is
// cryptographic proof that the endpoint is a live WARP server.
//
// Reference: WireGuard whitepaper / wireguard-go device/noise-protocol.go,
// device/noise-helpers.go, device/cookie.go, tai64n/tai64n.go.
package main

import (
	"crypto/hmac"
	"crypto/rand"
	"encoding/base64"
	"encoding/binary"
	"errors"
	"hash"
	"net"
	"sync/atomic"
	"time"

	"golang.org/x/crypto/blake2s"
	"golang.org/x/crypto/chacha20poly1305"
	"golang.org/x/crypto/curve25519"
)

const (
	noiseConstruction = "Noise_IKpsk2_25519_ChaChaPoly_BLAKE2s"
	wgIdentifier      = "WireGuard v1 zx2c4 Jason@zx2c4.com"
	wgLabelMAC1       = "mac1----"

	// Cloudflare's well-known WARP server public key, as published in every
	// public WARP WireGuard configuration.
	warpPublicKeyBase64 = "bmXOC+F1FxEMF9dyiK2H5/1SUtzH0JuVo51h2wPfgyo="

	msgInitiationType = 1
	msgResponseType   = 2
	msgInitiationSize = 148
	msgResponseSize   = 92

	// Layout of a handshake initiation message (little-endian).
	initOffsetSender    = 4
	initOffsetEphemeral = 8
	initOffsetStatic    = 40
	initOffsetTimestamp = 88
	initOffsetMAC1      = 116
	initOffsetMAC2      = 132
)

// warpPublicKey is the decoded WARP server public key.
var warpPublicKey [32]byte

func init() {
	key, err := base64.StdEncoding.DecodeString(warpPublicKeyBase64)
	if err != nil || len(key) != 32 {
		panic("invalid hardcoded WARP public key")
	}
	copy(warpPublicKey[:], key)
}

// --- Noise KDF helpers (HKDF with BLAKE2s, per wireguard-go) ---

func noiseHMAC1(sum *[blake2s.Size]byte, key, in0 []byte) {
	mac := hmac.New(func() hash.Hash {
		h, _ := blake2s.New256(nil)
		return h
	}, key)
	mac.Write(in0)
	mac.Sum(sum[:0])
}

func noiseHMAC2(sum *[blake2s.Size]byte, key, in0, in1 []byte) {
	mac := hmac.New(func() hash.Hash {
		h, _ := blake2s.New256(nil)
		return h
	}, key)
	mac.Write(in0)
	mac.Write(in1)
	mac.Sum(sum[:0])
}

func noiseKDF1(t0 *[blake2s.Size]byte, key, input []byte) {
	noiseHMAC1(t0, key, input)
	noiseHMAC1(t0, t0[:], []byte{0x1})
}

func noiseKDF2(t0, t1 *[blake2s.Size]byte, key, input []byte) {
	var prk [blake2s.Size]byte
	noiseHMAC1(&prk, key, input)
	noiseHMAC1(t0, prk[:], []byte{0x1})
	noiseHMAC2(t1, prk[:], t0[:], []byte{0x2})
}

func noiseMixHash(dst, h *[blake2s.Size]byte, data []byte) {
	hash, _ := blake2s.New256(nil)
	hash.Write(h[:])
	hash.Write(data)
	hash.Sum(dst[:0])
}

func newNoisePrivateKey() (sk [32]byte, err error) {
	if _, err = rand.Read(sk[:]); err != nil {
		return sk, err
	}
	sk[0] &= 248
	sk[31] = (sk[31] & 127) | 64
	return sk, nil
}

func noisePublicKey(sk [32]byte) (pk [32]byte) {
	curve25519.ScalarBaseMult(&pk, &sk)
	return pk
}

func noiseSharedSecret(sk, pk [32]byte) (ss [32]byte, err error) {
	curve25519.ScalarMult(&ss, &sk, &pk)
	for _, b := range ss {
		if b != 0 {
			return ss, nil
		}
	}
	return ss, errors.New("invalid public key: shared secret is zero")
}

// timestampCounter keeps initiation timestamps monotonic within a run, so a
// retried initiation to the same peer is never rejected as a replay.
var timestampCounter uint64

// tai64nTimestamp returns the current time as a 12-byte TAI64N timestamp,
// matching wireguard-go's tai64n package.
func tai64nTimestamp() [12]byte {
	var ts [12]byte
	secs := uint64(0x400000000000000a) + uint64(time.Now().Unix())
	nano := uint32(time.Now().Nanosecond()) &^ 0xFFFFFF
	// Keep timestamps strictly increasing even inside the same second.
	nano |= uint32(atomic.AddUint64(&timestampCounter, 1)&0xFF) << 24
	binary.BigEndian.PutUint64(ts[0:8], secs)
	binary.BigEndian.PutUint32(ts[8:12], nano)
	return ts
}

// buildHandshakeInitiation builds a 148-byte WireGuard handshake initiation
// addressed to remotePub, using staticPriv as our static identity. It returns
// the message and the sender index embedded in it.
func buildHandshakeInitiation(staticPriv, remotePub [32]byte) ([]byte, uint32, error) {
	chainKey := blake2s.Sum256([]byte(noiseConstruction))
	var hash [blake2s.Size]byte
	noiseMixHash(&hash, &chainKey, []byte(wgIdentifier))

	ephemeralPriv, err := newNoisePrivateKey()
	if err != nil {
		return nil, 0, err
	}
	ephemeralPub := noisePublicKey(ephemeralPriv)

	// mixHash(remote static public key)
	noiseMixHash(&hash, &hash, remotePub[:])

	msg := make([]byte, msgInitiationSize)
	binary.LittleEndian.PutUint32(msg[0:4], msgInitiationType)
	copy(msg[initOffsetEphemeral:initOffsetEphemeral+32], ephemeralPub[:])

	// mixKey(ephemeral public key), mixHash(ephemeral public key)
	noiseKDF1(&chainKey, chainKey[:], ephemeralPub[:])
	noiseMixHash(&hash, &hash, ephemeralPub[:])

	// Encrypt our static public key: DH(ephemeral, remote static).
	ss, err := noiseSharedSecret(ephemeralPriv, remotePub)
	if err != nil {
		return nil, 0, err
	}
	var key [chacha20poly1305.KeySize]byte
	var newChainKey [blake2s.Size]byte
	noiseKDF2(&newChainKey, &key, chainKey[:], ss[:])
	chainKey = newChainKey
	staticPub := noisePublicKey(staticPriv)
	aead, err := chacha20poly1305.New(key[:])
	if err != nil {
		return nil, 0, err
	}
	var zeroNonce [chacha20poly1305.NonceSize]byte
	aead.Seal(msg[initOffsetStatic:initOffsetStatic], zeroNonce[:], staticPub[:], hash[:])
	noiseMixHash(&hash, &hash, msg[initOffsetStatic:initOffsetStatic+48])

	// Encrypt the timestamp: DH(our static, remote static).
	ss2, err := noiseSharedSecret(staticPriv, remotePub)
	if err != nil {
		return nil, 0, err
	}
	noiseKDF2(&newChainKey, &key, chainKey[:], ss2[:])
	chainKey = newChainKey
	ts := tai64nTimestamp()
	aead, err = chacha20poly1305.New(key[:])
	if err != nil {
		return nil, 0, err
	}
	aead.Seal(msg[initOffsetTimestamp:initOffsetTimestamp], zeroNonce[:], ts[:], hash[:])
	noiseMixHash(&hash, &hash, msg[initOffsetTimestamp:initOffsetTimestamp+28])

	// Sender index: random, must be non-zero.
	var indexBytes [4]byte
	if _, err := rand.Read(indexBytes[:]); err != nil {
		return nil, 0, err
	}
	senderIndex := binary.LittleEndian.Uint32(indexBytes[:])
	if senderIndex == 0 {
		senderIndex = 1
	}
	binary.LittleEndian.PutUint32(msg[initOffsetSender:initOffsetSender+4], senderIndex)

	// MAC1: BLAKE2s-128 keyed with BLAKE2s-256("mac1----" || remote public
	// key), over everything before the MAC1 field. MAC2 stays zero: we hold
	// no cookie yet, and a server that is not under load accepts that.
	macKey := blake2s.Sum256(append([]byte(wgLabelMAC1), remotePub[:]...))
	mac, _ := blake2s.New128(macKey[:])
	mac.Write(msg[:initOffsetMAC1])
	mac.Sum(msg[initOffsetMAC1:initOffsetMAC1])

	return msg, senderIndex, nil
}

// probeWireGuard sends a WireGuard handshake initiation to endpoint over UDP
// and waits for a handshake response. It reports the round-trip latency and
// whether a valid response arrived. Only a genuine WARP server can produce
// the response, because it must first decrypt our initiation with its static
// private key.
func probeWireGuard(endpoint string, timeout time.Duration) (int64, bool) {
	network := "udp4"
	if len(endpoint) > 0 && endpoint[0] == '[' {
		network = "udp6"
	}
	conn, err := net.DialTimeout(network, endpoint, timeout)
	if err != nil {
		return 0, false
	}
	defer conn.Close()
	return probeWireGuardConn(conn, timeout)
}

// probeWireGuardConn runs the handshake probe over an already-open
// connection, so the reply handling can be tested without a live server.
func probeWireGuardConn(conn net.Conn, timeout time.Duration) (int64, bool) {
	staticPriv, err := newNoisePrivateKey()
	if err != nil {
		return 0, false
	}
	msg, senderIndex, err := buildHandshakeInitiation(staticPriv, warpPublicKey)
	if err != nil {
		return 0, false
	}

	deadline := time.Now().Add(timeout)
	if err := conn.SetDeadline(deadline); err != nil {
		return 0, false
	}
	start := time.Now()
	if _, err := conn.Write(msg); err != nil {
		return 0, false
	}
	buf := make([]byte, 2048)
	for {
		n, err := conn.Read(buf)
		if err != nil {
			return 0, false
		}
		// A cookie reply (type 3) means the server is there but busy; keep
		// waiting for the real handshake response until the deadline.
		if n == msgResponseSize && len(buf) > 0 && buf[0] == msgResponseType {
			receiver := binary.LittleEndian.Uint32(buf[8:12])
			if receiver == senderIndex {
				return time.Since(start).Milliseconds(), true
			}
		}
	}
}
