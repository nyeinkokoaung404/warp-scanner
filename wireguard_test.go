package main

import (
	"bytes"
	"crypto/rand"
	"encoding/binary"
	"net"
	"testing"
	"time"

	"golang.org/x/crypto/blake2s"
	"golang.org/x/crypto/chacha20poly1305"
)

// responderConsume mirrors the responder side of wireguard-go's
// ConsumeMessageInitiation: it verifies MAC1, decrypts the ephemeral/static/
// timestamp fields and returns the initiator's static public key and the
// timestamp. If buildHandshakeInitiation is correct, this must succeed.
func responderConsume(msg []byte, respPriv, respPub [32]byte) ([32]byte, [12]byte, error) {
	var emptyPub [32]byte
	var emptyT [12]byte
	if len(msg) != msgInitiationSize {
		return emptyPub, emptyT, errBadMessage
	}
	// Verify MAC1.
	macKey := blake2s.Sum256(append([]byte(wgLabelMAC1), respPub[:]...))
	mac, _ := blake2s.New128(macKey[:])
	mac.Write(msg[:initOffsetMAC1])
	var wantMAC [16]byte
	mac.Sum(wantMAC[:0])
	if !bytes.Equal(wantMAC[:], msg[initOffsetMAC1:initOffsetMAC1+16]) {
		return emptyPub, emptyT, errBadMAC
	}

	chainKey := blake2s.Sum256([]byte(noiseConstruction))
	var hash [blake2s.Size]byte
	noiseMixHash(&hash, &chainKey, []byte(wgIdentifier))

	// mixHash(responder's own static public key)
	noiseMixHash(&hash, &hash, respPub[:])

	// mixKey + mixHash(ephemeral public key from the message)
	var ephemeralPub [32]byte
	copy(ephemeralPub[:], msg[initOffsetEphemeral:initOffsetEphemeral+32])
	noiseKDF1(&chainKey, chainKey[:], ephemeralPub[:])
	noiseMixHash(&hash, &hash, ephemeralPub[:])

	// Decrypt the initiator's static public key.
	ss, err := noiseSharedSecret(respPriv, ephemeralPub)
	if err != nil {
		return emptyPub, emptyT, err
	}
	var key [chacha20poly1305.KeySize]byte
	var newChainKey [blake2s.Size]byte
	noiseKDF2(&newChainKey, &key, chainKey[:], ss[:])
	chainKey = newChainKey
	aead, err := chacha20poly1305.New(key[:])
	if err != nil {
		return emptyPub, emptyT, err
	}
	var zeroNonce [chacha20poly1305.NonceSize]byte
	var initPub [32]byte
	decrypted, err := aead.Open(nil, zeroNonce[:], msg[initOffsetStatic:initOffsetStatic+48], hash[:])
	if err != nil {
		return emptyPub, emptyT, err
	}
	copy(initPub[:], decrypted)
	noiseMixHash(&hash, &hash, msg[initOffsetStatic:initOffsetStatic+48])

	// Decrypt the timestamp.
	ss2, err := noiseSharedSecret(respPriv, initPub)
	if err != nil {
		return emptyPub, emptyT, err
	}
	noiseKDF2(&newChainKey, &key, chainKey[:], ss2[:])
	chainKey = newChainKey
	aead, err = chacha20poly1305.New(key[:])
	if err != nil {
		return emptyPub, emptyT, err
	}
	plain, err := aead.Open(nil, zeroNonce[:], msg[initOffsetTimestamp:initOffsetTimestamp+28], hash[:])
	if err != nil {
		return emptyPub, emptyT, err
	}
	var ts [12]byte
	copy(ts[:], plain)
	return initPub, ts, nil
}

var (
	errBadMessage = errTest("bad initiation message size")
	errBadMAC     = errTest("bad MAC1")
)

type errTest string

func (e errTest) Error() string { return string(e) }

func TestBuildInitiationRoundTrip(t *testing.T) {
	respPriv, err := newNoisePrivateKey()
	if err != nil {
		t.Fatal(err)
	}
	respPub := noisePublicKey(respPriv)

	initPriv, err := newNoisePrivateKey()
	if err != nil {
		t.Fatal(err)
	}
	initPub := noisePublicKey(initPriv)

	msg, senderIndex, err := buildHandshakeInitiation(initPriv, respPub)
	if err != nil {
		t.Fatalf("buildHandshakeInitiation: %v", err)
	}
	if len(msg) != msgInitiationSize {
		t.Fatalf("initiation size = %d, want %d", len(msg), msgInitiationSize)
	}
	if binary.LittleEndian.Uint32(msg[0:4]) != msgInitiationType {
		t.Fatalf("initiation type = %d, want %d", binary.LittleEndian.Uint32(msg[0:4]), msgInitiationType)
	}
	if senderIndex == 0 || binary.LittleEndian.Uint32(msg[initOffsetSender:initOffsetSender+4]) != senderIndex {
		t.Fatalf("sender index mismatch: %d", senderIndex)
	}
	if !bytes.Equal(msg[initOffsetMAC2:], make([]byte, 16)) {
		t.Fatal("MAC2 must be zero (no cookie yet)")
	}

	gotPub, gotTS, err := responderConsume(msg, respPriv, respPub)
	if err != nil {
		t.Fatalf("responder could not consume initiation: %v", err)
	}
	if gotPub != initPub {
		t.Fatal("responder decrypted a different static public key")
	}
	secs := binary.BigEndian.Uint64(gotTS[0:8]) - uint64(0x400000000000000a)
	now := uint64(time.Now().Unix())
	if secs < now-120 || secs > now+120 {
		t.Fatalf("timestamp seconds %d, want near now %d", secs, now)
	}
}

func TestProbeWireGuardConn(t *testing.T) {
	// This VM's sandbox drops UDP replies (even on loopback), so the probe's
	// reply handling is tested over net.Pipe instead. The crypto itself is
	// covered by TestBuildInitiationRoundTrip.
	server, client := net.Pipe()
	defer server.Close()
	defer client.Close()
	go func() {
		buf := make([]byte, 2048)
		n, err := server.Read(buf)
		if err != nil {
			return
		}
		if n != msgInitiationSize || buf[0] != msgInitiationType {
			return
		}
		resp := make([]byte, msgResponseSize)
		binary.LittleEndian.PutUint32(resp[0:4], msgResponseType)
		if _, err := rand.Read(resp[4:8]); err != nil {
			return
		}
		copy(resp[8:12], buf[initOffsetSender:initOffsetSender+4])
		server.Write(resp)
	}()

	latency, ok := probeWireGuardConn(client, 2*time.Second)
	if !ok {
		t.Fatal("probe did not accept the handshake response")
	}
	if latency < 0 {
		t.Fatalf("negative latency %d", latency)
	}
}

func TestProbeWireGuardConnSilent(t *testing.T) {
	// A peer that never answers must report not-ok, not hang.
	server, client := net.Pipe()
	defer server.Close()
	defer client.Close()
	go func() {
		buf := make([]byte, 2048)
		server.Read(buf) // swallow the initiation, never reply
	}()

	latency, ok := probeWireGuardConn(client, 500*time.Millisecond)
	if ok || latency != 0 {
		t.Fatalf("silent peer reported ok=%v latency=%d", ok, latency)
	}
}

func TestProbeWireGuardConnWrongReceiver(t *testing.T) {
	server, client := net.Pipe()
	defer server.Close()
	defer client.Close()
	go func() {
		buf := make([]byte, 2048)
		n, err := server.Read(buf)
		if err != nil {
			return
		}
		if n != msgInitiationSize {
			return
		}
		// Response with a receiver index that is not ours.
		resp := make([]byte, msgResponseSize)
		binary.LittleEndian.PutUint32(resp[0:4], msgResponseType)
		binary.LittleEndian.PutUint32(resp[8:12], 0xdeadbeef)
		server.Write(resp)
	}()

	_, ok := probeWireGuardConn(client, 500*time.Millisecond)
	if ok {
		t.Fatal("probe accepted a response meant for another sender index")
	}
}
