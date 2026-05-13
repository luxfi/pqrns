// Copyright (C) 2025-2026, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

// Package identity exposes PQ-RNS wire constants + domain-separation
// context strings. Identity keys themselves come from luxfi/zwing —
// the single canonical Lux implementation of the hybrid signing
// identity (Ed25519 + ML-DSA-65) and X-Wing KEM (X25519 + ML-KEM-768).
//
// One way only: this package owns wire sizes and PQ-RNS-specific
// context strings; zwing owns the keys and primitives.
package identity

import (
	"crypto/ecdh"
	"crypto/sha256"

	"github.com/luxfi/zwing"
)

// Sizes (bytes). On-wire identity layout for PQ-RNS:
//
//	Ed25519 (32) || X25519 (32) || ML-DSA-65 pub (1952) || ML-KEM-768 pub (1184)
//
// PublicIdentitySize = 3200.
const (
	Ed25519PubSize  = 32
	X25519PubSize   = 32
	MLDSA65PubSize  = 1952
	MLKEM768PubSize = 1184

	// FingerprintSize matches native RNS — 16 bytes of SHA-256 prefix.
	FingerprintSize = 16

	PublicIdentitySize = Ed25519PubSize + X25519PubSize + MLDSA65PubSize + MLKEM768PubSize
)

// IdentityKind discriminates between native classical RNS and PQ-RNS
// hybrid identities. The wire byte appears in the announce frame's
// capability block.
type IdentityKind uint16

const (
	KindClassical IdentityKind = 0x0001
	KindHybridV1  IdentityKind = 0x0002
)

// Domain-separation context strings. Every HKDF derivation and every
// signature in PQ-RNS carries one of these.
const (
	CtxLinkKDF     = "PQRNS-LINK-v1"
	CtxIdentitySig = "PQRNS-IDENTITY-SIG-v1"
	CtxAnnounceSig = "PQRNS-ANNOUNCE-SIG-v1"
	CtxRekey       = "PQRNS-LINK-REKEY-v1"
)

// Fingerprint computes the 16-byte PQ-RNS fingerprint over a zwing
// IdentityPublic. Same shape as native RNS: SHA-256 prefix of the
// canonical identity-blob bytes.
func Fingerprint(pub *zwing.IdentityPublic) [FingerprintSize]byte {
	h := sha256.New()
	h.Write(pub.MarshalBinary())
	sum := h.Sum(nil)
	var fp [FingerprintSize]byte
	copy(fp[:], sum[:FingerprintSize])
	return fp
}

// X25519PubBytes returns the X25519 leg of a zwing X-Wing public key
// as a 32-byte slice. PQ-RNS announces use the X25519 leg directly in
// the classical-only address namespace.
func X25519PubBytes(xpub *zwing.XWingPublicKey) []byte {
	out := make([]byte, X25519PubSize)
	copy(out, xpub.X25519[:])
	return out
}

// X25519PubFromBytes parses a raw 32-byte X25519 public key. PQ-RNS
// peers that want to verify the X25519 half of a hybrid identity
// against an out-of-band-known X25519 pub use this.
func X25519PubFromBytes(b []byte) (*ecdh.PublicKey, error) {
	return ecdh.X25519().NewPublicKey(b)
}
