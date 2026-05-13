// Copyright (C) 2025-2026, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

// Package identity implements the PQ-RNS hybrid identity: the
// concatenation of classical RNS keys (Ed25519 for signatures, X25519
// for ECDH) with NIST-standardised post-quantum keys (ML-DSA-65 for
// signatures, ML-KEM-768 for KEM).
//
// The wire layout is fixed:
//
//	identity ::= ed25519_pub  (32 bytes)
//	          || x25519_pub   (32 bytes)
//	          || mldsa65_pub  (1952 bytes)
//	          || mlkem768_pub (1184 bytes)
//
// The 16-byte fingerprint is computed as the SHA-256 prefix of the
// identity blob (whole blob, including the PQ keys), so a hybrid
// identity has a stable, globally-unique address that's observably
// distinct from a classical-identity hash.
//
// One way only. There is exactly one identity construction in PQ-RNS
// v1. New variants become new profile versions, not parameters here.
package identity

// Sizes for the public-key blobs (bytes).
const (
	Ed25519PubSize  = 32
	X25519PubSize   = 32
	MLDSA65PubSize  = 1952 // FIPS 204 ML-DSA-65 public key
	MLKEM768PubSize = 1184 // FIPS 203 ML-KEM-768 public key

	// FingerprintSize is the SHA-256 prefix length used as the RNS-side
	// address. Matches the native RNS fingerprint length so the
	// addressing namespace stays the same across native and PQ-RNS peers.
	FingerprintSize = 16

	// Total public-identity size in bytes.
	PublicIdentitySize = Ed25519PubSize + X25519PubSize + MLDSA65PubSize + MLKEM768PubSize
)

// IdentityKind discriminates between native RNS identities (classical only)
// and PQ-RNS hybrid identities. The wire type byte is part of the announce
// frame's capability block.
type IdentityKind uint16

const (
	KindClassical IdentityKind = 0x0001 // native RNS: Ed25519 + X25519 only
	KindHybridV1  IdentityKind = 0x0002 // PQ-RNS v1: classical + ML-DSA-65 + ML-KEM-768
)

// Domain-separation context strings. Every HKDF derivation and every
// signature in PQ-RNS carries one of these. No two layers ever derive
// a key from the same transcript.
const (
	CtxLinkKDF     = "PQRNS-LINK-v1"
	CtxIdentitySig = "PQRNS-IDENTITY-SIG-v1"
	CtxAnnounceSig = "PQRNS-ANNOUNCE-SIG-v1"
	CtxRekey       = "PQRNS-LINK-REKEY-v1"
)
