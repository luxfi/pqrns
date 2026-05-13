// Copyright (C) 2025-2026, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

// Package link defines the PQ-RNS hybrid link establishment surface.
// The 3-packet handshake matches the wire layout in the paper:
//
//	LinkRequest   (initiator → responder): ephemeral X25519 || ephemeral
//	              ML-KEM-768 pub || encap to responder's static ML-KEM ||
//	              hybrid signature over the transcript.
//	LinkAccept    (responder → initiator): ephemeral X25519 || encap to
//	              initiator's ephemeral ML-KEM || HMAC ack || hybrid sig.
//	LinkActivate  (initiator → responder): HMAC activate (32 bytes).
//
// One way only. There is exactly one Establish() entry point on each
// side. There is no cipher negotiation: two endpoints either speak
// PQ-RNS-HYBRID-v1 or they don't link.
//
// This package currently exposes the surface only. The packet
// marshalling + KEM/sig wiring lands in a follow-up commit that
// includes the same KAT vectors and round-trip tests as pqsafe. The
// surface is fixed now so call sites can be wired ahead.
package link

import (
	"github.com/luxfi/pqrns/pkg/identity"
)

// Constants from the wire format.
const (
	X25519EphSize  = 32
	MLKEMCTSize    = 1088
	HMACAckSize    = 32
	SessionKeySize = 64 // 32 enc || 32 mac (matches native RNS Fernet token shape)
)

// LinkRequest is the initiator's first packet on the wire.
type LinkRequest struct {
	InitiatorFingerprint [identity.FingerprintSize]byte
	InitEphX25519        [X25519EphSize]byte
	InitEphMLKEMPub      []byte // initiator's ephemeral MLKEM pub (so responder can encap to it)
	InitEphMLKEMCT       [MLKEMCTSize]byte
	HybridCapFlags       uint16
	Ed25519Sig           []byte
	MLDSA65Sig           []byte
}

// LinkAccept is the responder's reply.
type LinkAccept struct {
	RespEphX25519  [X25519EphSize]byte
	RespEphMLKEMCT [MLKEMCTSize]byte
	AckHMAC        [HMACAckSize]byte
	Ed25519Sig     []byte
	MLDSA65Sig     []byte
}

// LinkActivate is the initiator's final ACK.
type LinkActivate struct {
	AckHMAC [HMACAckSize]byte
}

// Session is the established link state.
type Session struct {
	Key             [SessionKeySize]byte
	PeerFingerprint [identity.FingerprintSize]byte
}
