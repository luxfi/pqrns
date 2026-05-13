// Copyright (C) 2025-2026, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package identity

import (
	"crypto/ecdh"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"errors"
	"io"

	"github.com/cloudflare/circl/kem/mlkem/mlkem768"
	"github.com/cloudflare/circl/sign/mldsa/mldsa65"
)

// PublicIdentity is the hybrid identity in its on-wire form.
type PublicIdentity struct {
	Ed25519  ed25519.PublicKey
	X25519   *ecdh.PublicKey
	MLDSA65  *mldsa65.PublicKey
	MLKEM768 *mlkem768.PublicKey
}

// SecretIdentity holds the matching private keys.
type SecretIdentity struct {
	Ed25519  ed25519.PrivateKey
	X25519   *ecdh.PrivateKey
	MLDSA65  *mldsa65.PrivateKey
	MLKEM768 *mlkem768.PrivateKey
	Public   *PublicIdentity
}

// Errors.
var (
	ErrBadEd25519Sig = errors.New("identity: Ed25519 signature invalid")
	ErrBadMLDSA65Sig = errors.New("identity: ML-DSA-65 signature invalid")
)

// Generate produces a fresh hybrid identity.
func Generate(rng io.Reader) (*SecretIdentity, error) {
	if rng == nil {
		rng = rand.Reader
	}

	edPub, edSec, err := ed25519.GenerateKey(rng)
	if err != nil {
		return nil, err
	}
	x25519 := ecdh.X25519()
	xSec, err := x25519.GenerateKey(rng)
	if err != nil {
		return nil, err
	}
	mldsaPub, mldsaSec, err := mldsa65.GenerateKey(rng)
	if err != nil {
		return nil, err
	}
	mlkemPub, mlkemSec, err := mlkem768.GenerateKeyPair(rng)
	if err != nil {
		return nil, err
	}

	pub := &PublicIdentity{
		Ed25519:  edPub,
		X25519:   xSec.PublicKey(),
		MLDSA65:  mldsaPub,
		MLKEM768: mlkemPub,
	}
	return &SecretIdentity{
		Ed25519:  edSec,
		X25519:   xSec,
		MLDSA65:  mldsaSec,
		MLKEM768: mlkemSec,
		Public:   pub,
	}, nil
}

// Fingerprint returns the 16-byte SHA-256-truncated fingerprint of the
// hybrid identity. Matches the native RNS fingerprint shape; addressing
// namespace is preserved across native and PQ-RNS peers.
func (p *PublicIdentity) Fingerprint() [FingerprintSize]byte {
	h := sha256.New()
	h.Write(p.Ed25519)
	h.Write(p.X25519.Bytes())
	var mldsaPubBytes [MLDSA65PubSize]byte
	_ = mldsaPubBytes
	mldsaBytes, _ := p.MLDSA65.MarshalBinary()
	h.Write(mldsaBytes)
	var mlkemBytes [MLKEM768PubSize]byte
	p.MLKEM768.Pack(mlkemBytes[:])
	h.Write(mlkemBytes[:])
	sum := h.Sum(nil)
	var fp [FingerprintSize]byte
	copy(fp[:], sum[:FingerprintSize])
	return fp
}

// Sign produces a detached hybrid signature (Ed25519 + ML-DSA-65) over
// the supplied digest under the PQ-RNS domain-separation context.
func (sk *SecretIdentity) Sign(ctxStr string, digest []byte) (edSig, mldsaSig []byte, err error) {
	msg := append([]byte(ctxStr), digest...)
	edSig = ed25519.Sign(sk.Ed25519, msg)
	mldsaSig = make([]byte, MLDSA65SigSize)
	if err := mldsa65.SignTo(sk.MLDSA65, msg, nil, false, mldsaSig); err != nil {
		return nil, nil, err
	}
	return edSig, mldsaSig, nil
}

// Verify checks BOTH legs of a hybrid signature. Returns nil only if
// both pass.
func (p *PublicIdentity) Verify(ctxStr string, digest, edSig, mldsaSig []byte) error {
	msg := append([]byte(ctxStr), digest...)
	if !ed25519.Verify(p.Ed25519, msg, edSig) {
		return ErrBadEd25519Sig
	}
	if !mldsa65.Verify(p.MLDSA65, msg, nil, mldsaSig) {
		return ErrBadMLDSA65Sig
	}
	return nil
}

// MLDSA65SigSize re-exports the signature size for callers.
const MLDSA65SigSize = mldsa65.SignatureSize
