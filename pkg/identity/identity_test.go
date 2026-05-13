// Copyright (C) 2025-2026, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package identity

import (
	"bytes"
	"crypto/rand"
	"testing"
)

func TestGenerateAndSign(t *testing.T) {
	sk, err := Generate(rand.Reader)
	if err != nil {
		t.Fatalf("Generate: %v", err)
	}
	digest := []byte("test-digest-bytes")
	edSig, mldsaSig, err := sk.Sign(CtxIdentitySig, digest)
	if err != nil {
		t.Fatalf("Sign: %v", err)
	}
	if err := sk.Public.Verify(CtxIdentitySig, digest, edSig, mldsaSig); err != nil {
		t.Fatalf("Verify (correct): %v", err)
	}
	// Wrong context — both sigs invalid.
	if err := sk.Public.Verify(CtxLinkKDF, digest, edSig, mldsaSig); err == nil {
		t.Fatal("Verify with wrong context should fail")
	}
	// Tampered digest.
	tampered := append([]byte(nil), digest...)
	tampered[0] ^= 0x01
	if err := sk.Public.Verify(CtxIdentitySig, tampered, edSig, mldsaSig); err == nil {
		t.Fatal("Verify with tampered digest should fail")
	}
}

func TestFingerprintStable(t *testing.T) {
	sk, _ := Generate(rand.Reader)
	fp1 := sk.Public.Fingerprint()
	fp2 := sk.Public.Fingerprint()
	if !bytes.Equal(fp1[:], fp2[:]) {
		t.Fatalf("fingerprint not stable: %x vs %x", fp1, fp2)
	}
	if len(fp1) != FingerprintSize {
		t.Fatalf("fingerprint size %d != %d", len(fp1), FingerprintSize)
	}
}

func TestFingerprintsDiffer(t *testing.T) {
	a, _ := Generate(rand.Reader)
	b, _ := Generate(rand.Reader)
	fa := a.Public.Fingerprint()
	fb := b.Public.Fingerprint()
	if bytes.Equal(fa[:], fb[:]) {
		t.Fatal("two fresh identities produced the same fingerprint")
	}
}
