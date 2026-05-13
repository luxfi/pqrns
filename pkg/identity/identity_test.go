// Copyright (C) 2025-2026, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package identity_test

import (
	"bytes"
	"testing"

	"github.com/luxfi/zwing"

	"github.com/luxfi/pqrns/pkg/identity"
)

func TestSignAndVerifyHybrid(t *testing.T) {
	sk, err := zwing.GenerateIdentity()
	if err != nil {
		t.Fatalf("zwing.GenerateIdentity: %v", err)
	}

	digest := []byte("test-digest-bytes")
	sig := sk.Sign([]byte(identity.CtxIdentitySig), digest)

	if err := sk.Public().Verify([]byte(identity.CtxIdentitySig), digest, sig); err != nil {
		t.Fatalf("Verify (correct): %v", err)
	}

	// Wrong context refuses to verify.
	if err := sk.Public().Verify([]byte(identity.CtxLinkKDF), digest, sig); err == nil {
		t.Fatal("Verify with wrong context should fail")
	}

	// Tampered digest refuses to verify.
	tampered := append([]byte(nil), digest...)
	tampered[0] ^= 0x01
	if err := sk.Public().Verify([]byte(identity.CtxIdentitySig), tampered, sig); err == nil {
		t.Fatal("Verify with tampered digest should fail")
	}
}

func TestFingerprintStable(t *testing.T) {
	sk, _ := zwing.GenerateIdentity()
	fp1 := identity.Fingerprint(sk.Public())
	fp2 := identity.Fingerprint(sk.Public())
	if !bytes.Equal(fp1[:], fp2[:]) {
		t.Fatalf("fingerprint not stable: %x vs %x", fp1, fp2)
	}
	if len(fp1) != identity.FingerprintSize {
		t.Fatalf("fingerprint size %d != %d", len(fp1), identity.FingerprintSize)
	}
}

func TestFingerprintsDiffer(t *testing.T) {
	a, _ := zwing.GenerateIdentity()
	b, _ := zwing.GenerateIdentity()
	fa := identity.Fingerprint(a.Public())
	fb := identity.Fingerprint(b.Public())
	if bytes.Equal(fa[:], fb[:]) {
		t.Fatal("two fresh identities produced the same fingerprint")
	}
}
