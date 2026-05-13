// Copyright (C) 2025-2026, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

// Example program: generate two PQ-RNS identities, exchange
// announce-style fingerprints, run a hybrid sign/verify pair.
//
//	go run ./_examples/basic
package main

import (
	"fmt"
	"log"

	"github.com/luxfi/pqrns/pkg/identity"
)

func main() {
	alice, err := identity.Generate(nil)
	must(err)
	bob, err := identity.Generate(nil)
	must(err)

	fa := alice.Public.Fingerprint()
	fb := bob.Public.Fingerprint()
	fmt.Printf("alice fingerprint: %x\n", fa)
	fmt.Printf("bob   fingerprint: %x\n", fb)

	// Alice signs a message under the PQ-RNS identity context.
	msg := []byte("hello-from-alice")
	edSig, mldsaSig, err := alice.Sign(identity.CtxIdentitySig, msg)
	must(err)
	fmt.Printf("\nalice signed %d-byte message:\n", len(msg))
	fmt.Printf("  ed25519:    %d bytes\n", len(edSig))
	fmt.Printf("  ml-dsa-65:  %d bytes\n", len(mldsaSig))

	// Bob verifies — both legs must pass.
	if err := alice.Public.Verify(identity.CtxIdentitySig, msg, edSig, mldsaSig); err != nil {
		log.Fatalf("verify (alice's sig): %v", err)
	}
	fmt.Println("✓ bob verified alice's hybrid signature (Ed25519 + ML-DSA-65)")

	// Negative: a different context refuses to verify.
	if err := alice.Public.Verify(identity.CtxLinkKDF, msg, edSig, mldsaSig); err == nil {
		log.Fatal("verify with wrong context should have failed")
	}
	fmt.Println("✓ verify with wrong context refused (domain separation enforced)")
}

func must(err error) {
	if err != nil {
		log.Fatal(err)
	}
}
