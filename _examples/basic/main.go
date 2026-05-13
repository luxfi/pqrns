// Copyright (C) 2025-2026, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

// Example: generate two zwing hybrid identities, exchange announce-
// style fingerprints, run a hybrid sign/verify pair under the PQ-RNS
// identity domain-separation context.
//
//	go run ./_examples/basic
package main

import (
	"fmt"
	"log"

	"github.com/luxfi/zwing"

	"github.com/luxfi/pqrns/pkg/identity"
)

func main() {
	alice, err := zwing.GenerateIdentity()
	must(err)
	bob, err := zwing.GenerateIdentity()
	must(err)

	fa := identity.Fingerprint(alice.Public())
	fb := identity.Fingerprint(bob.Public())
	fmt.Printf("alice fingerprint: %x\n", fa)
	fmt.Printf("bob   fingerprint: %x\n", fb)

	msg := []byte("hello-from-alice")
	sig := alice.Sign([]byte(identity.CtxIdentitySig), msg)
	fmt.Printf("\nalice signed %d-byte message via zwing hybrid (Ed25519 + ML-DSA-65):\n", len(msg))
	fmt.Printf("  signature blob:  %d bytes\n", len(sig))

	if err := alice.Public().Verify([]byte(identity.CtxIdentitySig), msg, sig); err != nil {
		log.Fatalf("verify (alice's sig): %v", err)
	}
	fmt.Println("✓ bob verified alice's hybrid signature")

	if err := alice.Public().Verify([]byte(identity.CtxLinkKDF), msg, sig); err == nil {
		log.Fatal("verify with wrong context should have failed")
	}
	fmt.Println("✓ verify with wrong context refused (domain separation enforced)")
}

func must(err error) {
	if err != nil {
		log.Fatal(err)
	}
}
