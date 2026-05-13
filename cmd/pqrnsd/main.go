// Copyright (C) 2025-2026, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

// Command pqrnsd is the daemon that serves a PQ-RNS endpoint on one or
// more interfaces (TCP, LoRa via RNode, AX.25, serial, optical, ...).
//
// One and only one binary. No alternate dispatch modes. Subcommands:
//
//	pqrnsd serve        run the daemon
//	pqrnsd announce     manually emit a capability-bearing announce
//	pqrnsd dial         test link establishment to a destination
//	pqrnsd identity     show / rotate the local hybrid identity
//	pqrnsd version
package main

import (
	"fmt"
	"os"

	"github.com/spf13/cobra"

	"github.com/luxfi/pqrns/pkg/identity"
)

func main() {
	root := &cobra.Command{
		Use:   "pqrnsd",
		Short: "PQ-RNS — hybrid post-quantum profile for the Reticulum Network Stack",
	}

	root.AddCommand(
		serveCmd(),
		announceCmd(),
		dialCmd(),
		identityCmd(),
		versionCmd(),
	)

	if err := root.Execute(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

func versionCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "version",
		Short: "print PQ-RNS protocol + identity-kind version",
		Run: func(*cobra.Command, []string) {
			fmt.Printf("PQ-RNS-HYBRID-v1 identity_kind=0x%04x pub_id_size=%d\n",
				uint16(identity.KindHybridV1), identity.PublicIdentitySize)
		},
	}
}

func serveCmd() *cobra.Command {
	return &cobra.Command{Use: "serve", Short: "run the PQ-RNS daemon",
		RunE: notImplemented("serve")}
}
func announceCmd() *cobra.Command {
	return &cobra.Command{Use: "announce", Short: "emit a capability-bearing announce frame",
		RunE: notImplemented("announce")}
}
func dialCmd() *cobra.Command {
	return &cobra.Command{Use: "dial", Short: "test link establishment to a destination",
		RunE: notImplemented("dial")}
}
func identityCmd() *cobra.Command {
	return &cobra.Command{Use: "identity", Short: "show / rotate the local hybrid identity",
		RunE: notImplemented("identity")}
}

func notImplemented(name string) func(*cobra.Command, []string) error {
	return func(*cobra.Command, []string) error {
		return fmt.Errorf("%s: not implemented in this initial drop", name)
	}
}
