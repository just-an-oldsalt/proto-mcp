package main

import (
	"context"
	"errors"
	"fmt"

	"github.com/just-an-oldsalt/proto-mcp/internal/keystore"
)

// runInspect prints the current Keychain blob (with secret material
// truncated to a 12-char prefix) so you can verify whether
// persistSession is actually updating it across subcommand calls.
//
// Diagnostic only — not a stable interface. Will likely change shape
// or be folded into `status` once the auth-persistence loop is
// debugged.
func runInspect(_ context.Context, _ []string) error {
	stored, err := keystore.Load()
	if err != nil {
		if errors.Is(err, keystore.ErrNotFound) {
			fmt.Println("(no session stored — run `protonmcp login`)")
			return nil
		}
		return err
	}

	fmt.Println("Keychain blob contents:")
	fmt.Printf("  Email:        %s\n", stored.Email)
	fmt.Printf("  UID:          %s\n", truncate(stored.UID, 24))
	fmt.Printf("  AccessToken:  %s\n", truncate(stored.AccessToken, 16))
	fmt.Printf("  RefreshToken: %s\n", truncate(stored.RefreshToken, 16))
	fmt.Printf("  SaltedKeyPass: %d bytes\n", len(stored.SaltedKeyPass.Bytes()))
	fmt.Printf("  Cookies:      %d cookie(s)\n", len(stored.Cookies))
	for i, c := range stored.Cookies {
		fmt.Printf("    [%d] %s = %s  (domain=%q path=%q)\n",
			i, c.Name, truncate(c.Value, 16), c.Domain, c.Path)
	}
	return nil
}

func truncate(s string, n int) string {
	if len(s) <= n {
		return s + fmt.Sprintf(" (len=%d)", len(s))
	}
	return s[:n] + "...(len=" + fmt.Sprintf("%d", len(s)) + ")"
}
