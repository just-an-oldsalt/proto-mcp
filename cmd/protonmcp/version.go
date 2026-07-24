package main

import (
	"context"
	"fmt"

	"github.com/just-an-oldsalt/proto-mcp/internal/buildinfo"
)

// runVersion prints the build identity. Kept deliberately terse and
// stable — it's what a bug report gets pasted into, and what
// `protonmcp doctor` compares across binaries to spot a partial
// upgrade.
func runVersion(_ context.Context, args []string) error {
	if err := requireNoArgs("version", args); err != nil {
		return err
	}
	fmt.Println("protonmcp " + buildinfo.String())
	return nil
}
