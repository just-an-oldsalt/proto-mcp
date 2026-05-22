// Package logging configures the slog default logger with a
// redacting ReplaceAttr hook so we can never accidentally write
// secret material into log records.
//
// SECURITY Foundational #2. The redactor itself lives in
// internal/redact (Phase 4 extracted it so internal/audit can apply
// the same rules to args_json column values). This package is a thin
// shim that pipes slog through redact.Attr.
package logging

import (
	"io"
	"log/slog"
	"os"

	"github.com/just-an-oldsalt/proto-mcp/internal/redact"
)

// Setup installs a default slog logger writing to stderr in text
// format, with the redacting ReplaceAttr hook applied. Call once
// from main(); subsequent slog package-level calls go through it.
//
// w can be nil; defaults to os.Stderr.
func Setup(w io.Writer) {
	if w == nil {
		w = os.Stderr
	}
	handler := slog.NewTextHandler(w, &slog.HandlerOptions{
		Level: slog.LevelInfo,
		ReplaceAttr: func(_ []string, a slog.Attr) slog.Attr {
			return redact.Attr(a)
		},
	})
	slog.SetDefault(slog.New(handler))
}
