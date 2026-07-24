package serve

import (
	"context"
	"log/slog"
	"strings"
	"testing"

	"github.com/just-an-oldsalt/proto-mcp/internal/mcp"
	"github.com/just-an-oldsalt/proto-mcp/internal/mcptools"
	"github.com/just-an-oldsalt/proto-mcp/internal/policy"
)

func testEngine(t *testing.T) *policy.Engine {
	t.Helper()
	// Empty override path → the embedded default.yaml only, which is
	// what ships and therefore what coverage must hold for.
	e, err := policy.New(context.Background(), "",
		slog.New(slog.NewTextHandler(nopWriter{}, nil)))
	if err != nil {
		t.Fatalf("policy.New: %v", err)
	}
	return e
}

type nopWriter struct{}

func (nopWriter) Write(p []byte) (int, error) { return len(p), nil }

// TestEveryShippedToolHasAPolicyEntry is the regression guard that
// gives the coverage check its value: add a tool to mcptools.All
// without a stanza in default.yaml and this fails, rather than the tool
// shipping and denying every call at runtime for reasons no error
// message explains.
func TestEveryShippedToolHasAPolicyEntry(t *testing.T) {
	engine := testEngine(t)
	tools := mcptools.All(mcptools.Deps{})

	if len(tools) == 0 {
		t.Fatal("mcptools.All returned nothing; this test would pass vacuously")
	}

	if err := validatePolicyCoverage(engine, tools); err != nil {
		t.Error(err)
	}
}

// TestValidatePolicyCoverageFlagsMissingEntry proves the check can
// actually fail — without this, the test above passes for a validator
// that never reports anything.
func TestValidatePolicyCoverageFlagsMissingEntry(t *testing.T) {
	engine := testEngine(t)
	tools := []mcp.Tool{
		{Name: "mail_list"},                  // real, covered
		{Name: "mail_definitely_not_a_tool"}, // invented, uncovered
	}

	err := validatePolicyCoverage(engine, tools)
	if err == nil {
		t.Fatal("expected an error for a tool with no policy entry")
	}
	if !strings.Contains(err.Error(), "mail_definitely_not_a_tool") {
		t.Errorf("error should name the uncovered tool, got: %v", err)
	}
	if strings.Contains(err.Error(), "mail_list") {
		t.Errorf("error should not name the covered tool, got: %v", err)
	}
}

// TestValidatePolicyCoverageNilEngineIsAllowed — Setup permits a nil
// policy engine (every tool runs unguarded), which some tests rely on.
// Coverage checking must not turn that opt-out into a startup failure.
func TestValidatePolicyCoverageNilEngineIsAllowed(t *testing.T) {
	if err := validatePolicyCoverage(nil, []mcp.Tool{{Name: "whatever"}}); err != nil {
		t.Errorf("nil engine should skip coverage checking, got: %v", err)
	}
}

// TestValidatePolicyCoverageErrorIsSorted keeps the failure text stable
// across runs so it doesn't look like a different problem each restart.
func TestValidatePolicyCoverageErrorIsSorted(t *testing.T) {
	engine := testEngine(t)
	tools := []mcp.Tool{
		{Name: "zzz_missing"},
		{Name: "aaa_missing"},
	}
	err := validatePolicyCoverage(engine, tools)
	if err == nil {
		t.Fatal("expected an error")
	}
	msg := err.Error()
	if strings.Index(msg, "aaa_missing") > strings.Index(msg, "zzz_missing") {
		t.Errorf("names should be sorted, got: %v", err)
	}
}
