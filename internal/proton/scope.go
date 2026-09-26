package proton

import (
	"encoding/json"
	"errors"
	"fmt"

	gpa "github.com/ProtonMail/go-proton-api"
)

// CodeMissingScope is the API code Proton returns when the access token
// was not granted a scope the endpoint needs. The body looks like:
//
//	{"Code":9100,"Error":"Access token does not have sufficient scope",
//	 "Details":{"MissingScopes":["calendar"]}}
//
// go-proton-api has no constant for it.
const CodeMissingScope gpa.Code = 9100

// ErrMissingScope marks an error caused by Code 9100. Callers test for
// it with errors.Is. WrapMissingScope adds it to an error chain; the
// original *gpa.APIError stays in the chain, so MissingScopes still
// works on the wrapped error.
var ErrMissingScope = errors.New("proton: access token is missing a required scope")

// CalendarScopeNotice is the one sentence every surface (MCP tools,
// daemon log, CLI, doctor) uses to explain a session that can list
// calendars but not read their events. The cause is the client identity
// we log in as, not anything the user did, so re-login won't help.
// proto-mcp issue #110 tracks the real fix.
const CalendarScopeNotice = "Calendar events are unavailable: Proton did not grant this session the 'calendar' scope " +
	"(proto-mcp issue #110). Calendar names are available via calendar_list; events are not."

// IsMissingScope reports whether err is (or wraps) a Code 9100 response
// or ErrMissingScope.
func IsMissingScope(err error) bool {
	if err == nil {
		return false
	}
	if errors.Is(err, ErrMissingScope) {
		return true
	}
	_, ok := missingScopeAPIError(err)
	return ok
}

// MissingScopes returns the scopes a Code 9100 response says the token
// lacks, decoded from its Details. It returns nil when err isn't a 9100
// response, or when the response carries no parseable MissingScopes —
// use IsMissingScope to tell those apart.
func MissingScopes(err error) []string {
	apiErr, ok := missingScopeAPIError(err)
	if !ok || len(apiErr.Details) == 0 {
		return nil
	}
	var d struct {
		MissingScopes []string `json:"MissingScopes"`
	}
	if json.Unmarshal(apiErr.Details, &d) != nil {
		return nil
	}
	return d.MissingScopes
}

// WrapMissingScope returns err with ErrMissingScope added to its chain
// when err is a Code 9100 response, and err unchanged otherwise.
func WrapMissingScope(err error) error {
	if err == nil || errors.Is(err, ErrMissingScope) {
		return err
	}
	if _, ok := missingScopeAPIError(err); !ok {
		return err
	}
	return fmt.Errorf("%w: %w", ErrMissingScope, err)
}

// missingScopeAPIError finds a Code 9100 APIError in err's chain.
// go-proton-api returns *APIError (catchAPIError wraps it with %w), but
// APIError also satisfies error by value, so accept both.
func missingScopeAPIError(err error) (*gpa.APIError, bool) {
	var ptr *gpa.APIError
	if errors.As(err, &ptr) && ptr != nil {
		return ptr, ptr.Code == CodeMissingScope
	}
	var val gpa.APIError
	if errors.As(err, &val) {
		return &val, val.Code == CodeMissingScope
	}
	return nil, false
}
