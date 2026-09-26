package proton

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"reflect"
	"testing"

	gpa "github.com/ProtonMail/go-proton-api"
)

// scopeBody is the literal 403 body Proton returns for /calendar/v1/*/events
// on a session without the calendar scope (issue #110).
const scopeBody = `{"Code":9100,"Error":"Access token does not have sufficient scope","Details":{"MissingScopes":["calendar"]}}`

// apiErrFromBody decodes body the way go-proton-api does and wraps it the
// way catchAPIError does, so the tests exercise the real error shape.
func apiErrFromBody(t *testing.T, body string, status int) error {
	t.Helper()
	apiErr := &gpa.APIError{}
	if err := json.Unmarshal([]byte(body), apiErr); err != nil {
		t.Fatalf("decode APIError: %v", err)
	}
	apiErr.Status = status
	return fmt.Errorf("%v GET https://mail-api.proton.me/calendar/v1/x/events: %w", status, apiErr)
}

func TestMissingScopes_RealAPIError(t *testing.T) {
	err := apiErrFromBody(t, scopeBody, 403)

	if !IsMissingScope(err) {
		t.Fatal("IsMissingScope = false for a Code 9100 response")
	}
	if got := MissingScopes(err); !reflect.DeepEqual(got, []string{"calendar"}) {
		t.Errorf("MissingScopes = %v, want [calendar]", got)
	}

	wrapped := WrapMissingScope(err)
	if !errors.Is(wrapped, ErrMissingScope) {
		t.Error("wrapped error doesn't match ErrMissingScope")
	}
	// The original APIError must survive wrapping, including a second
	// layer of context from the caller.
	outer := fmt.Errorf("get events for calendar cal-1: %w", wrapped)
	if got := MissingScopes(outer); !reflect.DeepEqual(got, []string{"calendar"}) {
		t.Errorf("MissingScopes(wrapped) = %v, want [calendar]", got)
	}
	var apiErr *gpa.APIError
	if !errors.As(outer, &apiErr) || apiErr.Status != 403 {
		t.Errorf("APIError lost from the chain: %v", outer)
	}
	if WrapMissingScope(wrapped) != wrapped {
		t.Error("WrapMissingScope should not double-wrap")
	}
}

func TestMissingScopes_ValueAPIError(t *testing.T) {
	err := fmt.Errorf("ctx: %w", gpa.APIError{Code: CodeMissingScope, Details: gpa.ErrDetails(`{"MissingScopes":["calendar","mail"]}`)})
	if got := MissingScopes(err); !reflect.DeepEqual(got, []string{"calendar", "mail"}) {
		t.Errorf("MissingScopes = %v", got)
	}
}

func TestMissingScopes_9100WithoutDetails(t *testing.T) {
	err := apiErrFromBody(t, `{"Code":9100,"Error":"Access token does not have sufficient scope"}`, 403)
	if !IsMissingScope(err) {
		t.Error("IsMissingScope = false for 9100 without Details")
	}
	if got := MissingScopes(err); got != nil {
		t.Errorf("MissingScopes = %v, want nil", got)
	}
}

func TestMissingScopes_NonMatching(t *testing.T) {
	cases := map[string]error{
		"nil":           nil,
		"plain":         errors.New("403 insufficient scope (Code=9100)"),
		"hv 9001":       apiErrFromBody(t, `{"Code":9001,"Error":"Human verification required","Details":{"HumanVerificationToken":"x"}}`, 422),
		"other 403":     apiErrFromBody(t, `{"Code":2011,"Error":"Forbidden"}`, 403),
		"net error":     fmt.Errorf("fetch: %w", io.ErrUnexpectedEOF),
		"nil *APIError": fmt.Errorf("x: %w", (*gpa.APIError)(nil)),
	}
	for name, err := range cases {
		t.Run(name, func(t *testing.T) {
			if IsMissingScope(err) {
				t.Error("IsMissingScope = true")
			}
			if got := MissingScopes(err); got != nil {
				t.Errorf("MissingScopes = %v, want nil", got)
			}
			if got := WrapMissingScope(err); got != err {
				t.Errorf("WrapMissingScope changed a non-9100 error: %v", got)
			}
			if errors.Is(WrapMissingScope(err), ErrMissingScope) {
				t.Error("non-9100 error matched ErrMissingScope")
			}
		})
	}
}
