package proton

import (
	"context"
	"encoding/json"
	"errors"
	"testing"

	gpa "github.com/ProtonMail/go-proton-api"
)

// hv9001JSON mirrors the real GET /core/v4/users 422 body captured while
// diagnosing this account's login — same field names, same "ownership-*"
// method names and WebUrl shape, sanitized token/URL values.
const hv9001JSON = `{
  "Status": 422,
  "Code": 9001,
  "Error": "Human verification required",
  "Details": {
    "HumanVerificationToken": "test-token-abc123",
    "HumanVerificationMethods": ["ownership-email", "ownership-sms"],
    "Direct": 1,
    "Description": "",
    "Title": "Verify account",
    "WebUrl": "https://verify.proton.me/?methods=ownership-email%2Cownership-sms&token=test-token-abc123",
    "ExpiresAt": 1789143997
  }
}`

func newHVAPIError(t *testing.T) *gpa.APIError {
	t.Helper()
	var err gpa.APIError
	if unmarshalErr := json.Unmarshal([]byte(hv9001JSON), &err); unmarshalErr != nil {
		t.Fatalf("unmarshal fixture: %v", unmarshalErr)
	}
	return &err
}

// TestTryWithHV_RetriesWithOriginalToken is the regression test for the
// bug this fixes: a prior version minted its own verification code via
// SendVerificationCode and retried with hv.Token replaced by that
// user-typed code. Proton rejected it with "Invalid or expired
// verification token" (Code 12087) because the token that comes back
// from the /users/code flow has nothing to do with the session the
// original 9001 error identified. The fix is to echo back the *exact*
// HumanVerificationToken/Methods from the original error, unmodified,
// after the user confirms they completed verification in the browser.
func TestTryWithHV_RetriesWithOriginalToken(t *testing.T) {
	hvErr := newHVAPIError(t)
	confirmCalls := 0
	creds := &Credentials{
		AskHVBrowserConfirm: func(_ context.Context, webURL string) error {
			confirmCalls++
			if webURL != "https://verify.proton.me/?methods=ownership-email%2Cownership-sms&token=test-token-abc123" {
				t.Errorf("unexpected webURL passed to confirm callback: %q", webURL)
			}
			return nil
		},
	}

	var gotRetryHV *gpa.APIHVDetails
	calls := 0
	result, err := tryWithHV(context.Background(), creds, func(hv *gpa.APIHVDetails) (string, error) {
		calls++
		if calls == 1 {
			if hv != nil {
				t.Errorf("first call should pass nil hv, got %+v", hv)
			}
			return "", hvErr
		}
		gotRetryHV = hv
		return "success", nil
	})
	if err != nil {
		t.Fatalf("tryWithHV returned error: %v", err)
	}
	if result != "success" {
		t.Errorf("result = %q, want %q", result, "success")
	}
	if calls != 2 {
		t.Fatalf("call count = %d, want 2", calls)
	}
	if confirmCalls != 1 {
		t.Errorf("AskHVBrowserConfirm called %d times, want 1", confirmCalls)
	}
	if gotRetryHV == nil {
		t.Fatal("retry call received nil hv")
	}
	if gotRetryHV.Token != "test-token-abc123" {
		t.Errorf("retry token = %q, want the original HumanVerificationToken unmodified", gotRetryHV.Token)
	}
	if len(gotRetryHV.Methods) != 2 || gotRetryHV.Methods[0] != "ownership-email" || gotRetryHV.Methods[1] != "ownership-sms" {
		t.Errorf("retry methods = %v, want the original HumanVerificationMethods unmodified", gotRetryHV.Methods)
	}
}

// TestTryWithHV_NoRetryOnSuccess ensures the common path (no 9001 at
// all) doesn't invoke the browser-confirm callback or retry.
func TestTryWithHV_NoRetryOnSuccess(t *testing.T) {
	creds := &Credentials{
		AskHVBrowserConfirm: func(context.Context, string) error {
			t.Fatal("AskHVBrowserConfirm should not be called when the first call succeeds")
			return nil
		},
	}
	calls := 0
	result, err := tryWithHV(context.Background(), creds, func(*gpa.APIHVDetails) (int, error) {
		calls++
		return 42, nil
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result != 42 {
		t.Errorf("result = %d, want 42", result)
	}
	if calls != 1 {
		t.Errorf("call count = %d, want 1", calls)
	}
}

// TestTryWithHV_CaptchaOnlyRejected ensures a captcha-only offer fails
// fast with a message pointing at the browser-trust workaround, rather
// than invoking AskHVBrowserConfirm — protonmcp has no way to render or
// solve a captcha challenge.
func TestTryWithHV_CaptchaOnlyRejected(t *testing.T) {
	captchaErr := &gpa.APIError{
		Status: 422,
		Code:   gpa.HumanVerificationRequired,
		Details: gpa.ErrDetails(`{
			"HumanVerificationToken": "tok",
			"HumanVerificationMethods": ["captcha"]
		}`),
	}
	creds := &Credentials{
		AskHVBrowserConfirm: func(context.Context, string) error {
			t.Fatal("AskHVBrowserConfirm should not be called for a captcha-only offer")
			return nil
		},
	}
	_, err := tryWithHV(context.Background(), creds, func(*gpa.APIHVDetails) (int, error) {
		return 0, captchaErr
	})
	if err == nil {
		t.Fatal("expected an error for a captcha-only offer, got nil")
	}
}

// TestTryWithHV_NoPromptAvailable ensures a nil AskHVBrowserConfirm
// fails with a clear error (surfacing the WebUrl) rather than a nil
// pointer panic — relevant for any future non-interactive caller.
func TestTryWithHV_NoPromptAvailable(t *testing.T) {
	hvErr := newHVAPIError(t)
	creds := &Credentials{} // AskHVBrowserConfirm left nil
	_, err := tryWithHV(context.Background(), creds, func(*gpa.APIHVDetails) (int, error) {
		return 0, hvErr
	})
	if err == nil {
		t.Fatal("expected an error when no prompt callback is set")
	}
}

// TestTryWithHV_NonHVErrorPassesThrough ensures an unrelated API error
// (or any other error) is returned as-is, not swallowed or retried.
func TestTryWithHV_NonHVErrorPassesThrough(t *testing.T) {
	wantErr := errors.New("network exploded")
	creds := &Credentials{
		AskHVBrowserConfirm: func(context.Context, string) error {
			t.Fatal("AskHVBrowserConfirm should not be called for a non-HV error")
			return nil
		},
	}
	calls := 0
	_, err := tryWithHV(context.Background(), creds, func(*gpa.APIHVDetails) (int, error) {
		calls++
		return 0, wantErr
	})
	if !errors.Is(err, wantErr) {
		t.Errorf("err = %v, want %v", err, wantErr)
	}
	if calls != 1 {
		t.Errorf("call count = %d, want 1 (no retry on non-HV error)", calls)
	}
}

func TestHasOwnershipMethod(t *testing.T) {
	tests := []struct {
		methods []string
		want    bool
	}{
		{[]string{"ownership-email", "ownership-sms"}, true},
		{[]string{"ownership-email"}, true},
		{[]string{"captcha", "ownership-sms"}, true}, // captcha alongside a usable method
		{[]string{"captcha"}, false},
		{[]string{"captcha", "sms"}, false},         // bare "sms" isn't "ownership-sms"
		{[]string{"ownership-captcha"}, false},      // fails closed: not a visitable-URL flow
		{[]string{"ownership-email-future"}, false}, // unrecognised: fail closed, don't guess
		{nil, false},
	}
	for _, tt := range tests {
		if got := hasOwnershipMethod(tt.methods); got != tt.want {
			t.Errorf("hasOwnershipMethod(%v) = %v, want %v", tt.methods, got, tt.want)
		}
	}
}
