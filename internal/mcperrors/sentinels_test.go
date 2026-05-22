package mcperrors

import (
	"errors"
	"fmt"
	"testing"
)

// TestSentinelsAreDistinct guards against the future "let's
// consolidate these" refactor that would silently change
// classification behavior. errors.Is must distinguish each pair.
func TestSentinelsAreDistinct(t *testing.T) {
	sentinels := []error{
		ErrUserCanceled,
		ErrAuthFailed,
		ErrNetwork,
		ErrUnlockFailed,
		ErrPolicyDenied,
	}
	for i, a := range sentinels {
		for j, b := range sentinels {
			if i == j {
				continue
			}
			if errors.Is(a, b) {
				t.Errorf("Is(%v, %v) returned true — sentinels collapsed", a, b)
			}
		}
	}
}

// TestWrappedSentinelStaysIdentifiable confirms that wrapping with
// fmt.Errorf %w keeps Is functional — the whole point of this
// package over stringly-typed errors.
func TestWrappedSentinelStaysIdentifiable(t *testing.T) {
	wrapped := fmt.Errorf("touchid helper exited 1: %w", ErrUserCanceled)
	if !errors.Is(wrapped, ErrUserCanceled) {
		t.Error("wrapped ErrUserCanceled didn't survive errors.Is")
	}
	if errors.Is(wrapped, ErrAuthFailed) {
		t.Error("ErrUserCanceled matched ErrAuthFailed — sentinels not distinct")
	}
}
