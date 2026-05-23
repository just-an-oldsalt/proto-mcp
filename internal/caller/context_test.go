package caller

import (
	"context"
	"testing"
)

func TestFromContextZeroByDefault(t *testing.T) {
	got := FromContext(context.Background())
	if got != (Caller{}) {
		t.Errorf("FromContext on bare ctx = %+v, want zero", got)
	}
}

func TestWithCallerRoundTrip(t *testing.T) {
	want := Caller{PID: 4242, UID: 501, Binary: "/Applications/Claude.app/Contents/MacOS/Claude"}
	ctx := WithCaller(context.Background(), want)
	got := FromContext(ctx)
	if got != want {
		t.Errorf("FromContext after WithCaller = %+v, want %+v", got, want)
	}
}

func TestWithCallerDoesntLeakAcrossContexts(t *testing.T) {
	// Two independent ctx trees → two independent Caller values.
	a := WithCaller(context.Background(), Caller{PID: 1})
	b := WithCaller(context.Background(), Caller{PID: 2})
	if FromContext(a).PID == FromContext(b).PID {
		t.Errorf("context values leaked across trees")
	}
}

func TestWithCallerOverlay(t *testing.T) {
	parent := WithCaller(context.Background(), Caller{PID: 1})
	child := WithCaller(parent, Caller{PID: 2})
	if FromContext(parent).PID != 1 {
		t.Error("parent ctx mutated by child WithCaller")
	}
	if FromContext(child).PID != 2 {
		t.Error("child WithCaller didn't override parent")
	}
}
