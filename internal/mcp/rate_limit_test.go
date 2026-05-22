package mcp

import (
	"testing"
	"time"
)

func TestParseLimitSpec(t *testing.T) {
	cases := []struct {
		in       string
		capacity int
		perSec   float64
		ok       bool
	}{
		{"20/hour", 20, 20.0 / 3600, true},
		{"5/minute", 5, 5.0 / 60, true},
		{"1/second", 1, 1, true},
		{"100/day", 100, 100.0 / 86400, true},
		{"20/h", 20, 20.0 / 3600, true},
		{"", 0, 0, false},
		{"20", 0, 0, false},
		{"abc/hour", 0, 0, false},
		{"-5/hour", 0, 0, false},
		{"0/hour", 0, 0, false},
		{"5/week", 0, 0, false},
	}
	for _, tc := range cases {
		t.Run(tc.in, func(t *testing.T) {
			cap, ps, ok := parseLimitSpec(tc.in)
			if ok != tc.ok {
				t.Errorf("ok = %v, want %v", ok, tc.ok)
				return
			}
			if !ok {
				return
			}
			if cap != tc.capacity {
				t.Errorf("capacity = %d, want %d", cap, tc.capacity)
			}
			if ps < tc.perSec*0.99 || ps > tc.perSec*1.01 {
				t.Errorf("perSec = %f, want %f", ps, tc.perSec)
			}
		})
	}
}

func TestRateLimiterEnforces(t *testing.T) {
	r := newRateLimiter()
	now := time.Unix(1_000_000, 0)
	r.now = func() time.Time { return now }

	// 3/hour — three calls at t=0 fine, fourth at t=0 denied.
	for i := 0; i < 3; i++ {
		ok, reason := r.Allow("test|1", "3/hour")
		if !ok {
			t.Fatalf("call %d denied: %s", i+1, reason)
		}
	}
	ok, _ := r.Allow("test|1", "3/hour")
	if ok {
		t.Fatal("call 4 should be denied (bucket empty)")
	}

	// 30 minutes later — bucket refilled half. ~1.5 tokens.
	now = now.Add(30 * time.Minute)
	ok, _ = r.Allow("test|1", "3/hour")
	if !ok {
		t.Fatal("after 30min should have refilled past 1 token")
	}

	// Different key — separate bucket.
	ok, _ = r.Allow("test|2", "3/hour")
	if !ok {
		t.Fatal("different key should have full bucket")
	}
}

func TestRateLimiterEmptySpecAlwaysAllows(t *testing.T) {
	r := newRateLimiter()
	for i := 0; i < 1000; i++ {
		ok, _ := r.Allow("x", "")
		if !ok {
			t.Fatal("empty spec should always allow")
		}
	}
}

func TestRateLimiterMalformedSpecAllows(t *testing.T) {
	// Malformed spec → fail open. Policy validator should have
	// caught the typo at load time, but this is the runtime fallback.
	r := newRateLimiter()
	ok, _ := r.Allow("x", "twenty/hour")
	if !ok {
		t.Error("malformed spec should not deny — fail open")
	}
}
