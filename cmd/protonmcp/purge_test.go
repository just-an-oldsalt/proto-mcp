package main

import (
	"testing"
	"time"
)

func TestParseDurationFlexible(t *testing.T) {
	cases := []struct {
		in   string
		want time.Duration
		ok   bool
	}{
		{"30d", 30 * 24 * time.Hour, true},
		{"7d", 7 * 24 * time.Hour, true},
		{"1d", 24 * time.Hour, true},
		{"24h", 24 * time.Hour, true},
		{"90m", 90 * time.Minute, true},
		{"45s", 45 * time.Second, true},
		{"", 0, false},
		{"7days", 0, false}, // not Go's shape
		{"-7d", 0, false},   // our regex anchors to digits only
		{"abc", 0, false},
	}
	for _, tc := range cases {
		t.Run(tc.in, func(t *testing.T) {
			got, err := parseDurationFlexible(tc.in)
			if (err == nil) != tc.ok {
				t.Errorf("ok = %v, want %v (err=%v)", err == nil, tc.ok, err)
				return
			}
			if tc.ok && got != tc.want {
				t.Errorf("got %v, want %v", got, tc.want)
			}
		})
	}
}
