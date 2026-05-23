package mcp

import "testing"

func TestFirstDisallowedRecipient(t *testing.T) {
	cases := []struct {
		name      string
		extracted []string
		allowed   []string
		want      string // "" means allowed
	}{
		{
			name:      "empty allowlist = no restriction",
			extracted: []string{"alice@example.com"},
			allowed:   []string{},
			want:      "",
		},
		{
			name:      "exact match allows",
			extracted: []string{"alice@example.com"},
			allowed:   []string{"alice@example.com"},
			want:      "",
		},
		{
			name:      "case-insensitive match",
			extracted: []string{"Alice@Example.COM"},
			allowed:   []string{"alice@example.com"},
			want:      "",
		},
		{
			name:      "domain suffix allows",
			extracted: []string{"alice@example.com", "bob@example.com"},
			allowed:   []string{"@example.com"},
			want:      "",
		},
		{
			name:      "outsider denied",
			extracted: []string{"alice@example.com", "mallory@evil.com"},
			allowed:   []string{"@example.com"},
			want:      "mallory@evil.com",
		},
		{
			name:      "mixed allowlist",
			extracted: []string{"alice@example.com", "bob@allowed.org"},
			allowed:   []string{"@example.com", "bob@allowed.org"},
			want:      "",
		},
		{
			name:      "no extracted = always allowed",
			extracted: nil,
			allowed:   []string{"@example.com"},
			want:      "",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := firstDisallowedRecipient(tc.extracted, tc.allowed)
			if got != tc.want {
				t.Errorf("got %q, want %q", got, tc.want)
			}
		})
	}
}
