package mcptools

import "testing"

// D41 — colours must be validated against Proton's fixed palette
// before the API call, and normalized to the canonical upper-case form
// Proton stores.
func TestNormalizeLabelColor(t *testing.T) {
	cases := []struct {
		name    string
		in      string
		want    string
		wantErr bool
	}{
		{"empty is allowed (Proton default)", "", "", false},
		{"exact palette value", "#8080FF", "#8080FF", false},
		{"lower-case is snapped to canonical", "#ec3e7c", "#EC3E7C", false},
		{"surrounding whitespace tolerated", "  #258723 ", "#258723", false},
		{"non-palette hex rejected", "#FF6B6B", "", true},
		{"arbitrary hex rejected", "#00ff00", "", true},
		{"garbage rejected", "blue", "", true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, err := normalizeLabelColor(tc.in)
			if tc.wantErr {
				if err == nil {
					t.Fatalf("normalizeLabelColor(%q) = %q, nil; want error", tc.in, got)
				}
				return
			}
			if err != nil {
				t.Fatalf("normalizeLabelColor(%q) returned error: %v", tc.in, err)
			}
			if got != tc.want {
				t.Errorf("normalizeLabelColor(%q) = %q; want %q", tc.in, got, tc.want)
			}
		})
	}
}

// Every palette entry must round-trip through the validator unchanged —
// guards against a typo in the hardcoded list.
func TestNormalizeLabelColor_AllPaletteValuesValid(t *testing.T) {
	for _, c := range protonAccentColors {
		got, err := normalizeLabelColor(c)
		if err != nil {
			t.Errorf("palette value %q rejected by its own validator: %v", c, err)
		}
		if got != c {
			t.Errorf("palette value %q normalized to %q; want unchanged", c, got)
		}
	}
	if len(protonAccentColors) != 20 {
		t.Errorf("expected 20 Proton accent colors, got %d", len(protonAccentColors))
	}
}
