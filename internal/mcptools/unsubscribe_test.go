package mcptools

import (
	"reflect"
	"strings"
	"testing"
)

func TestParseUnsubscribe(t *testing.T) {
	const oneClick = "List-Unsubscribe=One-Click"
	longHTTPS := "https://example.com/u?t=" + strings.Repeat("a", 2048)

	tests := []struct {
		name  string
		unsub string
		post  string
		want  *unsubscribeInfo
	}{
		{
			name:  "empty",
			unsub: "",
			want:  nil,
		},
		{
			name:  "mailto only",
			unsub: "<mailto:unsub@example.com?subject=unsubscribe>",
			want:  &unsubscribeInfo{HTTPS: []string{}, Mailto: []string{"mailto:unsub@example.com?subject=unsubscribe"}},
		},
		{
			name:  "https only, no post",
			unsub: "<https://example.com/u/abc>",
			want:  &unsubscribeInfo{HTTPS: []string{"https://example.com/u/abc"}, Mailto: []string{}},
		},
		{
			name:  "both with one-click post",
			unsub: "<mailto:u@example.com>, <https://example.com/u/abc>",
			post:  oneClick,
			want: &unsubscribeInfo{
				HTTPS:    []string{"https://example.com/u/abc"},
				Mailto:   []string{"mailto:u@example.com"},
				OneClick: true,
			},
		},
		{
			name:  "post case-insensitive and trimmed",
			unsub: "<https://example.com/u>",
			post:  "  list-unsubscribe=one-click ",
			want:  &unsubscribeInfo{HTTPS: []string{"https://example.com/u"}, Mailto: []string{}, OneClick: true},
		},
		{
			name:  "post misspelled",
			unsub: "<https://example.com/u>",
			post:  "List-Unsubscribe=OneClick",
			want:  &unsubscribeInfo{HTTPS: []string{"https://example.com/u"}, Mailto: []string{}},
		},
		{
			name:  "post present but only mailto",
			unsub: "<mailto:u@example.com>",
			post:  oneClick,
			want:  &unsubscribeInfo{HTTPS: []string{}, Mailto: []string{"mailto:u@example.com"}},
		},
		{
			name:  "http javascript data dropped",
			unsub: "<http://example.com/u>, <javascript:alert(1)>, <data:text/html,<b>x</b>>, <ftp://example.com/u>",
			post:  oneClick,
			want:  nil,
		},
		{
			name:  "http dropped but https kept",
			unsub: "<http://example.com/u>, <HTTPS://example.com/u2>",
			post:  oneClick,
			want:  &unsubscribeInfo{HTTPS: []string{"HTTPS://example.com/u2"}, Mailto: []string{}, OneClick: true},
		},
		{
			name:  "unbracketed junk",
			unsub: "https://example.com/u, mailto:u@example.com",
			post:  oneClick,
			want:  nil,
		},
		{
			name:  "junk between entries ignored",
			unsub: "click here (please) <https://example.com/u> garbage",
			want:  &unsubscribeInfo{HTTPS: []string{"https://example.com/u"}, Mailto: []string{}},
		},
		{
			name:  "more than four entries",
			unsub: "<https://a.example/1>, <https://a.example/2>, <https://a.example/3>, <https://a.example/4>, <https://a.example/5>",
			want: &unsubscribeInfo{
				HTTPS:  []string{"https://a.example/1", "https://a.example/2", "https://a.example/3", "https://a.example/4"},
				Mailto: []string{},
			},
		},
		{
			name:  "over-long uri dropped",
			unsub: "<" + longHTTPS + ">",
			want:  nil,
		},
		{
			name:  "CRLF inside uri dropped",
			unsub: "<https://example.com/u\r\nX-Evil: 1>, <mailto:u@example.com>",
			want:  &unsubscribeInfo{HTTPS: []string{}, Mailto: []string{"mailto:u@example.com"}},
		},
		{
			name:  "control char and non-ASCII space dropped",
			unsub: "<https://example.com/\x1b[31mu>, <https://example.com/\u0085>, <https://example.com/a\u00a0b>",
			want:  nil,
		},
		{
			// RFC 2369 section 2: whitespace inside <> is ignored, so a
			// URL wrapped across folded header lines is joined back up.
			name:  "folding whitespace inside uri ignored",
			unsub: "<https://example.com/unsub?id= 123\t456>, < mailto:u@example.com >",
			want:  &unsubscribeInfo{HTTPS: []string{"https://example.com/unsub?id=123456"}, Mailto: []string{"mailto:u@example.com"}},
		},
		{
			name:  "https with userinfo dropped",
			unsub: "<https://user:pass@example.com/u>, <https://@example.com/u>",
			want:  nil,
		},
		{
			name:  "https without host dropped",
			unsub: "<https:///u>, <https:example.com>",
			want:  nil,
		},
		{
			name:  "mailto invalid addresses dropped",
			unsub: "<mailto:>, <mailto:not-an-address>, <mailto:a@example.com,b@example.com>, <mailto:?to=a@example.com>",
			want:  nil,
		},
		{
			name:  "mailto display name rejected",
			unsub: "<mailto:Evil%20%3Ca@example.com%3E>",
			want:  nil,
		},
		{
			name:  "duplicates collapsed",
			unsub: "<https://example.com/u>, <https://example.com/u>",
			want:  &unsubscribeInfo{HTTPS: []string{"https://example.com/u"}, Mailto: []string{}},
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := parseUnsubscribe(tc.unsub, tc.post)
			if !reflect.DeepEqual(got, tc.want) {
				t.Errorf("parseUnsubscribe(%q, %q)\n got  %+v\n want %+v", tc.unsub, tc.post, got, tc.want)
			}
		})
	}
}
