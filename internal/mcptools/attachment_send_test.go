package mcptools

import (
	"encoding/base64"
	"strings"
	"testing"
)

func TestDecodeAndValidateAttachments_HappyPath(t *testing.T) {
	body := []byte("hello world")
	in := []sendAttachmentInput{
		{
			Filename:   "report.pdf",
			MIMEType:   "application/pdf",
			ContentB64: base64.StdEncoding.EncodeToString(body),
		},
	}
	got, err := decodeAndValidateAttachments(Deps{}, in)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(got) != 1 {
		t.Fatalf("expected 1 decoded, got %d", len(got))
	}
	if got[0].Filename != "report.pdf" {
		t.Errorf("filename = %q, want report.pdf", got[0].Filename)
	}
	if got[0].MIMEType != "application/pdf" {
		t.Errorf("mime_type = %q, want application/pdf", got[0].MIMEType)
	}
	if string(got[0].Plain) != "hello world" {
		t.Errorf("plain = %q, want hello world", got[0].Plain)
	}
}

func TestDecodeAndValidateAttachments_NilOrEmpty(t *testing.T) {
	got, err := decodeAndValidateAttachments(Deps{}, nil)
	if err != nil {
		t.Errorf("nil input: %v", err)
	}
	if got != nil {
		t.Errorf("nil input should return nil, got %v", got)
	}
	got, err = decodeAndValidateAttachments(Deps{}, []sendAttachmentInput{})
	if err != nil || got != nil {
		t.Errorf("empty slice = (%v, %v), want (nil, nil)", got, err)
	}
}

func TestDecodeAndValidateAttachments_MissingFilename(t *testing.T) {
	_, err := decodeAndValidateAttachments(Deps{}, []sendAttachmentInput{
		{ContentB64: base64.StdEncoding.EncodeToString([]byte("x"))},
	})
	if err == nil {
		t.Fatal("expected error for missing filename")
	}
	if !strings.Contains(err.Error(), "filename") {
		t.Errorf("error should mention filename, got: %v", err)
	}
}

func TestDecodeAndValidateAttachments_MissingContent(t *testing.T) {
	_, err := decodeAndValidateAttachments(Deps{}, []sendAttachmentInput{
		{Filename: "x"},
	})
	if err == nil {
		t.Fatal("expected error for missing content_b64")
	}
	if !strings.Contains(err.Error(), "content_b64") {
		t.Errorf("error should mention content_b64, got: %v", err)
	}
}

func TestDecodeAndValidateAttachments_BadBase64(t *testing.T) {
	_, err := decodeAndValidateAttachments(Deps{}, []sendAttachmentInput{
		{Filename: "x", ContentB64: "not valid base64!!!"},
	})
	if err == nil {
		t.Fatal("expected error for invalid base64")
	}
	if !strings.Contains(err.Error(), "base64") {
		t.Errorf("error should mention base64, got: %v", err)
	}
}

// Default cap is 25 MiB (policy.DefaultMaxAttachmentBytes). One
// 26-MiB attachment should fail; the error message references the cap.
func TestDecodeAndValidateAttachments_OverSizeCap(t *testing.T) {
	tooBig := make([]byte, 26*1024*1024) // 26 MiB > 25 MiB default
	_, err := decodeAndValidateAttachments(Deps{}, []sendAttachmentInput{
		{Filename: "huge.bin", ContentB64: base64.StdEncoding.EncodeToString(tooBig)},
	})
	if err == nil {
		t.Fatal("expected size-cap error")
	}
	if !strings.Contains(err.Error(), "max_attachment_bytes") {
		t.Errorf("error should reference policy field, got: %v", err)
	}
}

// Sum-of-attachments check: two 20-MiB attachments each individually
// pass but cumulatively exceed 25 MiB.
func TestDecodeAndValidateAttachments_OverSumCap(t *testing.T) {
	chunk := make([]byte, 20*1024*1024)
	encoded := base64.StdEncoding.EncodeToString(chunk)
	_, err := decodeAndValidateAttachments(Deps{}, []sendAttachmentInput{
		{Filename: "a.bin", ContentB64: encoded},
		{Filename: "b.bin", ContentB64: encoded},
	})
	if err == nil {
		t.Fatal("expected cumulative-size error")
	}
	if !strings.Contains(err.Error(), "cumulative") {
		t.Errorf("error should reference cumulative size, got: %v", err)
	}
}

// Filename sanitization runs on decode — RTL spoof gets stripped.
func TestDecodeAndValidateAttachments_FilenameSanitized(t *testing.T) {
	got, err := decodeAndValidateAttachments(Deps{}, []sendAttachmentInput{
		{
			Filename:   "repor‮3pm.exe", // RTL-override spoof
			ContentB64: base64.StdEncoding.EncodeToString([]byte("x")),
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	if strings.ContainsRune(got[0].Filename, 0x202e) {
		t.Errorf("sanitization didn't strip RTL override: %q", got[0].Filename)
	}
}

// Default MIME type when omitted.
func TestDecodeAndValidateAttachments_DefaultMIME(t *testing.T) {
	got, err := decodeAndValidateAttachments(Deps{}, []sendAttachmentInput{
		{Filename: "x", ContentB64: base64.StdEncoding.EncodeToString([]byte("x"))},
	})
	if err != nil {
		t.Fatal(err)
	}
	if got[0].MIMEType != "application/octet-stream" {
		t.Errorf("default MIME = %q, want application/octet-stream", got[0].MIMEType)
	}
}

func TestAttachmentsSummary(t *testing.T) {
	cases := []struct {
		name string
		in   []decodedAttachment
		want string
	}{
		{
			name: "empty",
			in:   nil,
			want: "",
		},
		{
			name: "one",
			in:   []decodedAttachment{{Filename: "report.pdf", Plain: make([]byte, 2400)}},
			want: "Attachments: report.pdf (2 KB)",
		},
		{
			name: "exactly three",
			in: []decodedAttachment{
				{Filename: "a.pdf", Plain: make([]byte, 1024)},
				{Filename: "b.pdf", Plain: make([]byte, 1024)},
				{Filename: "c.pdf", Plain: make([]byte, 1024)},
			},
			want: "Attachments: a.pdf (1 KB), b.pdf (1 KB), c.pdf (1 KB)",
		},
		{
			name: "more than three truncates",
			in: []decodedAttachment{
				{Filename: "a", Plain: make([]byte, 1024)},
				{Filename: "b", Plain: make([]byte, 1024)},
				{Filename: "c", Plain: make([]byte, 1024)},
				{Filename: "d", Plain: make([]byte, 1024)},
				{Filename: "e", Plain: make([]byte, 1024)},
			},
			want: "Attachments: a (1 KB), b (1 KB), c (1 KB) and 2 more",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := attachmentsSummary(tc.in)
			if got != tc.want {
				t.Errorf("attachmentsSummary:\n got  %q\n want %q", got, tc.want)
			}
		})
	}
}

func TestHumanBytes(t *testing.T) {
	cases := map[int64]string{
		0:           "0 B",
		512:         "512 B",
		1024:        "1 KB",
		2048:        "2 KB",
		2 * 1 << 20: "2.0 MB",
		3 * 1 << 30: "3.0 GB",
	}
	for in, want := range cases {
		if got := humanBytes(in); got != want {
			t.Errorf("humanBytes(%d) = %q, want %q", in, got, want)
		}
	}
}
