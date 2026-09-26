package mcptools

import (
	"net/mail"
	"strings"
	"sync"
	"testing"
	"time"

	gpa "github.com/ProtonMail/go-proton-api"

	"github.com/just-an-oldsalt/proto-mcp/internal/proton"
)

func testDraft() gpa.Message {
	d := gpa.Message{Body: "-----BEGIN PGP MESSAGE-----A", MIMEType: "text/plain"}
	d.ID = "draft-1"
	d.Subject = "Q3 numbers"
	d.Sender = &mail.Address{Name: "Me", Address: "me@proton.me"}
	d.ToList = []*mail.Address{{Address: "alice@x.com"}}
	d.CCList = []*mail.Address{{Address: "bob@x.com"}}
	d.Attachments = []gpa.Attachment{{ID: "a1", Name: "q3.pdf", Size: 2048}}
	return d
}

// Issue #116 — any change between the approved snapshot and the draft
// about to be sent must be caught, including the ones the dialog can't
// display (body) and attachments past the first few.
func TestDraftChange(t *testing.T) {
	if got := draftChange(testDraft(), testDraft()); got != "" {
		t.Fatalf("identical drafts reported change %q", got)
	}
	cases := map[string]func(*gpa.Message){
		"subject":     func(d *gpa.Message) { d.Subject = "Q3 numbers (final)" },
		"sender":      func(d *gpa.Message) { d.Sender = &mail.Address{Address: "other@proton.me"} },
		"recipients":  func(d *gpa.Message) { d.BCCList = []*mail.Address{{Address: "evil@x.com"}} },
		"body":        func(d *gpa.Message) { d.Body = "-----BEGIN PGP MESSAGE-----B" },
		"attachments": func(d *gpa.Message) { d.Attachments = append(d.Attachments, gpa.Attachment{ID: "a2", Name: "x.exe"}) },
	}
	for want, mutate := range cases {
		d := testDraft()
		mutate(&d)
		if got := draftChange(testDraft(), d); got != want {
			t.Errorf("mutating %s: draftChange = %q", want, got)
		}
	}
	// Swapping one recipient for another, same count.
	d := testDraft()
	d.ToList = []*mail.Address{{Address: "mallory@x.com"}}
	if got := draftChange(testDraft(), d); got != "recipients" {
		t.Errorf("swapped To: draftChange = %q, want recipients", got)
	}
}

func TestDraftPromptBody_ShowsEverythingAndResistsInjection(t *testing.T) {
	d := testDraft()
	d.Subject = "hi\nBCC: evil@x.com"
	d.BCCList = []*mail.Address{{Address: "carol@x.com"}}
	for i := 2; i <= 5; i++ {
		d.Attachments = append(d.Attachments, gpa.Attachment{ID: "a", Name: "file" + string(rune('0'+i)) + ".txt", Size: 10})
	}
	body := draftPromptBody(d)
	for _, want := range []string{"Subject: hi BCC: evil@x.com", "To: alice@x.com", "CC: bob@x.com", "BCC: carol@x.com", "q3.pdf", "file5.txt"} {
		if !strings.Contains(body, want) {
			t.Errorf("prompt body missing %q:\n%s", want, body)
		}
	}
	if strings.Count(body, "\nBCC:") != 1 {
		t.Errorf("subject newline injected a fake BCC line:\n%s", body)
	}
}

func TestReplyRecipients(t *testing.T) {
	var parent gpa.Message
	parent.Sender = &mail.Address{Address: "boss@x.com"}
	parent.ToList = []*mail.Address{{Address: "Me@Proton.me"}, {Address: "team@x.com"}}
	parent.CCList = []*mail.Address{{Address: "boss@x.com"}, {Address: "cc@x.com"}}
	deps := Deps{Session: &proton.Session{Addresses: []gpa.Address{{Email: "me@proton.me"}}}}

	to, cc := replyRecipients(deps, parent, false)
	if strings.Join(to, ",") != "boss@x.com" || len(cc) != 0 {
		t.Errorf("reply: to=%v cc=%v", to, cc)
	}
	to, cc = replyRecipients(deps, parent, true)
	if strings.Join(to, ",") != "boss@x.com" || strings.Join(cc, ",") != "team@x.com,cc@x.com" {
		t.Errorf("reply-all: to=%v cc=%v, want CC without self or sender", to, cc)
	}
}

func TestReplySubject(t *testing.T) {
	if replySubject("hello") != "Re: hello" || replySubject("RE: hello") != "RE: hello" {
		t.Errorf("replySubject prefixing wrong")
	}
}

func TestKeyedMutex_SerializesSameKeyOnly(t *testing.T) {
	var k keyedMutex
	unlockA := k.Lock("a")

	// A different key is not blocked.
	done := make(chan struct{})
	go func() { k.Lock("b")(); close(done) }()
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("lock on b blocked behind a")
	}

	// The same key waits for the holder.
	var mu sync.Mutex
	acquired := false
	got := make(chan struct{})
	go func() {
		unlock := k.Lock("a")
		mu.Lock()
		acquired = true
		mu.Unlock()
		unlock()
		close(got)
	}()
	time.Sleep(50 * time.Millisecond)
	mu.Lock()
	early := acquired
	mu.Unlock()
	if early {
		t.Fatal("second Lock(a) acquired while a was held")
	}
	unlockA()
	<-got

	k.mu.Lock()
	defer k.mu.Unlock()
	if len(k.m) != 0 {
		t.Errorf("entries leaked after release: %d", len(k.m))
	}
}
