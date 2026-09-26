package mcptools

import (
	"context"
	"encoding/json"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/just-an-oldsalt/proto-mcp/internal/mcp"
	"github.com/just-an-oldsalt/proto-mcp/internal/store"
)

// A cache hit must surface `unsubscribe` from the cached headers
// without touching the (nil) session (#102).
func TestReadOne_CacheHitReturnsUnsubscribe(t *testing.T) {
	ctx := context.Background()
	st, err := store.Open(":memory:")
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()

	seed := func(id, unsub, post string) {
		t.Helper()
		if err := st.UpsertMessage(ctx, store.Message{ID: id, ThreadID: id, Subject: "s", Date: time.Unix(1, 0).UTC()}); err != nil {
			t.Fatal(err)
		}
		if err := st.SetCachedBody(ctx, id, store.CachedBody{
			Text:                "hello",
			ListUnsubscribe:     unsub,
			ListUnsubscribePost: post,
		}); err != nil {
			t.Fatal(err)
		}
	}
	seed("with", "<mailto:u@example.com>, <http://example.com/x>, <https://example.com/u?t=1>", "List-Unsubscribe=One-Click")
	seed("without", "", "")

	deps := Deps{Store: st} // Session nil: a cache miss would error.
	mctx := mcp.Context{Std: ctx}

	got, err := readOne(mctx, deps, "with", "text", false)
	if err != nil {
		t.Fatalf("readOne: %v", err)
	}
	if !got.FromCache {
		t.Fatal("expected cache hit")
	}
	want := &unsubscribeInfo{
		HTTPS:    []string{"https://example.com/u?t=1"},
		Mailto:   []string{"mailto:u@example.com"},
		OneClick: true,
	}
	if !reflect.DeepEqual(got.Unsubscribe, want) {
		t.Errorf("unsubscribe = %+v, want %+v", got.Unsubscribe, want)
	}

	// Wire shape.
	b, err := json.Marshal(got)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(b), `"unsubscribe":{"https":["https://example.com/u?t=1"],"mailto":["mailto:u@example.com"],"one_click":true}`) {
		t.Errorf("unexpected JSON: %s", b)
	}

	got, err = readOne(mctx, deps, "without", "text", false)
	if err != nil {
		t.Fatalf("readOne without: %v", err)
	}
	if got.Unsubscribe != nil {
		t.Errorf("unsubscribe = %+v, want nil", got.Unsubscribe)
	}
	if b, _ := json.Marshal(got); strings.Contains(string(b), "unsubscribe") {
		t.Errorf("unsubscribe key present without header: %s", b)
	}
}
