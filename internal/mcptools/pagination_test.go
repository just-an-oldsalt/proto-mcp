package mcptools

import (
	"context"
	"encoding/json"
	"fmt"
	"path/filepath"
	"testing"
	"time"

	"github.com/just-an-oldsalt/proto-mcp/internal/mcp"
	"github.com/just-an-oldsalt/proto-mcp/internal/store"
)

// #131 — list/search pagination and per-message flags.

func seedPagedMessages(t *testing.T, st *store.Store, folder string, n int) {
	t.Helper()
	for i := 0; i < n; i++ {
		if err := st.UpsertMessage(context.Background(), store.Message{
			ID: fmt.Sprintf("%s-%03d", folder, i), ThreadID: fmt.Sprintf("t-%s-%03d", folder, i),
			Subject: "quarterly report", Folder: folder,
			Date:   time.Unix(int64(1_700_000_000+i), 0),
			Unread: true, HasAttachments: true, ToJSON: "[]", CcJSON: "[]",
		}); err != nil {
			t.Fatal(err)
		}
	}
}

func openPagedStore(t *testing.T) *store.Store {
	t.Helper()
	st, err := store.Open(filepath.Join(t.TempDir(), "paging.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = st.Close() })
	return st
}

func callList(t *testing.T, tool mcp.Tool, args string) listResult {
	t.Helper()
	res, err := tool.Handler(mcp.Context{Std: context.Background()}, json.RawMessage(args))
	if err != nil {
		t.Fatalf("%s(%s): %v", tool.Name, args, err)
	}
	if res.IsError {
		t.Fatalf("%s(%s): error result %+v", tool.Name, args, res.Content)
	}
	lr, ok := res.StructuredContent.(listResult)
	if !ok {
		t.Fatalf("%s: structured content is %T", tool.Name, res.StructuredContent)
	}
	return lr
}

// walkPages follows next_cursor until it runs out and returns the total
// number of messages seen and the size of the first page.
func walkPages(t *testing.T, tool mcp.Tool, base string) (total, first int) {
	t.Helper()
	args := base
	for page := 0; page < 20; page++ {
		lr := callList(t, tool, args)
		if page == 0 {
			first = len(lr.Messages)
		}
		total += len(lr.Messages)
		if lr.NextCursor == "" {
			return total, first
		}
		var m map[string]any
		if err := json.Unmarshal([]byte(base), &m); err != nil {
			t.Fatal(err)
		}
		m["cursor"] = lr.NextCursor
		b, _ := json.Marshal(m)
		args = string(b)
	}
	t.Fatalf("%s: pagination did not terminate", tool.Name)
	return 0, 0
}

func TestPagination_DefaultLimitEmitsCursor(t *testing.T) {
	st := openPagedStore(t)
	seedPagedMessages(t, st, "inbox", 60)
	seedPagedMessages(t, st, "drafts", 60)
	deps := Deps{Store: st}

	cases := []struct {
		name string
		tool mcp.Tool
		args string
		want int
	}{
		{"mail_list", mailList(deps), `{"folder":"inbox"}`, 60},
		{"mail_search", mailSearch(deps), `{"query":"quarterly in:inbox"}`, 60},
		{"mail_draft_list", mailDraftList(deps), `{}`, 60},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			total, first := walkPages(t, tc.tool, tc.args)
			if first != store.DefaultSearchLimit {
				t.Errorf("first page = %d, want %d", first, store.DefaultSearchLimit)
			}
			if total != tc.want {
				t.Errorf("walked %d messages with limit omitted, want %d (next_cursor missing)", total, tc.want)
			}
		})
	}
}

// A limit above the store's cap is clamped; the cursor must follow the
// clamped size, not the requested one.
func TestPagination_LimitAboveCapEmitsCursor(t *testing.T) {
	st := openPagedStore(t)
	seedPagedMessages(t, st, "inbox", store.MaxSearchLimit+10)
	total, first := walkPages(t, mailList(Deps{Store: st}), `{"folder":"inbox","limit":500}`)
	if first != store.MaxSearchLimit {
		t.Errorf("first page = %d, want %d", first, store.MaxSearchLimit)
	}
	if total != store.MaxSearchLimit+10 {
		t.Errorf("walked %d messages, want %d", total, store.MaxSearchLimit+10)
	}
}

func TestListAndSearchReportUnreadAndAttachments(t *testing.T) {
	st := openPagedStore(t)
	seedPagedMessages(t, st, "inbox", 1)
	if err := st.UpsertMessage(context.Background(), store.Message{
		ID: "read", ThreadID: "t-read", Subject: "quarterly report", Folder: "inbox",
		Date: time.Unix(1_600_000_000, 0), ToJSON: "[]", CcJSON: "[]",
	}); err != nil {
		t.Fatal(err)
	}
	deps := Deps{Store: st}

	for name, lr := range map[string]listResult{
		"mail_list":   callList(t, mailList(deps), `{"folder":"inbox"}`),
		"mail_search": callList(t, mailSearch(deps), `{"query":"quarterly"}`),
	} {
		got := map[string]messageSummary{}
		for _, m := range lr.Messages {
			got[m.MessageID] = m
		}
		if m := got["inbox-000"]; !m.Unread || !m.HasAttachments {
			t.Errorf("%s: unread/attachment message reported unread=%v has_attachments=%v", name, m.Unread, m.HasAttachments)
		}
		if m, ok := got["read"]; !ok || m.Unread || m.HasAttachments {
			t.Errorf("%s: read message reported unread=%v has_attachments=%v (present=%v)", name, m.Unread, m.HasAttachments, ok)
		}
	}
}
