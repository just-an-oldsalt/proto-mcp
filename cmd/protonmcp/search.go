package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/just-an-oldsalt/proto-mcp/internal/store"
)

// searchOutput is the JSON shape `protonmcp search` prints. Mirrors
// the eventual MCP mail.search response so debugging done with the
// CLI translates straight to the MCP layer.
type searchOutput struct {
	Query string      `json:"query"`
	Hits  []searchHit `json:"hits"`
	Count int         `json:"count"`
}

type searchHit struct {
	MessageID   string    `json:"message_id"`
	ThreadID    string    `json:"thread_id,omitempty"`
	Subject     string    `json:"subject,omitempty"`
	FromAddress string    `json:"from_address,omitempty"`
	FromName    string    `json:"from_name,omitempty"`
	Date        time.Time `json:"date"`
	Folder      string    `json:"folder,omitempty"`
	Snippet     string    `json:"snippet,omitempty"`
}

func runSearch(ctx context.Context, args []string) error {
	fs := flag.NewFlagSet("search", flag.ContinueOnError)
	dbPath := fs.String("db", "", "SQLite store path (default: platform-standard data dir)")
	limit := fs.Int("limit", 50, "max hits to return (capped at 200)")
	offset := fs.Int("offset", 0, "skip this many hits (simple paging)")
	if err := fs.Parse(args); err != nil {
		return err
	}
	rest := fs.Args()
	if len(rest) == 0 {
		return errors.New("usage: protonmcp search [--db <path>] [--limit n] [--offset n] <query...>")
	}
	query := strings.Join(rest, " ")

	path := *dbPath
	if path == "" {
		p, err := store.DefaultPath()
		if err != nil {
			return err
		}
		path = p
	}
	st, err := store.Open(path)
	if err != nil {
		return fmt.Errorf("open store: %w", err)
	}
	defer st.Close()

	hits, err := st.Search(ctx, query, store.SearchOpts{
		Limit:  *limit,
		Offset: *offset,
	})
	if err != nil {
		return err
	}

	out := searchOutput{Query: query, Count: len(hits)}
	for _, h := range hits {
		out.Hits = append(out.Hits, searchHit{
			MessageID:   h.MessageID,
			ThreadID:    h.ThreadID,
			Subject:     h.Subject,
			FromAddress: h.FromAddress,
			FromName:    h.FromName,
			Date:        h.Date,
			Folder:      h.Folder,
			Snippet:     h.Snippet,
		})
	}
	enc := json.NewEncoder(os.Stdout)
	enc.SetIndent("", "  ")
	return enc.Encode(out)
}
