package mcptools

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"

	"github.com/just-an-oldsalt/proto-mcp/internal/store"
)

// Opaque pagination cursor. Phase 3 Q3 decision: cursors are
// base64(json{offset, qhash}) where qhash binds the cursor to the
// query it came from. Switching the underlying paging strategy later
// (offset → date-cursor → keyset) won't break client-held cursors,
// because the client never opens the envelope; the server validates
// + reissues on every request.

type cursorPayload struct {
	Offset int    `json:"o"`
	QHash  string `json:"h"`
}

func encodeCursor(offset int, qhash string) string {
	b, _ := json.Marshal(cursorPayload{Offset: offset, QHash: qhash})
	return base64.RawURLEncoding.EncodeToString(b)
}

// decodeCursor returns (offset, ok). ok=false if the cursor is
// malformed OR if the embedded query hash doesn't match the current
// query — the latter case means the client is paging through a stale
// result set, which should surface as an InvalidParams error rather
// than silently jump to the new query's offset.
func decodeCursor(s string, expectedHash string) (int, bool) {
	if s == "" {
		return 0, true
	}
	raw, err := base64.RawURLEncoding.DecodeString(s)
	if err != nil {
		return 0, false
	}
	var p cursorPayload
	if err := json.Unmarshal(raw, &p); err != nil {
		return 0, false
	}
	if p.QHash != expectedHash {
		return 0, false
	}
	if p.Offset < 0 {
		return 0, false
	}
	return p.Offset, true
}

// filterHash returns a short hex digest of a ListFilter. Used as the
// QHash in cursors so a cursor from one filter set can't be replayed
// against a different one.
//
// Hash inputs are the filter fields stringified — order matters but
// reproducibly so. SHA-256 truncated to 16 hex chars is plenty for
// collision-avoidance at the scale of "cursors a single user holds
// across a session."
func filterHash(f store.ListFilter) string {
	in := fmt.Sprintf("F=%s|L=%s|U=%v|T=%s|S=%d|E=%d",
		f.Folder, f.LabelID, f.UnreadOnly, f.ThreadID, f.SinceUnix, f.UntilUnix)
	sum := sha256.Sum256([]byte(in))
	return hex.EncodeToString(sum[:8])
}
