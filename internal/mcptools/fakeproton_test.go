package mcptools

import (
	"context"
	"encoding/json"
	"path/filepath"
	"testing"

	gpa "github.com/ProtonMail/go-proton-api"
	"github.com/ProtonMail/go-proton-api/server"
	"github.com/ProtonMail/gopenpgp/v2/crypto"

	"github.com/just-an-oldsalt/proto-mcp/internal/mcp"
	protonclient "github.com/just-an-oldsalt/proto-mcp/internal/proton"
	"github.com/just-an-oldsalt/proto-mcp/internal/store"
)

// fakeProtonEnv logs into go-proton-api's in-process fake server and
// returns Deps wired to it, the raw client, and the primary address
// keyring. Everything is in-memory or under t.TempDir(): no Keychain,
// no real HOME, no network.
func fakeProtonEnv(t *testing.T) (Deps, *gpa.Client, *crypto.KeyRing) {
	t.Helper()
	s := server.New()
	t.Cleanup(s.Close)
	if _, _, err := s.CreateUser("user", []byte("pass")); err != nil {
		t.Fatal(err)
	}
	m := gpa.New(gpa.WithHostURL(s.GetHostURL()), gpa.WithTransport(gpa.InsecureTransport()))
	t.Cleanup(m.Close)
	ctx := context.Background()
	c, _, err := m.NewClientWithLogin(ctx, "user", []byte("pass"))
	if err != nil {
		t.Fatal(err)
	}
	user, err := c.GetUser(ctx)
	if err != nil {
		t.Fatal(err)
	}
	addrs, err := c.GetAddresses(ctx)
	if err != nil {
		t.Fatal(err)
	}
	salts, err := c.GetSalts(ctx)
	if err != nil {
		t.Fatal(err)
	}
	kp, err := salts.SaltForKey([]byte("pass"), user.Keys.Primary().ID)
	if err != nil {
		t.Fatal(err)
	}
	ukr, akr, err := gpa.Unlock(user, addrs, kp, nil)
	if err != nil {
		t.Fatal(err)
	}
	st, err := store.Open(filepath.Join(t.TempDir(), "m.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = st.Close() })
	sess := &protonclient.Session{Client: c, User: user, Addresses: addrs, UserKR: ukr, AddrKRs: akr}
	return Deps{Session: sess, Store: st}, c, akr[addrs[0].ID]
}

// callOK runs tool's handler and fails the test on any error result.
func callOK(t *testing.T, tool mcp.Tool, args string) *mcp.ToolResult {
	t.Helper()
	res, err := tool.Handler(mcp.Context{Std: context.Background()}, json.RawMessage(args))
	if err != nil {
		t.Fatalf("%s: %v", tool.Name, err)
	}
	if res.IsError {
		t.Fatalf("%s returned an error result: %s", tool.Name, res.Content[0].Text)
	}
	return res
}
