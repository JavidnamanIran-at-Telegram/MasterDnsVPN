package udpserver

import (
	"context"
	"encoding/json"
	"io"
	"net"
	"os"
	"path/filepath"
	"testing"
	"time"

	MemberCreds "masterdnsvpn-go/internal/membercreds"
)

func writeCreds(t *testing.T, path string, table map[string]MemberCreds.Account) {
	t.Helper()
	raw, err := json.Marshal(table)
	if err != nil {
		t.Fatalf("marshal creds: %v", err)
	}
	if err := os.WriteFile(path, raw, 0o600); err != nil {
		t.Fatalf("write creds: %v", err)
	}
}

func TestSplitMemberToken(t *testing.T) {
	// The matcher strips the dots from the payload labels, so `labels` arrives
	// concatenated while the request name still has them.
	cases := []struct {
		name    string
		base    string
		labels  string
		payload string
		token   string
		ok      bool
	}{
		{"aabb.ccdd.tok3n.st.example.com", "st.example.com", "aabbccddtok3n", "aabbccdd", "tok3n", true},
		{"PAYLOAD.TOK3N.st.example.com", "st.example.com", "payloadtok3n", "payload", "tok3n", true},
		{"onlytoken.st.example.com", "st.example.com", "onlytoken", "", "", false},
		{"a.b.st.example.com", "st.example.com", "ab", "a", "b", true},
		{"", "st.example.com", "", "", "", false},
	}
	for _, c := range cases {
		payload, token, ok := splitMemberToken(c.name, c.base, c.labels)
		if ok != c.ok || payload != c.payload || token != c.token {
			t.Fatalf("splitMemberToken(%q,%q,%q) = (%q,%q,%v), want (%q,%q,%v)",
				c.name, c.base, c.labels, payload, token, ok, c.payload, c.token, c.ok)
		}
	}
}

func TestMemberCredsLookupAndReload(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "creds.json")
	writeCreds(t, path, map[string]MemberCreds.Account{
		"aaaabbbbcccc": {User: "tg-1@grp", Pass: "pw-one"},
	})

	table := MemberCreds.New(path)
	if !table.Enabled() {
		t.Fatal("table should be enabled with a path")
	}
	got, ok := table.Lookup("aaaabbbbcccc")
	if !ok || got.User != "tg-1@grp" || got.Pass != "pw-one" {
		t.Fatalf("known token not resolved: %+v ok=%v", got, ok)
	}
	if _, ok := table.Lookup("ffffffffffff"); ok {
		t.Fatal("unknown token must not resolve - that refusal is the metering boundary")
	}
	if _, ok := table.Lookup(""); ok {
		t.Fatal("empty token must not resolve")
	}

	// A member added later must be picked up without a restart; the table
	// re-stats at most every couple of seconds, so wait past that.
	writeCreds(t, path, map[string]MemberCreds.Account{
		"aaaabbbbcccc": {User: "tg-1@grp", Pass: "pw-one"},
		"ddddeeeeffff": {User: "tg-2@grp", Pass: "pw-two"},
	})
	time.Sleep(2500 * time.Millisecond)
	got, ok = table.Lookup("ddddeeeeffff")
	if !ok || got.User != "tg-2@grp" {
		t.Fatalf("new member not picked up after reload: %+v ok=%v", got, ok)
	}

	// And a revoked member must stop resolving.
	writeCreds(t, path, map[string]MemberCreds.Account{
		"ddddeeeeffff": {User: "tg-2@grp", Pass: "pw-two"},
	})
	time.Sleep(2500 * time.Millisecond)
	if _, ok := table.Lookup("aaaabbbbcccc"); ok {
		t.Fatal("revoked member still resolves")
	}
}

// captureAuth runs handleExternalSOCKS5Auth against a pipe and returns the
// username/password it actually presented upstream.
func captureAuth(t *testing.T, ctx context.Context, s *Server) (string, string) {
	t.Helper()
	client, server := net.Pipe()
	defer client.Close()
	defer server.Close()

	type result struct{ user, pass string }
	out := make(chan result, 1)
	go func() {
		header := make([]byte, 2)
		if _, err := io.ReadFull(server, header); err != nil {
			out <- result{}
			return
		}
		user := make([]byte, header[1])
		_, _ = io.ReadFull(server, user)
		plen := make([]byte, 1)
		_, _ = io.ReadFull(server, plen)
		pass := make([]byte, plen[0])
		_, _ = io.ReadFull(server, pass)
		_, _ = server.Write([]byte{0x01, 0x00}) // auth success
		out <- result{string(user), string(pass)}
	}()

	if err := s.handleExternalSOCKS5AuthCtx(ctx, client, 0x02); err != nil {
		t.Fatalf("auth failed: %v", err)
	}
	r := <-out
	return r.user, r.pass
}

func TestSOCKSAuthUsesTheMemberFromContext(t *testing.T) {
	s := &Server{
		externalSOCKS5Auth: true,
		externalSOCKS5User: []byte("shared-account"),
		externalSOCKS5Pass: []byte("shared-secret"),
	}

	// Without a member the stock shared account is used, so an unforked
	// deployment behaves exactly as before.
	user, pass := captureAuth(t, context.Background(), s)
	if user != "shared-account" || pass != "shared-secret" {
		t.Fatalf("stock path changed: got %q/%q", user, pass)
	}

	// With a member on the context the stream is charged to them instead.
	ctx := withMember(context.Background(), MemberCreds.Account{User: "tg-7@grp", Pass: "pw-seven"})
	user, pass = captureAuth(t, ctx, s)
	if user != "tg-7@grp" || pass != "pw-seven" {
		t.Fatalf("member credentials not used: got %q/%q", user, pass)
	}
}

func TestSessionBindingSurvivesLaterStreams(t *testing.T) {
	account := MemberCreds.Account{User: "tg-9@grp", Pass: "pw-nine"}
	rememberMemberSession(42, account)

	got, ok := memberForSession(42)
	if !ok || got.User != "tg-9@grp" {
		t.Fatalf("session not bound to its member: %+v ok=%v", got, ok)
	}
	if _, ok := memberForSession(43); ok {
		t.Fatal("an unopened session must not resolve to anyone")
	}

	forgetMemberSession(42)
	if _, ok := memberForSession(42); ok {
		t.Fatal("closed session still bound")
	}
}
