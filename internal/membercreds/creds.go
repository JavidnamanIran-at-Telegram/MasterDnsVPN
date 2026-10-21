// Package membercreds maps a per-member DNS label to the SOCKS account that
// member's traffic must be charged to.
//
// MasterDnsVPN and StormDNS have no client identity of their own: one server
// key is shared by everyone, so stock builds can only offer a shared account
// that cannot be metered or revoked for one person. This table is the other
// half of the fix - the server reads the label directly above its zone as a
// member token and looks the token up here to decide whose authenticated SOCKS
// inbound to dial. A token with no entry gets no connection at all, which is
// what makes the table the metering boundary.
//
// The file is re-read when it changes, so adding or revoking a member takes
// effect without a restart (a restart would drop every live session).
package membercreds

import (
	"encoding/json"
	"os"
	"sync"
	"time"
)

// Account is one member's login on the node's authenticated SOCKS inbound.
type Account struct {
	User string `json:"user"`
	Pass string `json:"pass"`
}

// Table is a lazily-reloaded view of the credentials file.
type Table struct {
	path string

	mu      sync.RWMutex
	entries map[string]Account
	modTime time.Time
	size    int64
	checked time.Time
	loaded  bool
}

// recheckAfter bounds how often the file is stat-ed: a busy tunnel looks up a
// token on every stream, and stat-ing per lookup would be wasteful.
const recheckAfter = 2 * time.Second

// New returns a table backed by path. The file does not have to exist yet; an
// absent or unreadable file simply means no member is authorized, which fails
// closed rather than letting everyone through.
func New(path string) *Table {
	return &Table{path: path}
}

// Enabled reports whether a credentials file was configured at all.
func (t *Table) Enabled() bool { return t != nil && t.path != "" }

// Lookup returns the account for a member token. The second result is false
// when the token is unknown, which the caller must treat as "refuse", never as
// "fall back to a shared account".
func (t *Table) Lookup(token string) (Account, bool) {
	if t == nil || t.path == "" || token == "" {
		return Account{}, false
	}
	t.refresh()

	t.mu.RLock()
	defer t.mu.RUnlock()
	account, ok := t.entries[token]
	return account, ok
}

// Len reports how many tokens are currently authorized, for logging.
func (t *Table) Len() int {
	if t == nil {
		return 0
	}
	t.refresh()
	t.mu.RLock()
	defer t.mu.RUnlock()
	return len(t.entries)
}

// refresh reloads the file when its mtime or size has moved. Both are checked
// because a rewrite within the same clock tick can leave mtime unchanged.
func (t *Table) refresh() {
	now := time.Now()

	t.mu.RLock()
	fresh := t.loaded && now.Sub(t.checked) < recheckAfter
	t.mu.RUnlock()
	if fresh {
		return
	}

	info, err := os.Stat(t.path)
	if err != nil {
		t.mu.Lock()
		// Keep serving whatever was last loaded: a momentarily unreadable file
		// must not disconnect members who are already authorized.
		t.checked = now
		t.loaded = true
		t.mu.Unlock()
		return
	}

	t.mu.RLock()
	unchanged := t.loaded && info.ModTime().Equal(t.modTime) && info.Size() == t.size
	t.mu.RUnlock()
	if unchanged {
		t.mu.Lock()
		t.checked = now
		t.mu.Unlock()
		return
	}

	raw, err := os.ReadFile(t.path)
	if err != nil {
		t.mu.Lock()
		t.checked = now
		t.loaded = true
		t.mu.Unlock()
		return
	}

	entries := make(map[string]Account)
	if err := json.Unmarshal(raw, &entries); err != nil {
		// A half-written file is not a reason to cut everyone off; the next
		// check picks up the complete one.
		t.mu.Lock()
		t.checked = now
		t.loaded = true
		t.mu.Unlock()
		return
	}

	t.mu.Lock()
	t.entries = entries
	t.modTime = info.ModTime()
	t.size = info.Size()
	t.checked = now
	t.loaded = true
	t.mu.Unlock()
}
