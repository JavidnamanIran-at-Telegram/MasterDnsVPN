package udpserver

// Per-member identity for a tunnel that upstream has none.
//
// Upstream shares one server key between every client, so the only account it
// can offer is a shared one: unmeterable and impossible to revoke for a single
// person. This file adds the missing piece. The member puts a token in the DNS
// label directly above the server's zone:
//
//	<payload>.<payload>.<token>.m.example.com
//
// The token is looked up in a credentials table to find that member's own
// login on the node's authenticated SOCKS inbound, and every stream of that
// session is dialed as them. A token with no entry gets no session at all, so
// the table - not the tunnel - is the metering boundary.
//
// The client needs no change: the member is simply configured with a longer
// domain, and one NS delegation covers the whole subtree.

import (
	"context"
	"strings"
	"sync"
	"time"

	MemberCreds "masterdnsvpn-go/internal/membercreds"
)

var (
	memberIdentityOn bool
	memberTable      *MemberCreds.Table

	memberMu       sync.RWMutex
	memberSessions = map[uint32]memberSession{}
)

type memberSession struct {
	account MemberCreds.Account
	seen    time.Time
}

// Session ids are uint8 in some of these projects and uint16 in others, so
// they are widened to uint32 here and cast at the call sites.
//
// memberSessionTTL drops the mapping for a session that has gone quiet, so a
// long-lived server does not accumulate one entry per session id forever.
const memberSessionTTL = 30 * time.Minute

// EnableMemberIdentity turns per-member accounting on. Called once at startup.
func EnableMemberIdentity(credsPath string) {
	memberIdentityOn = true
	memberTable = MemberCreds.New(credsPath)
}

// MemberIdentityEnabled reports whether per-member accounting is active.
func MemberIdentityEnabled() bool { return memberIdentityOn && memberTable.Enabled() }

// AuthorizedMembers is how many tokens the table currently holds, for logging.
func AuthorizedMembers() int { return memberTable.Len() }

// splitMemberToken separates the member's token from the tunnel payload.
//
// The domain matcher hands back the labels above the zone with their dots
// already stripped, so the payload arrives as one concatenated string and the
// token cannot be found in it by splitting. The request name still has the
// label boundaries, so the token is read from there and then removed from the
// tail of the concatenated payload, which is where it sits.
//
// Returns ok=false when there is no separate token label or nothing would be
// left to decode, and the caller must refuse rather than serve.
func splitMemberToken(requestName, baseDomain, labels string) (payload string, token string, ok bool) {
	trimmed := strings.TrimSuffix(strings.TrimSuffix(requestName, "."), ".")
	base := strings.TrimSuffix(baseDomain, ".")
	if base != "" {
		trimmed = strings.TrimSuffix(trimmed, base)
		trimmed = strings.TrimSuffix(trimmed, ".")
	}
	idx := strings.LastIndexByte(trimmed, '.')
	if idx <= 0 || idx == len(trimmed)-1 {
		return "", "", false
	}
	token = strings.ToLower(trimmed[idx+1:])
	if token == "" || len(labels) <= len(token) {
		return "", "", false
	}
	if !strings.HasSuffix(strings.ToLower(labels), token) {
		// The matcher lowercases, so a mismatch here means the name is not
		// shaped the way we expect and must not be served.
		return "", "", false
	}
	return labels[:len(labels)-len(token)], token, true
}

// authorizeMember resolves a token to an account. A resolver may rewrite the
// case of a name in flight (DNS 0x20), so the token is folded before matching.
func authorizeMember(token string) (MemberCreds.Account, bool) {
	return memberTable.Lookup(strings.ToLower(token))
}

// rememberMemberSession binds a session id to the member it was opened by, so
// every later stream on that session is charged to the same account even
// though only the first packets carry the token in a name we parsed.
func rememberMemberSession(sessionID uint32, account MemberCreds.Account) {
	now := time.Now()
	memberMu.Lock()
	memberSessions[sessionID] = memberSession{account: account, seen: now}
	if len(memberSessions) > 1 {
		for id, entry := range memberSessions {
			if now.Sub(entry.seen) > memberSessionTTL {
				delete(memberSessions, id)
			}
		}
	}
	memberMu.Unlock()
}

// memberForSession returns the account a session belongs to.
func memberForSession(sessionID uint32) (MemberCreds.Account, bool) {
	memberMu.RLock()
	entry, ok := memberSessions[sessionID]
	memberMu.RUnlock()
	return entry.account, ok
}

// forgetMemberSession drops a closed session's mapping.
func forgetMemberSession(sessionID uint32) {
	memberMu.Lock()
	delete(memberSessions, sessionID)
	memberMu.Unlock()
}

type memberContextKey struct{}

// withMember carries the account down to the SOCKS dial, which is the only
// place that needs it and is several calls away from the session.
func withMember(ctx context.Context, account MemberCreds.Account) context.Context {
	if ctx == nil {
		ctx = context.Background()
	}
	return context.WithValue(ctx, memberContextKey{}, account)
}

// memberFromContext returns the account a dial must authenticate as.
func memberFromContext(ctx context.Context) (MemberCreds.Account, bool) {
	if ctx == nil {
		return MemberCreds.Account{}, false
	}
	account, ok := ctx.Value(memberContextKey{}).(MemberCreds.Account)
	return account, ok
}
