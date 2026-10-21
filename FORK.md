# Why this fork exists

Upstream [masterking32/MasterDnsVPN](https://github.com/masterking32/MasterDnsVPN) shares **one server key
between every client**. That is a sound choice for a tunnel meant to be handed
out freely, but it means a stock build can offer only a single shared account:
no member can be metered, and no member can be cut off on their own without
cutting off everyone. Anyone running MasterDnsVPN for a known set of accounts has to
invent identity outside the protocol.

This fork adds that identity, in the least invasive way the protocol allows.

## How it works

The member puts a token in the DNS label directly above the server's zone:

    <payload>.<payload>.<token>.m.example.com
                         ^^^^^^^ 12 lowercase base32 characters

The server splits that label off before decoding the payload, looks it up in a
credentials table, and dials **that member's own login** on an authenticated
SOCKS upstream for every stream of the session. A token with no entry gets no
session at all, so the table - not the tunnel - is the metering boundary.

**No client change is needed.** The member is configured with a longer domain and
nothing else; one NS delegation covers the whole subtree. That is the reason this
design was chosen over the obvious alternative of one server process per account,
which costs a keypair, a socket, a process and a delegation each.

**It is off by default.** With no `MEMBER_CREDS_PATH` set, the behaviour is
upstream's, which is why upstream's own test suite still passes unchanged
(18 packages, 0 failures).

## What it touches

| File | Change |
|---|---|
| `internal/membercreds/creds.go` | **new** - the token to account table, reloaded when the file changes, failing closed |
| `internal/udpserver/member_identity.go` | **new** - token split, authorization, session binding, context plumbing |
| `internal/udpserver/server_ingress.go` | split the token off, refuse an absent or unknown one, bind the session id to the member |
| `internal/udpserver/socks5_upstream.go` | authenticate upstream as the member carried on the context |
| `internal/udpserver/server_deferred.go` | carry the session's member into a deferred dial |
| `internal/config/server.go` | `MEMBER_CREDS_PATH` |
| `cmd/server/main.go` | enable per-member identity when that path is set |

### One fix that is not about identity

`internal/dnsparser/response.go` - an in-zone NODATA reply was built without the
`AA` bit. A recursive resolver treats an authoritative server that answers for
its own zone without `AA` as lame: Cloudflare and Quad9 return SERVFAIL to the
client, while Google tolerates it. The one-line change builds those replies
authoritatively. Replies for names outside the zone are deliberately left as they
were, because looking like an ordinary resolver there is useful camouflage.

## Why the token must be split off everywhere

The decoded labels are consumed in more than one place. In this project there is a single one, `handleTunnelCandidate` in `server_ingress.go`. Any site left
unpatched still has the member token glued to the payload, and the symptom is not
an error - the client simply never gets a usable answer. After patching, a search for `decision.Labels` should only find the local token-stripped variable.

## Verification

`internal/udpserver/member_identity_test.go` covers the token split against the
real label format, including the case that matters most: **the domain matcher
returns the labels concatenated with the dots stripped**, so splitting on `.`
looks correct and silently never matches.

The build was also exercised end to end against a real client: a valid token
initialises a session and carries HTTPS; an unknown token is refused at
admission; and the node's SOCKS log shows each stream authenticated as the
member who owns that token, which is the whole point.

## Upstream

This is written up for upstream as well. If upstream takes the idea, this fork
has no reason to exist, which would be the better outcome.
