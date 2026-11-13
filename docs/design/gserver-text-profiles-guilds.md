# Gserver link: profiles, guilds, cross-server text, PMs and buddies

Status: **A to G are implemented** (`src/gserver.rs`, `src/links.rs`,
`src/profiles.rs`, `src/buddies.rs`, `src/text.rs`; tests in
`tests/gserver_text.rs`), against fake gservers on loopback. No real
client or the fork has been run against them yet; the lab runs below are
still to do. H (SQLite) is not started. The work was split into
issues labelled `cursor` (see "Issues" at the end). Each section gives the
wire layout, what the listserver should do, what the gserver does with the
answer, and how sure we are of it.

## Where this comes from

- **Our GPL fork `seihai-gserver-v2`.** We read its gserver-side code to see
  what it sends and how it reads the answer. Packet ids and wire layouts are
  facts and may be used here. **Do not copy, port or translate any of its
  code** (see `AGENTS.md`).
- **A third-party .NET listserver release** (2026-11 review, in the project's
  private notes). It was read only as behaviour: which ids it answers and
  with what fields. None of its code is in this repo, and none may be added.
- **Seihai's own lobby notes** (`seihai-core` `protocol/lobby.rs`). They
  record what real 2.x+ clients send (`GraalEngine,pmguilds,""`,
  `GraalEngine,pmservers,""`).

Confidence tags used below:
- **[fork]**: the layout matches what the fork sends and parses. That is
  enough to make the fork work, but no real listserver capture backs it.
- **[both]**: the fork and the reference release agree.
- **[open]**: no capture exists. Answer conservatively and record a lab run
  before relying on it.

## Notation

`gchar(n)` is the byte `n + 32`. `GSHORT` is the two-byte Graal short that
`wire::Fields::gshort` reads. `GSTR` is `gchar(len)` followed by `len` bytes,
with a maximum of 223. **Text** is a Graal comma-tokenized line: fields joined by
`,`, and a field holding `,`, `"`, a space or nothing is quoted with inner
`"` doubled. A field that is itself a list is tokenized again, one level
deeper (the fork's `gtokenize` / `guntokenize`). Every message is one line
ending with `\n` inside the zlib frames, as for `VERIACC2` today.

Gserver to listserver (SVO) ids used here: 9 `VERIGUILD`, 12 `GETPROF`,
13 `SETPROF`, 14 `PLYRADD`, 26 `REQUESTLIST` (also called RequestText),
28 `REQUESTBUDDIES`, 29 `PMPLAYER`, 31 `SENDTEXT`.

Listserver to gserver (SVI) ids used here: 1 `VERIGUILD`, 7 `PROFILE`,
19 `REQUESTTEXT`, 20 `SENDTEXT`, 29 `PMPLAYER`.

## 0. Prerequisites (issue A)

### 0.1 Know each player's account and nickname

`PLYRADD` (14) already carries more than the listserver reads today
[fork]:

```
PLYRADD  GSHORT player_id  gchar(type)
         gchar(34) GSTR account      (prop ACCOUNTNAME)
         gchar(0)  GSTR nickname     (prop NICKNAME)
         ... level, x, y, alignment, ip props follow; ignore them
```

Keep `players: BTreeMap<u16, Player { account, nickname, kind }>` per
gserver instead of the current id set. Read props in order while the prop
id is 34 or 0, and stop at the first other prop id. Missing props leave the
fields empty, because older gservers send only the id and type. The player
count stays `players.len()`. Add lookups by account (case-insensitive) across
all servers, and by `(server, player_id)`.

### 0.2 Send to other gserver links

Today a link can only answer its own messages (`Step::Reply`). Profiles and
guilds only need that. Sections 3 to 5 need a message pushed to *another*
gserver. Give each link an outbound queue in `Shared` (an
`mpsc::Sender<Vec<u8>>` keyed by server id), and write from a writer that
does not block the reader:

- Plain link: a second thread owns a `try_clone()` of the `TcpStream`,
  takes lines from the queue, and writes them as zlib frames (lock or own
  the writer so replies and pushes do not interleave mid-frame).
- Encrypted link: `seihai_core::protocol::seclogin::Channel::split()` gives
  `ChannelSend` / `ChannelRecv`. Use the recv half in the reader and the
  send half in the writer thread, instead of `wrap()`.

`Step::Reply` then becomes "queue to self". Drop the queue when the link
closes. A send to a closed link is ignored.

## 1. Profiles (issue B) [both]

```
SVO GETPROF  GSHORT requester_id  <1 legacy byte>  target_account (rest of line)
SVO SETPROF  <1 legacy byte>  GSTR account  GSTR name  GSTR age  GSTR sex
             GSTR country  GSTR messenger  GSTR email  GSTR url
             GSTR hangout  GSTR quote
SVI PROFILE  GSHORT requester_id  GSTR target_account
             GSTR name ... GSTR quote          (the same 9 fields, in order)
```

The legacy byte is the client's own packet id, which the gserver passes
through (`PLI_PROFILEGET` / `PLI_PROFILESET`). Skip it and don't check its
value.

- `GETPROF`: look up the profile and answer `PROFILE` with its nine fields.
  For an account with no stored profile, still answer, with nine empty
  fields. The fork appends online time, kills, rating and so on from its own
  data, so the client still gets a useful profile. (The reference release
  answers only when a profile exists. Answering with empty fields is our
  choice, so mark it in the test.)
- `SETPROF`: store the nine fields for `account`, each clamped to 223
  bytes. The fork only sends this when the account matches the logged-in
  player. With issue A in place, also check that `account` is a player on
  *this* link, and drop it otherwise.
- v6 clients do not use these packets. That is the fork's business.
- Storage: in memory plus an optional `profiles` file setting (empty means
  memory only). Issue H moves it into SQLite.

## 2. Global guilds (issue C) [both]

```
SVO VERIGUILD  GSHORT player_id  GSTR account  GSTR nickname  GSTR guild
SVI VERIGUILD  GSHORT player_id  GSTR "nickname (guild)"
```

The gserver has already shown the nickname without the guild and asks
whether the tag may stay. Answer only when it may. With no answer, the tag
stays off [both].

Config (hot-reloaded like the rest):

```toml
[guilds]
"Staff" = ["alice", "bob"]          # members, compared case-insensitively
```

Valid means the guild exists and `account` is a member. Build the answer as
`nickname + " (" + guild + ")"` and clamp it to 223 bytes. Don't log
the member list.

## 3. Cross-server player lists: `pmservers`, `pmguilds`, `pmserverplayers` (issue D) [fork]

The gserver wraps a client's request text as:

```
SVO REQUESTLIST  GSHORT player_id  <text>
SVI REQUESTTEXT  GSHORT player_id  <text>     (the fork passes it to the client as PLO_SERVERTEXT)
```

| Request (`weapon,type,option…`) | Answer text |
|---|---|
| `X,pmservers,…` | the request's fields, then one field per **other** listed (non-hidden) server name |
| `X,pmguilds,…` | the request's fields, then one field per guild name from `[guilds]` |
| `GraalEngine,pmserverplayers,<server>` | `GraalEngine,pmserverplayers,<server>,P1,P2,…` where each `Pn` is the tokenized pair `account\nnickname` for one player on `<server>` |
| `X,lister,simplelist` | `X,lister,simpleserverlist,S1,S2,…` where each `Sn` is the tokenized triple `name\n<hq tag>name\nplayer_count` |

Notes:
- The fork reads `pmserverplayers` specially. It treats field 3 as the
  server name and the remaining fields as the player list, then shows those
  players in its PM list as "nick (on server)" with external ids. It sends
  this request itself when a player opens a server in the PM list.
- Leave out the requesting server in `pmservers`. The reference release does
  not, but listing yourself gives duplicate entries. **[open]**: confirm
  this with a real 2.x+ client's PM server tab.
- `<hq tag>` is `state::hq_tag(level)` (the same `P `, `H `, `U `... tags
  as the list).
- Hidden servers (HQ level 0) never appear here.

## 4. Cross-server private messages (issue E) [fork]

```
SVO PMPLAYER  GSHORT sender_id  <text: to_server, from_account, from_nick,
                                       "GraalEngine", "pmplayer", to_account, message>
SVI PMPLAYER  <text: from_server, from_account, from_nick,
                     "GraalEngine", "pmplayer", to_account, message>
```

Find the gserver named `to_server`, case-insensitively. Rewrite field 0 to
the **sender's** server name and push the line to that gserver. The
receiver uses field 0 to add the sender to its PM list, so the reply comes
back the same way. If no server or player matches, drop the message and log
it. Rate-limit per sender link, for example 20 a second, and cap a line at
the existing frame limits.

## 5. Channel chat (`irc`) and player-count pushes (issue F) [fork]

The gserver sends channel requests through `REQUESTLIST` (26):

- `GraalEngine,irc,join,<#chan>`: answer `REQUESTTEXT` with
  `GraalEngine,irc,join,<#chan>` (with `#` added if it was missing). The fork
  then marks the player as in the channel. Track membership as
  `(server, player_id) → channels` for issue F's counts. Membership isn't
  needed for delivery.
- `GraalEngine,irc,part,<#chan>`: answer the same way with `part`.
- `GraalEngine,irc,privmsg,<from_account>,<#chan>,<message>`: push
  `SVI SENDTEXT` (20) with the same six fields to **every other** gserver.
  Their gservers deliver it to their players in that channel. The sender's own
  gserver already delivered it locally.

Player-count pushes [fork]: when a server's player count changes, or the
server registers or drops, push `SVI SENDTEXT`
`Listserver,Modify,Server,<name>,players=<n>` to every other gserver. Send
`players=-1` when it drops or is renamed away. Coalesce changes to at most
one push per server a second.

`SVO SENDTEXT` (31) from a gserver stays logged only.
`Listserver,SetRemoteIp,<ip>` toward a gserver (it tells the gserver its
public IP) is a possible extra and is not in scope here.

## 6. Buddies (issue G) [open]

**Built (2026-11-13), with the open parts chosen as below and marked in
`src/buddies.rs`.** Buddies are a real Graal feature, not a Seihai idea:
the 2.x player list has a Buddies section, 4.04r2 and 4.20r8 send
`verifybuddies` at every login (the live 4.04 login sent
`GraalEngine,lister,verifybuddies,1,0`), GServer-v2 forwards the three
options to the listserver, and an open listserver answers with
`buddylist`. Only the add/delete arguments and the client's handling of
our reply are unseen. Choices:
- `addbuddy` / `deletebuddy` take one or more accounts after the option,
  change the sender's stored list (at most 100, case ignored, no commas),
  and answer nothing.
- `verifybuddies,<flag>,<crc>` (Graal_analysis `protocol/v4x-clients.md`:
  `<flag>` is `loadbuddiesfromserver`, `<crc>` the CRC-32 of the list
  joined with commas, 0 when empty) is answered with `buddylist` only when
  `<flag>` is 1 and the CRC differs from the stored list's.
- `REQUESTBUDDIES` (28) is read as a GSHORT player id, then
  `account,weapon,type`, and answered with `weapon,type,buddylist,…`.
- Stored in memory and in the `buddies` file when it is set.

Lab check still to do: a real 4.04r2 or 4.20r8 with
`loadbuddiesfromserver=1` through the fork, with one account's list
stored here: does the Buddies tab fill from `buddylist`? And what does a
2.22 or 4.x client send when a buddy is added?

What we know:
- The fork forwards `X,lister,verifybuddies|addbuddy|deletebuddy,…` from a
  logged-in, non-guest player through `REQUESTLIST` (26).
- `REQUESTBUDDIES` (28) is defined, and the reference release answers it:
  the request text is `account,weapon,type`, and the answer is `REQUESTTEXT`
  with `weapon,type,buddylist,acc1,acc2,…`. Our fork never sends 28.
- What a real client expects back for `verifybuddies` / `addbuddy` is **not
  captured**.

Plan: store buddy lists per account (account to a set of accounts, at most
100). On `addbuddy,<acc>` / `deletebuddy,<acc>` update the list for the
sender's account, which you look up with issue A. Answer
`verifybuddies` and `REQUESTBUDDIES` with the `buddylist` shape above. Before
merging, record a lab run with a real 2.x+ client's buddy tab, and change
the shape if the client wants something else.

## 7. Persistent store (issue H)

Accounts already use argon2id from the accounts file. Profiles (B) and
buddies (G) need writes. Move them, and optionally accounts, into SQLite
(`rusqlite` with the `bundled` feature) behind one `store` module, with a
`data` setting for the file. One-shot import from the accounts file. This
issue is optional and comes after B and G.

## Testing (every issue)

Use loopback shape tests in `tests/shapes.rs` style. A fake gserver sends
the SVO line and the test checks the SVI line. Sections 3 to 5 need two
fake gservers on one listserver. Where a lab run is required, use the fork
on loopback with a real client under Wine, as in `docs/lab/`.

## Issues

| Issue | Section | Label |
|---|---|---|
| A: player accounts from PLYRADD, outbound queues | 0 | `cursor`, `protocol` |
| B: profiles (12/13 → 7) | 1 | `cursor`, `protocol` |
| C: global guilds (9 → 1) | 2 | `cursor`, `protocol` |
| D: pmservers / pmguilds / pmserverplayers / simplelist (26 → 19) | 3 | `cursor`, `protocol` |
| E: cross-server PMs (29 → 29) | 4 | `cursor`, `protocol` |
| F: irc channel relay and player-count pushes (26 → 19/20) | 5 | `cursor`, `protocol` |
| G: buddies (26/28 → 19), needs a capture | 6 | `cursor`, `protocol`, `needs-capture` |
| H: SQLite store for profiles and buddies | 7 | `cursor` |

Order: A, then B and C (they need only replies), then D, E and F, then G and H.
