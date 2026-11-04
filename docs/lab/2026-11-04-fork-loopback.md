# Lab run: the fork and the Rust gserver register, Seihai and real clients list, 2026-11-04

NEXT item 1: Seihai's list client and real clients under Wine. Where: cloud
container, Linux x86-64, loopback only. Every server was started by hand on
`127.0.0.1`.

## What was run

| Part | Repo and commit | Build |
|---|---|---|
| Listserver | `seihai-listserver` `main` at `e72bb43` | `cargo build --release` |
| GPL fork gserver | `seihai-gserver-v2` `seihai` at `f585ca6` | the release workflow's Linux steps (GCC 14, vcpkg `x64-linux`, `-DTESTS=OFF -DUPNP=OFF`), its `bin/` lab world as is |
| Rust gserver | `seihai-gserver` `main` at `25cd970` | `cargo build --release`, its `world/` |
| Client | `seihai` `main` at `440bcb7` | `cargo build --release -p seihai-mae` |

The container's network refused source-archive downloads, so the vcpkg
ports' archives were made from git clones of the same tags (`git archive |
gzip -n`) and checked against the ports' SHA512, and the fork was given a
local ANTLR jar with `-DANTLR4_JAR_LOCATION` (4.13.2, the version it asks
for). Nothing in the fork was changed.

Listserver config (the rest at the defaults):

```toml
bind = "127.0.0.1"
gserver_port = 14900
client_ports = [14921, 14922, 14923]
accounts = "accounts.txt"     # one account, test1, made with add-account
status_log_secs = 5
```

Client command, for each of 2.05, 2.17, 2.22 and 2.31:

```
export GRAAL_PW=labpw
seihai-mae --online 127.0.0.1:14922 --list-only --account test1 --password-env GRAAL_PW --version 2.22
```

## Run 1: the fork registers, four clients list it

`./gs2emu --server default` (fork lab world: `listip = 127.0.0.1`,
`listport = 14900`, empty `hq_password`, `hq_level = 1`).

Listserver log: the fork connects, sends its version, `NEWSERVER` (name
`My Server`, port 14802, address 127.0.0.1), HQ level 1 and its allowed
versions. Plain link, as expected for the fork. The fork's console says it
is connected to `127.0.0.1:14900` and warns that it does not send its
local address because that is loopback (harmless here).

| Client | Port | Status line | List | Exit |
|---|---|---|---|---|
| 2.05 | 14922 | `Welcome to Lab listserver, player.` | `My Server 127.0.0.1:14802`, 0 players | 0 |
| 2.17 | 14922 | `Welcome to Lab listserver, test1.` | same | 0 |
| 2.22 | 14922 | `Welcome to Lab listserver, test1.`, empty site and upgrade URLs | same | 0 |
| 2.31 | 14922 | same as 2.22 | same | 0 |
| 2.22, wrong password | 14922 | `listserver error: Your password is incorrect.` | none | 1 |

2.05 sends only the list name (shape A, no account), so the status names
the default `player`. 2.05 and 2.31 were also asked on 14921 and 14923:
the same list on both.

## Run 2: allow-list and HQ password

Same as run 1 plus `gservers = [{ ip = "127.0.0.1", hq_password = "labhq" }]`
in the listserver config, and `hq_password` / `hq_level` set in the fork's
`config/adminconfig.txt`. Clients 2.05 and 2.31.

| Fork setting | Listserver log | Lists |
|---|---|---|
| `hq_password = labhq`, `hq_level = 1` | `hq password accepted`, then `NEWSERVER` | both list `My Server` |
| `hq_password = wrongpw` | `hq password refused`, link closed, entry dropped | both: 0 servers |
| `hq_password = labhq`, `hq_level = 0` | accepted, `hq level 0` | both: 0 servers (hidden; the RC list was not asked) |

The fork sends `SERVERHQPASS` before `NEWSERVER`, so the allow-list works
with it unchanged. With a refused password the fork reconnects about once a
second, and every attempt is logged (four in four seconds). That is the
fork's reconnect timer, not a listserver fault; it is noted here in case
the log noise matters on a hosted listserver.

## Run 3: the Rust gserver registers next to the fork

Allow-list off again. `seihai-gserver --world <copy of world/>` with
`port = 14812`, `listserver = 127.0.0.1:14900`, `listserver_secure = true`
(the default) and `listserver_accounts = true`.

- Rust gserver: `trusting its key SHA256:...` on first contact (pinned in
  `config/listserver.pin`), then `registered (encrypted)`. The listserver
  log shows `encrypted link (SEI00001 SVLINK01)` and `NEWSERVER Seihai Lab
  port 14812`. The fingerprint matched the one the listserver printed at
  start.
- The fork registered at the same time over its plain link.
- 2.05, 2.17, 2.22 and 2.31 each listed both servers: `Seihai Lab
  127.0.0.1:14812` and `My Server 127.0.0.1:14802`, status `There are 2
  server(s) online.`
- After the fork was stopped, the listserver logged `closed: My Server,
  entry dropped` and 2.31 listed only `Seihai Lab`.

## Run 4: real clients under Wine

Wine 9 (32-bit prefix) and Xvfb, all inside a private network namespace
whose only interface is loopback. Every IPv4 address there is routed to
`lo`, and a catch-all DNS stub answers every name with 127.0.0.1, so each
client's built-in list host lands on this listserver without a hosts entry.
The listserver binds `0.0.0.0` inside the namespace (loopback only there),
with the same `accounts.txt`. The fork's lab world runs unchanged.

| Client | Exe | Listserver log | Server list in the client |
|---|---|---|---|
| 2.05 rev2 | `Graal.exe` from the 2.05 rev2 archive | port 14921, `list name newmain`, no account (shape A) | `My Server`, 0 players, version and description shown |
| 2.17.1 | `Graal_2171.exe` | port 14922, `list name newmain`, `account test1` | `My Server`, 0 players |
| 2.22 | `Graal_222.exe` | port 14922, handshake id 7, gen 5, `account test1` | `My Server`, status `Welcome to Lab listserver, test1.` / `There are 1 server(s) online.` |
| 2.31 | `Graal_231.exe` | same as 2.22 | same as 2.22 |

All four real clients log in to the list and show the fork. That matches
Seihai's 2.05, 2.17, 2.22 and 2.31 list profiles in run 1.

Past the list (not part of this item, noted for the fork):

- 2.22 and 2.31 connect to the fork (`New login: test1 [New Client (2.22+)]`)
  and then stay at "Loading account..." after the server message is closed.
  The same fork binary with the older lab pack's world gets 2.22 into the
  game. The difference that matters is that world's
  `config/servermessage.html`: with it, 2.22 plays; with the fork's own file,
  or with an image line that points at a placeholder or loopback address, it
  waits. The cause is not known; Wine's HTML control (no wine-gecko) may play
  a part. It does not involve the listserver.
- 2.05 rev2 connects and stays on the loading screen, which is the known
  pre-2.1 wait for SETACTIVELEVEL.

## Tests

`cargo test` on the same commit: 50 passed, 0 failed (lib 21, rest 7,
secure_gserver_link 4, secure_login 6, seihai_client 1, shapes 11).

## Not checked

- The RC list (id 5) showing the hidden HQ level 0 server.
- Logging in to either gserver from the list, and `VERIACC2` from the Rust
  gserver with `listserver_accounts = true` (no gserver login was made).
