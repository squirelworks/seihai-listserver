# seihai-listserver

A Graal listserver: gives classic clients (2.00 to 2.31), Seihai and RCs their server list, and lets gservers register and verify accounts.

Part of the Seihai server stack:
[seihai-gserver](https://github.com/squirelworks/seihai-gserver) ·
[seihai-npcserver](https://github.com/squirelworks/seihai-npcserver) ·
[seihai-listserver](https://github.com/squirelworks/seihai-listserver) ·
[seihai-rc](https://github.com/squirelworks/seihai-rc) ·
[seihai-gserver-v2](https://github.com/squirelworks/seihai-gserver-v2) (GPL fork of GServer-v2, ships first) ·
client: [seihai](https://github.com/squirelworks/seihai).

**Status: first working version.** A Rust port of the lab listserver v2
(`docs/reference/listserver.py`), checked on loopback with its shape tests and
with Seihai's own list client. The plan is in [docs/PLAN.md](docs/PLAN.md), the
rules every contributor and coding agent follows are in [AGENTS.md](AGENTS.md),
the code layout is in [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md) and the ordered
to-do list is in [docs/NEXT.md](docs/NEXT.md).

## Run

```
seihai-listserver sample-config > seihai-listserver.toml   # optional, edit to taste
seihai-listserver                                           # reads ./seihai-listserver.toml if present
seihai-listserver --config path/to/listserver.toml
seihai-listserver key-fingerprint seihai-login.key
```

`key-fingerprint` prints the secure-login public key and its fingerprint and
exits. It does not start the listserver and does not create a missing key.
`key-fingerprint --config seihai-listserver.toml` uses that file's
`secure_login_key`. Editing `seihai-listserver.toml` while the listserver is
running reloads it (on Unix, `SIGHUP` does too). The bind address and the
ports stay as they were until a restart. Every `status_log_secs` the log
gets a line with how many servers and players are listed (`0` turns that
off).

With no config it listens on `127.0.0.1`: gservers register on 14900 and
clients ask for the list on 14921, 14922 and 14923 (every port answers every
login shape). The site and upgrade URLs are empty unless you set them.

Point a gserver's listserver setting at `127.0.0.1`, port 14900. Point a client
at one of the client ports, for example
`seihai --online 127.0.0.1:14922 --list-only --account test1 --password-env GRAAL_PW --version 2.22`.

## Hosting for other machines

By default the listserver only listens on `127.0.0.1`, so only programs on the
same machine can reach it. To serve clients and gservers on other machines:

1. Set `bind` in `seihai-listserver.toml` to `"0.0.0.0"` (every IPv4 interface)
   or to one interface's address, such as `"<lan-or-public-ip>"`.
2. Open the ports in the firewall and, behind a router, forward them to this
   machine: the client ports (`client_ports`, 14921 to 14923 by default) for
   players, and `gserver_port` (14900) only for the gservers you run.
3. Set `gserver_ip`. With `"peer"` the list shows each gserver at the address
   its link comes from. A gserver on the same machine then registers from
   `127.0.0.1`, and players elsewhere cannot use that address. In that case set
   `gserver_ip = "sent"` and set the gserver's own server IP to the address
   players should use (`<public-host>`).
4. Use an accounts file (see below) unless the list is meant to be open to
   every account and password. `login_fail_limit` (default 30 per
   `login_fail_window_secs`, default 60) caps failed client logins and failed
   `VERIACC2` checks from one address. The two are counted apart. Set either
   to 0 for no cap. For real 1.41 rev 1, set `silent_list_after_ms` (for
   example 500); 0 leaves the listserver quiet until the client speaks.

```toml
bind = "0.0.0.0"
gserver_ip = "sent"
accounts = "accounts.txt"
```

Any program that can reach `gserver_port` can register a server on the list
and ask whether an account and password are valid (`VERIACC2`) unless
`gservers` is set. With a list, links from other addresses are dropped, and
a server is listed only after it sends `SERVERHQPASS` with that address's
`hq_password` (the raw rest of the line, before `NEWSERVER`). Leave
`gservers` empty on a lab. On a public host, set it and still open
`gserver_port` only to those addresses.

```toml
gservers = [{ ip = "127.0.0.1", hq_password = "change-me" }]
```

## Accounts

Without an `accounts` file every account and password gets in (open mode).
With one, only the accounts in it can fetch the list, and gservers that check
accounts through the listserver (`VERIACC2`) get the same answer.

```
GRAAL_PW=labpw seihai-listserver add-account accounts.txt test1 --password-env GRAAL_PW
```

The file keeps an argon2id hash per account, never the password. It is read
again when it changes, so accounts can be added while the listserver runs.
Lines in the Python lab listserver's plain `account password` format are
skipped with a warning; add those accounts again with `add-account`.

## What it speaks

| Client | Sends | Gets |
|---|---|---|
| 1.41 rev 1 (shape S) | nothing, when `silent_list_after_ms` is set | the shape A reply |
| 2.00, 2.05 (shape A) | id 0 list name | id 0 list, id 2 status (one zlib frame) |
| 2.17 (shape B) | id 0 + id 1 account in one frame | the same, once |
| 2.19 to 2.21 (gen 4) | id 4 key + token, then id 1 | id 0 + id 2 in one bz2, partly XORed frame |
| 2.22, 2.31, 3.x (gen 5) | id 7 key + token + list name, then id 1 | two gen-5 zlib frames: id 0; id 2, id 3 site URL, id 5 upgrade URL |
| RC (gen 5) | id 5 key + token, then id 1 | as gen 5, and hidden servers |

gen 4 and gen 5 lists carry the HQ level tag (`H ` bronze, none for
classic, `P ` gold, `3 ` G3D). HQ level 0 is hidden: that gserver appears
only on the RC list (client id 5), tagged `U `, and is left off the other
lists. A refused login gets id 4 and the link closes. Gservers: `REGISTERV3`, `NEWSERVER`, `SERVERHQPASS`, `SERVERHQLEVEL`,
`SETPLYR`, `PLYRADD`, `PLYRREM`, `VERIACC2`, `SETIP`, `PING`, `SENDTEXT`. A
gserver's entry is dropped when its link closes or is silent for
`gserver_timeout_secs`.

## Secure login (SEI00001)

Seihai clients started with `--secure-login` send the version token
`SEI00001` and get the list without the account or password ever crossing
the wire in the clear (X25519 key exchange, Ed25519-signed server hello,
ChaCha20-Poly1305). The spec is Seihai's
[`documentation/secure-login.md`](https://github.com/squirelworks/seihai/blob/main/documentation/secure-login.md).

- On first start the listserver makes its key in `secure_login_key`
  (default `seihai-login.key` beside the config) and logs its fingerprint.
  Publish the fingerprint so players can check it; back the file up.
- `secure_login_key = ""` turns secure logins off.
- `require_secure_login = true` refuses classic account logins (real
  Graal clients then cannot get the list).
- Classic logins work exactly as before. The secure login is for Seihai
  only: real Graal clients cannot be changed, so their logins stay in the
  clear.

### Encrypted gserver link

seihai-gserver encrypts its link to the listserver (same handshake, inner
token `SVLINK01`, then ChaCha20-Poly1305 records), so the account checks
it sends (`VERIACC2`, with the player's password) are protected for every
player, real clients included. It uses the same key as above. Plain links
(GServer-v2, the GPL fork) are still taken unless
`require_secure_gserver_link = true`.

```
seihai-mae --online 127.0.0.1:14922 --list-only --version 2.31 --secure-login \
  --account test1 --password-env GRAAL_PW
```

## Build

```
cargo build --release
cargo test
```

`cargo test` starts the listserver on free loopback ports and runs the lab
shape tests (`tests/shapes.rs`), the silent-list, login-cap and reload tests
(`tests/rest.rs`), the `key-fingerprint` command (`tests/key_fingerprint.rs`)
and Seihai's list client for 2.05, 2.17, 2.22, 2.31 and 3.04
(`tests/seihai_client.rs`).

Releases for Linux, Windows and macOS are built by GitHub Actions on each `v*` tag.

## Licence

`MIT OR Apache-2.0`, at your option (see `LICENSE-MIT` and `LICENSE-APACHE`).
This repo contains no code from GServer-v2, gs2lib or gs2-parser (GPL) and must not.
