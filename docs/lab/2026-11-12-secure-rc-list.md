# Lab run: seihai-rc's secure RC list against this listserver, 2026-11-12

Issue #18. Where: cloud container, Linux x86-64, loopback only. Every
server was started by hand on `127.0.0.1`. No original RC binary was run.

| Part | Repo and commit | Build |
|---|---|---|
| Listserver | `seihai-listserver` this branch (on `main` at `e1345fb`) | `cargo build --release` |
| RC | `seihai-rc` `main` at `798aee0` | `cargo build --release` |
| Gservers | two scripted registrations (REGISTERV3, HQ level, NEWSERVER): `Quiet` at HQ level 0 (hidden), `TestWorld` at gold | Python, stdlib only |

Listserver config (the rest at the defaults):

```toml
bind = "127.0.0.1"
gserver_port = 14900
client_ports = [14921, 14922, 14923]
accounts = "accounts.txt"     # one account, test1, made with add-account
secure_login_key = "seihai-login.key"
```

The key was made on first start; `key-fingerprint` printed its public key,
which was passed to seihai-rc as `--server-key`.

## Before

seihai-rc sends C1 on id 5 (key byte, `SEI00001`, its RC token
`GSERV025`, its X25519 key, no list name). This listserver took the secure
token only on id 7, so it read the id 5 line as a classic RC handshake with
the token `SEI00001`, waited for a gen-5 id 1 that never came, and
seihai-rc got no server hello.

## After

```
$ seihai-rc servers --listserver 127.0.0.1:14922 --account test1 --secure-login --server-key KEY
Welcome to Lab listserver, test1.
There are 2 server(s) online.
1) [U] Quiet  127.0.0.1:14802  3.0.9  players: 0
2) [P] TestWorld  127.0.0.1:14802  3.0.9  players: 0
```

- Wrong password: `listserver refused the login: Your password is incorrect.`
- Another pinned key: seihai-rc stops before C2 (`server key ... is not the
  given key ...; not sending the password`).
- Classic RC login (no `--secure-login`): same list as before.

Listserver log for the four runs:

```
client 5 secure login SEI00001 (RC list), inner token GSERV025, list
client 5 account test1
client 6 secure login SEI00001 (RC list), inner token GSERV025, list
client 6 account test1
client 6 refused test1: Your password is incorrect.
client 7 secure login SEI00001 (RC list), inner token GSERV025, list
client 7 closed (failed to fill whole buffer)
client 8 handshake id 5, gen 5, token GSERV025, list
client 8 account test1
```

`require_secure_login` refusing the classic RC login, and failed secure RC
logins counting towards `login_fail_limit`, are covered by
`tests/secure_login.rs` rather than this run.
