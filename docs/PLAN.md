# seihai-listserver

Rust port of the lab listserver v2 (`listserver.py` in this folder, about 290 lines,
Python standard library only). The Python version was checked with real 2.05,
2.17.1 and 2.22 clients and Seihai's 2.00 to 2.31 profiles.

## What it does

Ports (lab values; make them settings): 14900 for gservers, 14921/14922/14923 for
clients.

Client side, by login shape:

- **id 0, list name only, plain zlib** (2.00, 2.05; shape A): reply id 0 server
  list, then id 2 status.
- **id 0 + id 1 account/password in one frame** (2.17; shape B): the same reply, once,
  after the account.
- **id 4 key + token** (gen 4, 2.19 to 2.21): bz2 frames, partial XOR.
- **id 5 key + token** (RC list, gen 5): every server, type-tagged.
- **id 7 key + token + list name** (gen 5, 2.22 and 2.31): after id 1, two zlib
  frames: id 0 list; then id 2 status, id 3 site URL, id 5 upgrade URL.
- A refused login gets id 4 (error text) and the link is closed.
- Note: real 2.17.1 asks for the list on the third client port in the classic format.

Gserver side: `SVO_REGISTERV3` (one uncompressed line), then zlib frames:
`NEWSERVER` (22), `SERVERHQPASS` (23), `SERVERHQLEVEL` (24), `SETPLYR` (7),
`PLYRADD` (14), `PLYRREM` (15), `VERIACC2` (17, answered with `SVI_VERIACC2` 11:
SUCCESS or the account error), `SETIP` (5, beta4's 60 s keep-alive), `PING` (16,
logged), `SENDTEXT` (31). A server's entry is dropped when its link closes.
HQ level to list tag: 0 hidden `U `, 1 bronze `H `, 2 classic (none), 3 gold `P `,
4 G3D `3 `.

Accounts: open by default; with an accounts file only listed accounts get in.

## Port plan

1. Cargo workspace, binary `seihai-listserver`, depending on `seihai-core` (git tag)
   for gen 2/3/4/5 framing and the list encoding (`protocol/list.rs`,
   `listserver-login.md` in the Seihai docs).
2. Config file (TOML): bind address (default `127.0.0.1`), ports, list name, status
   text, site/upgrade URLs (default empty), accounts file or open mode.
3. Accounts with hashed passwords (argon2 or similar), plus a small `add-account`
   command. The Python version keeps plain passwords; do not keep that.
4. Port `test_listserver.py`'s shape tests to Rust integration tests that start the
   server on an ephemeral loopback port.
5. Lab check: Seihai `--list-only` for 2.00, 2.05, 2.17, 2.22, 2.31; real clients
   under Wine if available; the fork and the Rust gserver both register.

## State (2026-10-31)

Steps 1 to 4 are done. The config is `seihai-listserver.sample.toml`; the
accounts are argon2id hashes made with `seihai-listserver add-account`.
Checked on loopback in a container:

- `cargo test`: the shape tests (`tests/shapes.rs`) and Seihai's list client
  from seihai-core v0.0.3 for 2.05, 2.17, 2.22, 2.31 and 3.04
  (`tests/seihai_client.rs`), right and wrong passwords.
- `docs/reference/test_listserver.py` run unchanged against the Rust binary
  (open mode, and with an accounts file and `--bad-login`): all checks pass.

Still to do for step 5: real clients under Wine, and the fork and the Rust
gserver registering. Speaking first to a silent 1.41 is
`silent_list_after_ms` (0 is off). Which gservers may register is the
`gservers` allow-list (empty keeps the open behaviour).

## Secure login (2026-10-31)

Done: id 7 with `SEI00001` (Seihai `documentation/secure-login.md`) on every
client port, `secure_login_key` and `require_secure_login` settings, tests in
`tests/secure_login.rs` with Seihai's own client.

Next:

- [x] `seihai-core` is on tag `v0.0.5`.
- [ ] The RC list (id 5) through the same handshake, once `seihai-rc` uses it.
- [x] The gserver link (`VERIACC2`, 17) is encrypted (2026-10-31).
- [x] A `key-fingerprint` command that prints the key without starting.
