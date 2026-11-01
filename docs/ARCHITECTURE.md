# Architecture

How `seihai-listserver` is put together, for whoever works on it next. The
rules (licences, no real servers, loopback-only tests) are in `AGENTS.md`.
What is done and what is next is in `docs/PLAN.md` and `docs/NEXT.md`.

## Layout

| File | What it does |
|---|---|
| `src/main.rs` | Command line: run, `add-account`, `sample-config`, `--version`. No logic. |
| `src/lib.rs` | Module list; re-exports `Config`, `start`, `Running`. |
| `src/config.rs` | `Config` (TOML, `serde(default, deny_unknown_fields)`), checks, `SAMPLE` (the shipped `seihai-listserver.sample.toml`, kept equal to the defaults by a test). |
| `src/server.rs` | Binds the gserver port and every client port, then one accept thread per port and one thread per link. `Shared` holds the config, accounts and server table. Caps open links at `max_connections`. |
| `src/gserver.rs` | One gserver link: the uncompressed `REGISTERV3` line, then zlib frames of `SVO_*` messages; replies only to `VERIACC2`. Removes the entry when the link ends. When `gservers` is set, other addresses are dropped and `NEWSERVER` waits for a matching `SERVERHQPASS`. |
| `src/client.rs` | One client link. `Coding` is the link's framing: `Plain` (zlib), `Gen4` (bz2 + XOR), `Gen5` (compression byte + XOR). It starts `Plain`; id 4 switches to `Gen4`, id 5 or 7 to `Gen5`. Id 7 with `SEI00001` goes to `secure_login`: S1 out and the sealed id 1 in, both plain, then `Gen5` from the seed. |
| `src/state.rs` | `Servers` (the gserver table, in connect order, behind one mutex), the id 0 list and id 2 status builders, HQ tags. |
| `src/accounts.rs` | `Accounts::Open` or a file of argon2id hashes, read again when its mtime changes; `add_account`. |
| `src/wire.rs` | GCHAR/GSTRING/GSHORT, the `u16be` frame, `show()` for safe log text. |
| `src/log.rs` | `log!`: timestamped lines to stderr and the optional `log_file`. |

From `seihai-core` (git tag in `Cargo.toml`) it uses only
`protocol::{zlib_*, bz2_*, Gen5, Gen5Comp, write_zlib_frame}`, and in tests
`net::Connection::fetch_server_list` (Seihai's own list client) and
`protocol::parse_list_reply`.

## Data flow

```
gserver --REGISTERV3, NEWSERVER, PLYRADD...--> gserver.rs --> Servers (state.rs)
                                    VERIACC2 --> accounts.rs --> SVI_VERIACC2 back
client --login frame--> client.rs --account--> accounts.rs
                                  <--list/status-- Servers
```

## Choices and why

- **Threads, not async.** A listserver has few, short links. Blocking
  `std::net` with read timeouts keeps it small and dependency-free. If it
  ever needs thousands of links, swap `server.rs` for tokio; the handlers
  only need `Read`/`Write`.
- **One mutex for the table.** Every operation is a small map change or a
  list build; contention is not a concern at this size.
- **Argon2 verify outside the lock.** `Accounts::check` clones the hash and
  releases the lock before hashing.
- **Same reply on every client port.** Real clients pick different ports
  (2.17.1 asks on the third) but the shapes do not clash, so every port
  answers every shape.
- **`gserver_ip = "peer"` by default.** Safe on a lab; see the README for hosting.
- **`gservers` empty by default.** Any link may register, as before. A non-empty list is an address check plus the HQ password, both before the server is listed.

## Adding a message

1. Add the id to `svo`/`pli` (or `svi`/`plo`) with the name from the protocol notes.
2. Handle it in `gserver::handle` or the `match pid` in `client::run`.
   Parse with `wire::Fields`; return early on a short payload, never panic.
3. Add a test in `tests/shapes.rs` that sends the raw bytes and checks the reply.

## Tests

- Unit tests in each module (`cargo test --lib`).
- `tests/shapes.rs`: the Python lab tests, on free loopback ports.
- `tests/seihai_client.rs`: Seihai's list client for 2.05, 2.17, 2.22, 2.31, 3.04.
- `tests/secure_login.rs`: the Seihai secure login (`SEI00001`): right and wrong password, wrong key, trust on first use, `require_secure_login`, a tampered seal.
- By hand: `python3 -I docs/reference/test_listserver.py` against a running
  binary on the default ports (needs the Python reference beside it).

## Secure login (SEI00001)

Spec: Seihai `documentation/secure-login.md`. The crypto is
`seihai_core::protocol::seclogin`, shared with the client and seihai-gserver.
The key is loaded (or made) in `server::start` from `secure_login_key` and
kept in `Shared::identity`. A seal that does not open closes the link with
no answer.

## Encrypted gserver link

`gserver.rs` reads the first line; `SEI00001` there starts the encrypted
link (C1 with inner `SVLINK01`, S1 back as a plain line), and the rest of
the link is the classic one inside `seclogin::Channel` records
(`Duplex` + `Channel::wrap`). `session` runs the same loop either way.
`require_secure_gserver_link` refuses plain links. Tests:
`tests/secure_gserver_link.rs`.
