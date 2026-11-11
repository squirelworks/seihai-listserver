# Next steps

In order. One branch and pull request each (see `AGENTS.md`). Each item says
where the code goes.

1. ~~**Lab run with the fork.**~~ Start `seihai-gserver-v2` with its listserver
   set to `127.0.0.1:14900`, then Seihai `--list-only` for 2.05, 2.17, 2.22,
   2.31 on the client ports. Record it in `docs/lab/` (client, commit, result).
   Done (2026-11-04): the fork and `seihai-gserver` both register, Seihai's
   four profiles list them with and without the allow-list, and real 2.05
   rev2, 2.17.1, 2.22 and 2.31 under Wine list the fork
   (`docs/lab/2026-11-04-fork-loopback.md`). The RC list for a hidden
   server is still open; it is tracked in item 7.
2. ~~**Gserver allow-list** (`config.rs`, `gserver.rs`).~~ Done (2026-11-01):
   `gservers = [{ ip = "127.0.0.1", hq_password = "..." }]`. When it is set,
   links from other addresses are dropped, and `NEWSERVER` is listed only
   after `SERVERHQPASS` matches. Empty keeps the open behaviour. Tests in
   `tests/shapes.rs`.
3. ~~**Shape S, silent 1.41** (`client.rs`).~~ Done (2026-11-01):
   `silent_list_after_ms` (0 = off). When no byte arrives in that time, the
   shape A reply goes out. Test: connect, send nothing, expect `[0, 2]`.
4. ~~**Hidden servers** (`state.rs`, `client.rs`).~~ Done (2026-11-01).
   Squirrel's decision: a gserver with HQ level 0 is hidden. It appears
   only on the RC list (client id 5), tagged `U `. Public lists omit it
   and are not tagged `U `. The `{servers}` figure in a client's status
   is the number of rows on that list. An empty `gservers` allow-list is
   unchanged. Loopback tests in `tests/shapes.rs`. The Wine client pass
   in item 1 is still open.
5. ~~**Login rate limit** (`accounts.rs` or `client.rs`).~~ Done (2026-11-01):
   `login_fail_limit` failed client logins and failed `VERIACC2` checks per
   address, counted apart, inside `login_fail_window_secs`. Over the cap the
   password is not checked. 0 on either setting turns the cap off.
6. ~~**Reload on signal / admin** (`main.rs`).~~ Done (2026-11-01): the config
   file is read again when it changes, and on SIGHUP (Unix). Bind address and
   ports stay until a restart. `status_log_secs` logs servers and players
   (0 = off).
7. **seihai-rc integration.** The RC list (id 5) is answered here
   (`tests/shapes.rs`), and a real 2.22 RC under Wine has used this
   listserver in seihai-rc's lab runs (seihai-rc
   `docs/lab/2026-11-04-rc-accounts.md`). Still to do:
   - a test in `seihai-rc` that logs in through this listserver (its tests
     use a fake listserver, `tests/fake_servers.rs`);
   - a lab run where a real RC lists a hidden (HQ level 0) server.
8. ~~**First release** (`v0.1.0`).~~ Done (2026-11-04): published
   with Linux, Windows and both macOS archives. Notes in
   `docs/releases/v0.1.0.md`.

## Secure login follow-ups (2026-10-31)

- **The RC list (id 5) through the same handshake** (`client.rs`). Ready to
  start: seihai-rc has sent it since 2026-11-01 (`servers --secure-login`):
  id 5, the key byte, `SEI00001`, the RC token and the client's key, no list
  name; then the sealed id 1. This listserver still answers `SEI00001` only
  on id 7, so seihai-rc's secure RC list is so far checked only against its
  own fake listserver (seihai-rc `docs/lab/2026-11-01-secure-rc-list.md`).
- Seihai only: real clients cannot be changed, so their logins stay in the
  clear (Squirrel, 2026-10-31).
- Done (2026-10-31): the encrypted gserver link, so `VERIACC2` is no longer
  in the clear between Seihai's gserver and this listserver.
- Done: `seihai-core` is on tag `v0.0.6` (2026-11-11).
- Done (2026-11-01): `key-fingerprint` prints the public key and fingerprint
  without starting, and does not create a missing key file.
