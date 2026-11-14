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
7. ~~**seihai-rc integration.**~~ Done (2026-11-12). The RC list (id 5) is
   answered here (`tests/shapes.rs`); seihai-rc logs in through this
   listserver in `tests/real_listserver.rs` (seihai-rc #35); and a real
   2.22 RC listed a hidden (HQ level 0) server while real 2.22 and 2.31
   clients did not see it (`docs/lab/2026-11-12-hidden-server.md`).
8. ~~**First release** (`v0.1.0`).~~ Done (2026-11-04): published
   with Linux, Windows and both macOS archives. Notes in
   `docs/releases/v0.1.0.md`.

## Secure login follow-ups (2026-10-31)

- Done (2026-11-12): the RC list (id 5) through the same handshake
  (`client.rs`, issue #18). Checked with seihai-rc itself on loopback:
  `docs/lab/2026-11-12-secure-rc-list.md`.
- Seihai only: real clients cannot be changed, so their logins stay in the
  clear (Squirrel, 2026-10-31).
- Done (2026-10-31): the encrypted gserver link, so `VERIACC2` is no longer
  in the clear between Seihai's gserver and this listserver.
- Done: `seihai-core` is on tag `v0.0.6` (2026-11-11).
- Done (2026-11-01): `key-fingerprint` prints the public key and fingerprint
  without starting, and does not create a missing key file.

## Gserver text, profiles, guilds, PMs, buddies (2026-11-13)

Spec: `docs/design/gserver-text-profiles-guilds.md`. Work is filed as
issues labelled `cursor`, in the order A → B, C → D, E, F → G, H.
A to G are built in PR #47. H (#39), the SQLite `data` store for
profiles and buddies with a one-shot import of the text files, follows it.
Still open: the real-client lab runs listed in the design doc (a 4.x
client's buddy tab, a 2.x+ PM-server tab), and moving accounts into the
store, which is optional and not planned.
