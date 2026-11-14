# Next steps

The original plan and its completion evidence follow. For remaining work, see the
last section and roadmap issue #20. One branch and pull request per change (see
`AGENTS.md`). Each original item says
where the code goes.

1. ~~**Lab run with the fork.**~~ Start `seihai-gserver-v2` with its listserver
   set to `127.0.0.1:14900`, then Seihai `--list-only` for 2.05, 2.17, 2.22,
   2.31 on the client ports. Record it in `docs/lab/` (client, commit, result).
   Done (2026-11-04): the fork and `seihai-gserver` both register, Seihai's
   four profiles list them with and without the allow-list, and real 2.05
   rev2, 2.17.1, 2.22 and 2.31 under Wine list the fork
   (`docs/lab/2026-11-04-fork-loopback.md`). The hidden-server RC check
   was completed in item 7.
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
   unchanged. Loopback tests in `tests/shapes.rs`; real-client and RC
   evidence is in item 7.
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
- Done: the core update to `v0.0.6` landed in #21 (2026-11-11).
  The current `Cargo.toml` pin is `seihai-core` tag `v0.2.16` (was `v0.1.0`, #43).
- Done (2026-11-01): `key-fingerprint` prints the public key and fingerprint
  without starting, and does not create a missing key file.

## Gserver text, profiles, guilds, PMs, buddies (2026-11-13)

Spec: `docs/design/gserver-text-profiles-guilds.md`. A to G (issues
#32–#38) landed in PR #47. H (#39), the optional SQLite `data` store for
profiles and buddies with a one-shot import of the text files, landed in #48.
The real-client checks were done on 2026-11-14 with 4.20r8
(`docs/lab/2026-11-14-buddies-pm-tab-4.20r8.md`), and both shapes held.

## Remaining work and limits

- The PM-tab check on a 2.x client remains unverified; the 4.20r8 result
  above does not establish it. The design note also leaves a 2.22 client's
  buddy-add request unseen.
- Roadmap #20 tracks re-running seihai-servertools' suite stress against
  each release. This document does not claim a new run.
- Moving accounts into SQLite is optional and not planned. Accounts still
  use the accounts file; the `data` store covers profiles and buddies.
- The separate February 2000 Graal3D host needs no listserver work;
  `docs/PLAN.md` distinguishes it from the Torque-era HQ level 4 tag.
