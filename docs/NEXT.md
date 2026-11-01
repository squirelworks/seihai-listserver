# Next steps

In order. One branch and pull request each (see `AGENTS.md`). Each item says
where the code goes.

1. **Lab run with the fork.** Start `seihai-gserver-v2` with its listserver
   set to `127.0.0.1:14900`, then Seihai `--list-only` for 2.05, 2.17, 2.22,
   2.31 on the client ports. Record it in `docs/lab/` (client, commit, result).
   Then real clients under Wine, as in the handoff's `07-lab-testing.md`.
2. ~~**Gserver allow-list** (`config.rs`, `gserver.rs`).~~ Done (2026-11-01):
   `gservers = [{ ip = "127.0.0.1", hq_password = "..." }]`. When it is set,
   links from other addresses are dropped, and `NEWSERVER` is listed only
   after `SERVERHQPASS` matches. Empty keeps the open behaviour. Tests in
   `tests/shapes.rs`.
3. ~~**Shape S, silent 1.41** (`client.rs`).~~ Done (2026-11-01):
   `silent_list_after_ms` (0 = off). When no byte arrives in that time, the
   shape A reply goes out. Test: connect, send nothing, expect `[0, 2]`.
4. **Hidden servers** (`state.rs`). HQ level 0 is tagged `U ` for everyone,
   as in the Python version, and a unit test pins that. Decide with Squirrel
   whether only the RC list (id 5) should see them.
5. ~~**Login rate limit** (`accounts.rs` or `client.rs`).~~ Done (2026-11-01):
   `login_fail_limit` failed client logins and failed `VERIACC2` checks per
   address, counted apart, inside `login_fail_window_secs`. Over the cap the
   password is not checked. 0 on either setting turns the cap off.
6. ~~**Reload on signal / admin** (`main.rs`).~~ Done (2026-11-01): the config
   file is read again when it changes, and on SIGHUP (Unix). Bind address and
   ports stay until a restart. `status_log_secs` logs servers and players
   (0 = off).
7. **seihai-rc integration.** Stage 1 of `seihai-rc` is merged, and the RC
   list (id 5) is already answered here (`tests/shapes.rs`). Still to add: a
   test in `seihai-rc` that logs in through this listserver.
8. **First release** (`v0.1.0`): only after Squirrel or Chiaki says go. The
   release workflow already packs the binary, README, licences and the
   sample config for four targets.

## Secure login follow-ups (2026-10-31)

- The RC list (id 5) through the same handshake, once `seihai-rc` speaks it.
- Seihai only: real clients cannot be changed, so their logins stay in the
  clear (Squirrel, 2026-10-31).
- Done (2026-10-31): the encrypted gserver link, so `VERIACC2` is no longer
  in the clear between Seihai's gserver and this listserver.
- Done: `seihai-core` is on tag `v0.0.5`.
- Done (2026-11-01): `key-fingerprint` prints the public key and fingerprint
  without starting, and does not create a missing key file.
