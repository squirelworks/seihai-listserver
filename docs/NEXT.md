# Next steps

In order. One branch and pull request each (see `AGENTS.md`). Each item says
where the code goes.

1. **Lab run with the fork.** Start `seihai-gserver-v2` with its listserver
   set to `127.0.0.1:14900`, then Seihai `--list-only` for 2.05, 2.17, 2.22,
   2.31 on the client ports. Record it in `docs/lab/` (client, commit, result).
   Then real clients under Wine, as in the handoff's `07-lab-testing.md`.
2. **Gserver allow-list** (`config.rs`, `gserver.rs`). A setting such as
   `gservers = [{ ip = "127.0.0.1", hq_password = "..." }]`. When it is set,
   drop links from other addresses, and check `SERVERHQPASS` (now ignored)
   before taking `NEWSERVER`. Empty keeps today's open behaviour. Needed
   before the gserver port is opened to the internet. Tests in `tests/shapes.rs`.
3. **Shape S, silent 1.41** (`client.rs`). Real 1.41 rev 1 connects and waits
   for the list. Add `silent_list_after_ms` (0 = off): when no frame arrives
   in that time, send the shape A reply. Test: connect, send nothing, expect
   `[0, 2]`.
4. **Hidden servers** (`state.rs`). HQ level 0 is tagged `U ` for everyone,
   as in the Python version. Decide with Squirrel whether only the RC list
   (id 5) should see them.
5. **Login rate limit** (`accounts.rs` or `client.rs`). Per-address limit on
   failed logins and `VERIACC2` checks, so a public listserver is not a
   password oracle. Argon2 makes each guess slow, but there is no cap.
6. **Reload on signal / admin** (`main.rs`). Config reload without restart,
   and a status line (servers, players) every few minutes in the log.
7. **seihai-rc integration.** The RC list (id 5) is already answered; once
   `seihai-rc` stage 1 exists, add a test there that logs in through this
   listserver.
8. **First release** (`v0.1.0`): only after Squirrel or Chiaki says go. The
   release workflow already packs the binary, README, licences and the
   sample config for four targets.

## Secure login follow-ups (2026-10-31)

- The RC list (id 5) through the same handshake, once `seihai-rc` speaks it.
- Seihai only: real clients cannot be changed, so their logins stay in the
  clear (Squirrel, 2026-10-31).
- Done (2026-10-31): the encrypted gserver link, so `VERIACC2` is no longer
  in the clear between Seihai's gserver and this listserver.
- Switch `seihai-core` from the PR rev to `v0.0.5` once tagged.
- A `key-fingerprint` command that prints the key without starting.
