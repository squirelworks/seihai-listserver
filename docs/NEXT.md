# Roadmap status (issues #63 and #64)

Working status for [0.2.0 issue #63](https://github.com/squirelworks/seihai-listserver/issues/63)
and [1.0 issue #64](https://github.com/squirelworks/seihai-listserver/issues/64),
reconciled 2026-11-22 against `main` at `548f07b`. Tick boxes when the matching
PR merges. One branch and pull request per change (`AGENTS.md`).

## Where it stands

- **`v0.1.0` / `v0.1.1` are released.** Login shapes from 1.41 rev 1 through
  3.x and the RC list, the gserver link (`REGISTERV3` and the rest,
  `VERIACC2`, `SERVERINFO` warps), the gserver allow-list with HQ
  passwords, hidden servers, argon2id accounts, the login rate limit,
  config reload, secure login for Seihai and the encrypted gserver link
  are in. Plan items 1–6 and 8 are done.
- **Secure RC list (#18)** and **hidden-server lab (#19)** are closed
  (`#22`, `#30`; seihai-rc `#35`).
- **Gserver text features A–H (#32–#39):** profiles, guilds, cross-server
  lists/PMs/channels/buddies and the optional SQLite `data` store landed
  in `#47` / `#48`. Spec:
  `docs/design/gserver-text-profiles-guilds.md`. Native 4.20r8 buddy and
  PM-tab checks are in `#49`
  (`docs/lab/2026-11-14-buddies-pm-tab-4.20r8.md`).
- **Core pin:** `seihai-core` tag `v0.7.2`.
- **Since the 2026-11-14 PLAN refresh:** gserver ping `#54`; 1.39-and-earlier
  out-of-scope note `#57`; shape-S provenance `#58`; densest-row list
  truncate `#59`; join-count caps `#60`; incomplete first-frame handshake
  timeout `#61`.

## Recent merged persistence acceptance

- [x] New machine IDs stop at the table loader's supported maximum before
      append/live mutation; existing maximum-ID matching and key extension
      remain supported. Last-valid/refusal/reload tests pass ([#73](https://github.com/squirelworks/seihai-listserver/pull/73)).
- [x] Real-file SQLite tests preserve profile arrays, buddy ordering and
      exact import records across reopen, and logical version/data through
      repeated populated newer-schema refusal ([#74](https://github.com/squirelworks/seihai-listserver/pull/74)). This was tests-only.

Both PRs passed Linux/Windows CI. The Store has schema version 1 and
holds profiles/buddies/import records, not accounts or guilds. The
unversioned fixture uses the current layout: no historical migration or
byte-identical/journal-free refusal is established. Config/schema docs,
migration policy, missing labs, stress and macOS/release gates stay open.

## Open checkboxes

### Evidence / ops

- [ ] **2.x PM-tab / buddy-add evidence:** the 4.20r8 lab does not establish
      the PM tab on a 2.x client; a 2.22 buddy-add request remains unseen
      (see the design coverage summary).
- [ ] **seihai-servertools suite stress** re-run against each release (it
      found `silent_list_after_ms` and `max_connections`).

### Explicitly not planned

- [ ] A February 2000 Graal3D list entry, only if a separate G3D-9 host ever
      registers here. Suite roadmap (seihai#353) says no listserver work for
      that era; Torque HQ level 4 / `3 ` listing is a different path and
      stays held until a capture exists.

## Done record (condensed)

- [x] Fork + Rust gserver loopback lab (`docs/lab/2026-11-04-fork-loopback.md`).
- [x] Gserver allow-list, shape S, hidden servers, login rate limit, config
      reload / SIGHUP.
- [x] seihai-rc integration and hidden-server real-RC lab
      (`docs/lab/2026-11-12-hidden-server.md`).
- [x] `v0.1.0` and `v0.1.1` releases.
- [x] Secure client login, encrypted gserver link, secure RC list
      (`docs/lab/2026-11-12-secure-rc-list.md`).
- [x] Gserver text A–H + SQLite store (`#47`, `#48`) and 4.20r8 lab (`#49`).
- [x] Gserver ping `#54`; historical core `v0.4.0` `#56`; docs `#57`/`#58`; list and
      link hardening `#59`–`#61`.

## Not in scope

Real Graal clients keep logging in in the clear (Seihai-only secure login).
This binary stays a listserver: no NPCs on the listserver, no Discord bridge,
no JWT web API, no device-hash PC-id product surface beyond what already
landed for enrolled clients. Accounts stay in the accounts file; moving them
into SQLite is optional and not planned.
