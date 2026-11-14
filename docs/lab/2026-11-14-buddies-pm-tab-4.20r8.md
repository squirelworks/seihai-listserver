# Lab run: buddies and the PM server tab with a real 4.20r8, 2026-11-14

Checks the open points of design §3 (`pmservers`) and §6 (buddies) with
a real client. GwenTea2 host, loopback only: the client ran under Wine
in a network namespace with only loopback, so it could reach no public
server. Lab accounts only (`labbud1`, `labbud2`, `labbud3`).

## What was run

| Part | Version |
|---|---|
| seihai-listserver | `main` at `c37d5b4` (#47 and #48), `cargo build --release` |
| Listserver config | `gserver_port = 14900`, `client_ports = [14921, 14922, 14923]`, an accounts file made with `add-account`, `data = "data.sqlite"`, `status_log_secs = 5` |
| GPL fork | two copies of `seihai-gserver-v2`, "Lab Buddy A" and "Lab Buddy B", both pointed at the listserver, `generation = modern` |
| Client | real Graal 4.20r8 (Windows) under Wine on the host |

Lab changes, none in the listserver:
- Fork B started with `generation = newmain`, which refused 4.20r8
  ("Client version not allowed"), so it was switched to `modern`.
- Fork A's start level got a serverwarp NPC so the 4.x client leaves
  Login mode. The original level was kept next to it.

## Check A: buddies (design §6). Pass.

- At every login, after a serverwarp, and again when the fork's
  listserver link reconnects (the fork re-sends players' requests), the
  client sends `GraalEngine,lister,verifybuddies,1,<crc>`. `<crc>` is the
  CRC-32 of the list joined with commas, as `src/buddies.rs` assumes.
- Our `GraalEngine,lister,buddylist,…` answer is taken, even mid-session.
  Proof: `labbud1`'s stored list was cut to `labbud2` and the listserver
  restarted. The client rewrote its own buddy file to match, and
  `labbud3` left its Buddies group.
- The client's right-click "Buddy" item sends
  `GraalEngine,lister,addbuddy,labbud3` and
  `GraalEngine,lister,deletebuddy,labbud3`: one account after the option,
  and no answer expected. That matches our choice.
- The stored list survived a listserver restart (the `data` SQLite file).

## Check B: the PM server tab (design §3). Pass.

- The client sends `GraalEngine,pmservers,""` by itself at login, not
  when the tab is opened.
- From "Lab Buddy A" we answered `GraalEngine,pmservers,"","Lab Buddy B"`
  (the requesting server left out). The tab showed only the other server,
  with no duplicate entry.
- Opening a server sends `GraalEngine,pmserverplayers,Lab Buddy A`. We
  answered `…,"Lab Buddy A","labbud3,*labbud3"`. A player who is not a
  buddy shows under that server's row. A buddy shows in the Buddies group
  as "*labbud3 (on Lab Buddy A)".

## Also seen

- The 4.x client never shows offline buddies.
- A buddy on another server only shows after that server's
  `pmserverplayers` answer.

## Not covered

- No 2.22 or 2.31 client was run, so check B is confirmed on 4.20r8
  only.

No listserver code change was needed.
