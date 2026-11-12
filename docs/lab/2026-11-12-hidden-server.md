# Lab run: a hidden server on the RC list and not on player lists, 2026-11-12 (#19)

Loopback only, inside a Windows 10 lab VM with no network adapter. Every
server and client ran on `127.0.0.1`.

| Part | Commit | Build |
|---|---|---|
| seihai-listserver | `main` at `350a56e` | `cargo build --release` (Windows) |
| seihai-gserver-v2 | `seihai` at `1548ee3` | MinGW-w64 Release; its `bin/servers/` lab world |
| seihai-gserver | `main` at `3c26e78` | `cargo build --release` |
| Real clients | Graal 2.22 (`Graal_222.exe`), 2.31 (`Graal_231.exe`), RC 2.22 (`RemoteControl.exe`) | as shipped, `listserver.txt` = `127.0.0.1` / `14922` |
| seihai-rc | `main` at `afc2107` | `cargo build --release` |

Listserver config: `bind = "127.0.0.1"`, `gserver_port = 14901` (14900 was
taken by a 6.x login gserver in the same session), `client_ports = [14921,
14922, 14923]`, open accounts.

Six gservers registered: five GServer-v2 lab servers (`login`, `modern`,
`default`, `classic`, `npcdemo`, each with `localhostlist = true` so that
localhost mode still registers) and one seihai-gserver. **Lab Classic had
`hq_level = 0`** in `config/adminconfig.txt`; the listserver logged `gserver 5
hq level 0`. The others sent HQ level 1.

## What each client saw

| Client | Login (listserver log) | List |
|---|---|---|
| Real 2.22 | id 7, gen 5, `GNW30123`, list newmain, account `lab222` | 5 servers under "Bronze": Lab Login, Lab Modern, My Server, Seihai NPC demo, Seihai NPC Lab. "There are 5 server(s) online." **No Lab Classic.** |
| Real 2.31 | id 7, gen 5, `GNW30123`, list newmain, account `lab231` | The same 5 under "Hosted". **No Lab Classic.** |
| Real RC 2.22 | id 5, gen 5, account `labrc` | 6 servers. **Lab Classic is listed**, with the RC's warning icon in front of it (the `U ` tag); the others have no icon. |
| seihai-rc `servers --listserver 127.0.0.1:14922 --account labrc` | id 5 | 6 servers: Lab Classic as `[U]`, the rest `[H]`; "There are 6 server(s) online." |

So a gserver with HQ level 0 is on the RC list only, tagged `U `, and the
player lists' server count matches the rows they show.
