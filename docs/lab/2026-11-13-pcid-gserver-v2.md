# Loopback check: PC ids reach GServer-v2's RC, 2026-11-13

Loopback only (`127.0.0.1`), in a Linux build container. Our own programs
only: no real Graal client and no public server.

| Part | Version |
|---|---|
| seihai-listserver | this branch (PC ids), started as a library on port 14990 |
| seihai-gserver-v2 | release `v4.0.0-seihai.2`, Linux x86_64 archive, a copy of its `default` world with `localhost = false`, `listport = 14990`, `serverport = 14812`, `generation = modern`, staff `labrc` |
| Clients | a small test program: gen-5 client logins (type 5, token `G3D14097`) with chosen machine lists, then seihai-rc `dd10322` as a type-6 RC |

Machine lists sent (graal-client-repro's made-up digests of SquirrelOS,
SquirrelNIC and SquirrelBIOS strings):

| Account | After the password |
|---|---|
| alice | `win,<os>,<nic>,<bios>,"6.2 9200 "` |
| bob | nothing (as 1.x to 3.x) |
| carol | the same three digests, `"10.0 19045 "` (a Windows update) |
| dave | `win,"","","","6.2 9200 "` (Seihai's own client) |

Listserver log:

```
gserver 1 veriacc2 alice type 32, identity 114 bytes, pc id 1: ok
gserver 1 veriacc2 bob type 32, identity 0 bytes: ok
gserver 1 veriacc2 carol type 32, identity 116 bytes, pc id 1: ok
gserver 1 veriacc2 dave type 32, identity 24 bytes: ok
```

The RC then said `/openaccess alice`, `bob`, `carol`, `dave`. GServer-v2
answered with `PLO_SERVERTEXT` (82):

```
GraalEngine,lister,ban,alice,1
GraalEngine,lister,ban,bob,0
GraalEngine,lister,ban,carol,1
GraalEngine,lister,ban,dave,0
```

So GServer-v2 took the PC id from `ASSIGNPCID` sent before the `SUCCESS`
answer, kept it for the player, and gave the same id after an OS-version
change. Players with no usable digests stayed at 0. The machines file held
one machine with three digest lines and no account names.

Not checked here: a real 4.x to 6.03 client (the digests are made up), and
a Windows or macOS host.
