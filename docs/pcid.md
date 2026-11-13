# PC ids (PCID)

A PC id is a number the listserver gives a gserver for each login, naming
the machine the player logged in from. GServer-v2 keeps it in memory and
shows it to staff: the RC command `/openaccess <account>` opens the RC's
ban window with `GraalEngine,lister,ban,<account>,<pcid>`.

Research: Graal_analysis `protocol/pcid.md` (what is proven and what is
not, and how each client makes each machine field).

## What is proven, and what is ours

Proven from clients and the GServer-v2 source:

- Windows 4.x to 6.03, and the Mac and Linux builds of the same years, send
  a comma list after the password: the platform (`win`, `mac`, `linux`), up
  to three MD5 digests of machine values, and on later builds the OS
  version. 1.x to 3.x clients send nothing there.
- The gserver forwards the list unchanged at the end of `SVO_VERIACC2`
  (17): a GSHORT length, then the text.
- The listserver answers with `SVI_ASSIGNPCID` (30): GSHORT player id,
  GCHAR player type (both as the gserver sent them), then a GCHAR-length
  string with the PC id in decimal. GServer-v2 reads it with `std::stoll`,
  so it must be digits only and fit a signed 64-bit number.
- GServer-v2 drops `ASSIGNPCID` for a player who is already loaded, and
  the `SUCCESS` answer to `VERIACC2` loads the player. So `ASSIGNPCID` must
  come **before** the `VERIACC2` answer.

**Not proven:** how the official listserver turns the digests into a
number. We do not hold it, and probing it is out of scope. The rule below
is ours.

## What the fields are

Each hardware field is an unsalted MD5 of raw bytes, as 32 lower-case hex
digits; a value the client could not read is sent empty (Graal_analysis
`protocol/pcid.md`, "What the client sends"):

| Platform | Slot 1 | Slot 2 | Slot 3 | Slot 4 |
|---|---|---|---|---|
| `win` | product id (often empty on 64-bit Windows) | network card: 4.x the UUID node, 5.24+ the first adapter with an IPv4 address | `C:` volume serial | OS version text (5.12+) |
| `mac` | built-in Ethernet MAC | 4 bytes of `stat("/etc")` | empty | OS version text (later builds) |
| `linux` | `eth0` MAC (six zero bytes when there is no `eth0`) | `/etc` inode | empty | `uname` text |

What changes them: a reinstall or format changes the product id, disk and
inode; a new card, Wi-Fi versus cable, a VPN or VM adapter, or MAC
randomisation changes the 5.24+ network field; updates change the OS
version. Imaged PCs share the disk serial and inode, and volume-licensed
installs can share a product id.

## Our rule: a machines table

- A machine is a row; its PC id is the row number, from 1.
- From the list, keep the platform and the digests in slots 1 to 3, keyed
  by platform and slot (a slot means different things per platform). A
  slot counts only when it is 32 hex digits. Empty fields, `""`, the MD5 of
  an empty string, the MD5 of six zero bytes
  (`7319468847d7b1aee40dbf5dd963c999`, Linux with no `eth0`) and anything
  in `pcid_ignore_hashes` are missing values. Slot 4 (the OS version) is
  never used.
- A login matches a machine when at least `pcid_match_hashes` of its
  digests (default **2**, so 2 of the Windows 3) are linked to that
  machine. The machine with the most matching digests wins, then the
  oldest.
- A matched login links any digest it sent that the machine lacked. Every
  network digest a machine has sent is kept, so a 5.24+ client switching
  between adapters still matches on its disk plus any earlier network
  digest, and a machine whose parts change one at a time keeps its PC id.
  Two parts changing at once makes a new machine.
- A login with fewer digests than `pcid_match_hashes` (an offline 64-bit
  Windows sends only its disk serial; Linux with no `eth0` sends only the
  inode) is weak evidence. It matches only a machine that has exactly those
  digests and no others. So a disk serial shared by imaged PCs never joins
  a full machine, and the same weak login still finds its own row again.
  Imaged PCs that only ever send the shared value do share one PC id: the
  fields cannot tell them apart.
- 6.03r7 on 64-bit Windows sends two digests (network and disk). With the
  default both must match, so remembering every network digest matters.
- No match: a new machine with this login's digests.
- No usable digest (1.x to 3.x, and Seihai's own client, which sends `""`
  fields): no PC id is sent, and GServer-v2 keeps 0.
- Only a login that got in (`SUCCESS`) gets a PC id, so wrong-password
  guesses do not grow the table.

The 2-of-3 rule came from the community ("store the hashes and if 2 of the
3 match, return the same pcid"). `pcid_match_hashes = 1` gives the looser
"any one digest" rule, which keeps a PC id through more changes but also
joins machines that share one value (a common product id, a cloned VM's
MAC).

## The file

`machines` (default `seihai-machines.tsv`, beside the config file) is made
on the first new machine. A header line, then one line per machine and
digest, only ever appended:

```
# seihai-listserver machines v1: pcid, platform, slot, md5 digest
1	win	1	c2482de76c59ac3c4ce0b7e065a2d09c
```

It holds no account, address or raw list. The digests are not secret,
though: a 4-byte serial or inode can be found by trying every value, and a
MAC by trying each vendor's 2^24 device numbers. Keep the file as private
as the raw machine values. Back it up with the accounts
file: a lost file starts the numbers again from 1, so old PC ids in RC
notes would point at new machines. If the file cannot be written, the login
still goes through with no PC id, and the log says why.

## Treat a PC id as a hint

The digests are plain text from the client. A modified client, a proxy or
a hex editor can send any values, and a player can change a part or move
to a VM. A PC id ban stops casual repeat offenders, nothing more. Keep
account and IP bans beside it, and do not ban on a PC id alone when an
account or address says otherwise. The listserver keeps no bans of its own
yet; the PC id is there for the gserver and RC.

## Checked

- `src/machines.rs` unit tests: parsing, the 2-of-3 rule, slots and
  platforms kept apart, restart, an unwritable file.
- `tests/pcid.rs`: a fake gserver sends graal-client-repro's made-up
  machine fields (4.20r8, 5.12 and 6.004 Mac shapes); `ASSIGNPCID` comes
  before `VERIACC2` in GServer-v2's layout; old clients and refused logins
  get none.
- Live on loopback with GServer-v2: `docs/lab/2026-11-13-pcid-gserver-v2.md`.
