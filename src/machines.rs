//! The machines table: a PC id (PCID) for each machine a player logs in from.
//!
//! Windows clients from 4.x to 6.03, and the Mac and Linux builds of the
//! same years, send a comma list after the password: the platform, then
//! MD5 digests of machine values (Windows: product id, adapter MAC, `C:`
//! volume serial), then on later builds the OS version. A gserver forwards
//! that list unchanged at the end of `VERIACC2`, and the listserver answers
//! with `SVI_ASSIGNPCID` (30) holding a decimal PCID.
//!
//! How the official listserver turns the list into a number is not known.
//! This table is our own rule, from the research note
//! (Graal_analysis `protocol/pcid.md`): a machine is a row, and its PCID is
//! the row number. A login matches a machine when enough of its hardware
//! digests are already linked to that machine, on the same platform and in
//! the same slot: `pcid_match_hashes` of them (2 by default, so 2 of the
//! Windows 3). A login that sends fewer digests than that matches only a
//! machine with exactly those digests and no others, so one shared disk
//! serial (PCs restored from one image) never joins two machines. The
//! machine with the most shared digests wins, then the oldest. A login that
//! matches no machine makes a new one. A matched login links any digest it
//! sent that the machine did not have yet, so the PCID follows a machine
//! whose parts change one at a time. A digest may be linked to more than
//! one machine.
//!
//! The OS-version field is never used (it changes with every Windows
//! update). Empty fields, `""`, the MD5 of an empty string and the MD5 of
//! six zero bytes (Linux with no `eth0`) are missing values, not matches. A client that sends no usable digest (1.x to 3.x,
//! or a 6.03r7 that sends only the platform) gets no PCID.
//!
//! The file holds one line per machine and digest:
//! `PCID<TAB>platform<TAB>slot<TAB>digest`. It is only appended to, so a
//! crash loses at most the line being written. Nothing else about the
//! player is stored: no account, no address, no raw identity text.

use std::collections::HashMap;
use std::fs::{File, OpenOptions};
use std::io::{self, BufRead, BufReader, Write};
use std::path::{Path, PathBuf};
use std::sync::Mutex;

/// The machine slots read after the platform. Slot 4 and later (the OS
/// version on 5.12 and later) are never used.
pub const HARDWARE_SLOTS: usize = 3;

/// The MD5 of an empty string, which a client sends when it could not read
/// a value. Never a match.
pub const MD5_OF_EMPTY: &str = "d41d8cd98f00b204e9800998ecf8427e";

/// The MD5 of six zero bytes. The Linux clients send it as their network
/// digest when no interface is named `eth0`, so every such machine sends
/// the same value. Never a match.
pub const MD5_OF_ZERO_MAC: &str = "7319468847d7b1aee40dbf5dd963c999";

/// The longest platform name kept (`win`, `mac`, `linux`).
const MAX_PLATFORM: usize = 16;

const HEADER: &str = "# seihai-listserver machines v1: pcid, platform, slot, md5 digest";

/// One hardware digest of a login: which platform, which slot (1 to
/// [`HARDWARE_SLOTS`]) and the 32 lower-case hex digits.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct Key {
    pub platform: String,
    pub slot: u8,
    pub digest: String,
}

/// Split an identity string on commas. A field that starts with `"` runs
/// to the closing quote, and `""` inside it is one quote.
pub fn split_identity(s: &[u8]) -> Vec<Vec<u8>> {
    let mut out = Vec::new();
    let mut i = 0;
    loop {
        let mut field = Vec::new();
        if s.get(i) == Some(&b'"') {
            i += 1;
            while i < s.len() {
                if s[i] == b'"' {
                    if s.get(i + 1) == Some(&b'"') {
                        field.push(b'"');
                        i += 2;
                        continue;
                    }
                    i += 1;
                    break;
                }
                field.push(s[i]);
                i += 1;
            }
            // Anything between the closing quote and the comma is dropped.
            while i < s.len() && s[i] != b',' {
                i += 1;
            }
        } else {
            while i < s.len() && s[i] != b',' {
                field.push(s[i]);
                i += 1;
            }
        }
        out.push(field);
        if i >= s.len() {
            return out;
        }
        i += 1; // the comma
    }
}

/// The hardware keys of an identity string. Empty when it has no platform
/// or no usable digest. `ignore` holds lower-case digests that must never
/// match (for example a product id that many machines share).
pub fn keys(identity: &[u8], ignore: &[String]) -> Vec<Key> {
    let fields = split_identity(identity);
    let Some(platform) = fields.first() else {
        return Vec::new();
    };
    let platform = platform.trim_ascii();
    if platform.is_empty()
        || platform.len() > MAX_PLATFORM
        || !platform.iter().all(u8::is_ascii_alphanumeric)
    {
        return Vec::new();
    }
    let platform = String::from_utf8_lossy(platform).to_ascii_lowercase();
    let mut out = Vec::new();
    for (slot, field) in fields.iter().enumerate().skip(1).take(HARDWARE_SLOTS) {
        let field = field.trim_ascii();
        if field.len() != 32 || !field.iter().all(u8::is_ascii_hexdigit) {
            continue;
        }
        let digest = String::from_utf8_lossy(field).to_ascii_lowercase();
        if digest == MD5_OF_EMPTY || digest == MD5_OF_ZERO_MAC || ignore.contains(&digest) {
            continue;
        }
        out.push(Key {
            platform: platform.clone(),
            slot: slot as u8,
            digest,
        });
    }
    out
}

/// The table, in memory and in its file.
pub struct Machines {
    path: PathBuf,
    inner: Mutex<Table>,
}

#[derive(Default)]
struct Table {
    by_key: HashMap<Key, Vec<u64>>,
    links: usize,
    /// How many digests each machine has.
    sizes: HashMap<u64, usize>,
    next: u64,
    machines: usize,
}

impl Machines {
    /// Load `path`, or start empty when it does not exist yet. The file is
    /// made on the first new machine.
    pub fn open(path: &Path) -> Result<Self, String> {
        let mut table = Table {
            next: 1,
            ..Table::default()
        };
        match File::open(path) {
            Ok(f) => {
                let mut ids = std::collections::HashSet::new();
                for (n, line) in BufReader::new(f).lines().enumerate() {
                    let line = line.map_err(|e| format!("{}: {e}", path.display()))?;
                    if line.is_empty() || line.starts_with('#') {
                        continue;
                    }
                    let bad = || format!("{} line {}: not a machines row", path.display(), n + 1);
                    let mut parts = line.split('\t');
                    let (Some(id), Some(platform), Some(slot), Some(digest), None) = (
                        parts.next(),
                        parts.next(),
                        parts.next(),
                        parts.next(),
                        parts.next(),
                    ) else {
                        return Err(bad());
                    };
                    let id: u64 = id.parse().map_err(|_| bad())?;
                    let slot: u8 = slot.parse().map_err(|_| bad())?;
                    if id == 0 || id > i64::MAX as u64 || digest.len() != 32 {
                        return Err(bad());
                    }
                    ids.insert(id);
                    table.next = table.next.max(id + 1);
                    let ids_of = table
                        .by_key
                        .entry(Key {
                            platform: platform.to_string(),
                            slot,
                            digest: digest.to_ascii_lowercase(),
                        })
                        .or_default();
                    if !ids_of.contains(&id) {
                        ids_of.push(id);
                        table.links += 1;
                        *table.sizes.entry(id).or_default() += 1;
                    }
                }
                table.machines = ids.len();
            }
            Err(e) if e.kind() == io::ErrorKind::NotFound => {}
            Err(e) => return Err(format!("{}: {e}", path.display())),
        }
        Ok(Self {
            path: path.to_path_buf(),
            inner: Mutex::new(table),
        })
    }

    /// How many machines, and machine-digest links, are known.
    pub fn counts(&self) -> (usize, usize) {
        let t = self.inner.lock().unwrap_or_else(|e| e.into_inner());
        (t.machines, t.links)
    }

    /// The PCID for a login's keys: the machine that shares the most keys,
    /// at least `need` of them, the oldest on a tie; or a new machine. A
    /// login with fewer than `need` keys matches only a machine with
    /// exactly those keys. Keys the machine lacks are linked
    /// to it. `None` when `keys` is empty. An error when the file cannot be
    /// written: a PCID that is not stored would be handed out again after a
    /// restart, so the caller sends none.
    pub fn assign(&self, keys: &[Key], need: usize) -> Result<Option<u64>, String> {
        if keys.is_empty() {
            return Ok(None);
        }
        // A login with fewer digests than `need` (an offline 64-bit Windows
        // sends only its disk serial) is weak evidence: it matches only a
        // machine that has exactly those digests and no others, so a disk
        // serial shared by imaged PCs never merges a full machine.
        let weak = keys.len() < need;
        let need = need.clamp(1, keys.len());
        let mut t = self.inner.lock().unwrap_or_else(|e| e.into_inner());
        let mut shared: HashMap<u64, usize> = HashMap::new();
        for k in keys {
            for &id in t.by_key.get(k).into_iter().flatten() {
                *shared.entry(id).or_default() += 1;
            }
        }
        let found = shared
            .into_iter()
            .filter(|&(id, n)| n >= need && (!weak || t.sizes.get(&id) == Some(&n)))
            .max_by(|a, b| a.1.cmp(&b.1).then(b.0.cmp(&a.0)))
            .map(|(id, _)| id);
        let id = found.unwrap_or(t.next);
        let new: Vec<&Key> = keys
            .iter()
            .filter(|k| !t.by_key.get(*k).is_some_and(|ids| ids.contains(&id)))
            .collect();
        if !new.is_empty() {
            let mut text = String::new();
            for k in &new {
                text.push_str(&format!("{id}\t{}\t{}\t{}\n", k.platform, k.slot, k.digest));
            }
            self.append(&text)
                .map_err(|e| format!("{}: {e}", self.path.display()))?;
            for k in new {
                t.by_key.entry(k.clone()).or_default().push(id);
                t.links += 1;
                *t.sizes.entry(id).or_default() += 1;
            }
        }
        if found.is_none() {
            t.next += 1;
            t.machines += 1;
        }
        Ok(Some(id))
    }

    fn append(&self, text: &str) -> io::Result<()> {
        let fresh = !self.path.exists();
        let mut f = OpenOptions::new()
            .create(true)
            .append(true)
            .open(&self.path)?;
        let mut out = String::new();
        if fresh {
            out.push_str(HEADER);
            out.push('\n');
        }
        out.push_str(text);
        f.write_all(out.as_bytes())?;
        f.sync_data()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // The made-up digests graal-client-repro's rebuilds send (MD5 hex of
    // "SquirrelOS product id ...", "SquirrelNIC MAC ..." and
    // "SquirrelBIOS C: volume serial ...").
    const OS: &str = "c2482de76c59ac3c4ce0b7e065a2d09c";
    const NIC: &str = "3c639304427ab3b3c6439a39c31c9df5";
    const BIOS: &str = "217767adb74e936b5ee209ed65ecc400";

    fn win(a: &str, b: &str, c: &str, ver: &str) -> Vec<u8> {
        format!("win,{a},{b},{c},\"{ver}\"").into_bytes()
    }

    #[test]
    fn split_handles_quotes_and_empty_fields() {
        assert_eq!(
            split_identity(b"win,\"\",ab,,\"6.2 9200 \",\"a\"\"b\""),
            vec![
                b"win".to_vec(),
                b"".to_vec(),
                b"ab".to_vec(),
                b"".to_vec(),
                b"6.2 9200 ".to_vec(),
                b"a\"b".to_vec()
            ]
        );
        assert_eq!(split_identity(b"win"), vec![b"win".to_vec()]);
        assert_eq!(split_identity(b"\"open"), vec![b"open".to_vec()]);
    }

    #[test]
    fn keys_skip_missing_values_and_the_os_version() {
        let k = keys(&win(OS, NIC, BIOS, "6.2 9200 "), &[]);
        assert_eq!(k.len(), 3);
        assert_eq!(
            k[1],
            Key {
                platform: "win".into(),
                slot: 2,
                digest: NIC.into()
            }
        );
        // 6.03r7 on Windows 10: an empty product id.
        let k = keys(
            format!("win,\"\",{NIC},{BIOS},\"6.2 9200 \"").as_bytes(),
            &[],
        );
        assert_eq!(k.iter().map(|k| k.slot).collect::<Vec<_>>(), vec![2, 3]);
        // Linux with no eth0: the six-zero-byte digest is missing.
        let k = keys(format!("linux,{MD5_OF_ZERO_MAC},{OS},").as_bytes(), &[]);
        assert_eq!(k.iter().map(|k| k.slot).collect::<Vec<_>>(), vec![2]);
        // The MD5 of an empty string, upper case hex, an ignored digest.
        let k = keys(
            format!("WIN,{},{},{BIOS}", MD5_OF_EMPTY, NIC.to_uppercase()).as_bytes(),
            &[BIOS.to_string()],
        );
        assert_eq!(k.len(), 1);
        assert_eq!(k[0].platform, "win");
        assert_eq!(k[0].digest, NIC);
        // A 32-hex-digit OS version in slot 4 is still not used.
        assert_eq!(keys(format!("linux,,,,{OS}").as_bytes(), &[]), vec![]);
        // Old clients and junk.
        assert!(keys(b"", &[]).is_empty());
        assert!(keys(b"win", &[]).is_empty());
        assert!(keys(format!("w n,{OS}").as_bytes(), &[]).is_empty());
    }

    fn pcid(m: &Machines, identity: &[u8]) -> Option<u64> {
        m.assign(&keys(identity, &[]), 2).unwrap()
    }

    #[test]
    fn two_of_three_keep_the_pcid_and_survive_a_restart() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("machines.tsv");
        let m = Machines::open(&path).unwrap();
        assert!(!path.exists(), "no file until a machine is known");
        assert_eq!(pcid(&m, b"win"), None);

        assert_eq!(pcid(&m, &win(OS, NIC, BIOS, "6.2 9200 ")), Some(1));
        // A Windows update: same machine.
        assert_eq!(pcid(&m, &win(OS, NIC, BIOS, "10.0 19045 ")), Some(1));
        // A new network card: two of three still match, and the new
        // card's digest is linked.
        let nic2 = "0123456789abcdef0123456789abcdef";
        assert_eq!(pcid(&m, &win(OS, nic2, BIOS, "x")), Some(1));
        // Then a new disk: the old product id and the new card still match.
        let bios2 = "fedcba9876543210fedcba9876543210";
        assert_eq!(pcid(&m, &win(OS, nic2, bios2, "x")), Some(1));
        // Only one of three: another machine.
        let os2 = "00000000000000000000000000000001";
        let nic3 = "00000000000000000000000000000002";
        assert_eq!(pcid(&m, &win(os2, nic3, BIOS, "x")), Some(2));
        // 6.03r7 on Windows 10 sends two digests; both must match.
        assert_eq!(
            pcid(
                &m,
                format!("win,\"\",{NIC},{BIOS},\"6.2 9200 \"").as_bytes()
            ),
            Some(1)
        );
        // One digest sent (offline 64-bit Windows): a disk serial alone
        // does not join a full machine, but finds its own machine again.
        assert_eq!(pcid(&m, &win("", "", BIOS, "")), Some(3));
        assert_eq!(pcid(&m, &win("", "", BIOS, "")), Some(3));
        // The same digests on another platform, or in another slot, are
        // other machines.
        assert_eq!(pcid(&m, format!("mac,{OS},{NIC},\"\"").as_bytes()), Some(4));
        assert_eq!(pcid(&m, format!("win,{NIC},{OS}").as_bytes()), Some(5));
        let counts = m.counts();
        assert_eq!(counts.0, 5);

        let again = Machines::open(&path).unwrap();
        assert_eq!(again.counts(), counts);
        assert_eq!(pcid(&again, &win(OS, NIC, BIOS, "")), Some(1));
        assert_eq!(pcid(&again, &win(os2, nic3, "", "")), Some(2));
        let new = "22222222222222222222222222222222";
        assert_eq!(pcid(&again, &win("", "", BIOS, "")), Some(3));
        assert_eq!(pcid(&again, &win(new, "", "", "")), Some(6));
        let text = std::fs::read_to_string(&path).unwrap();
        assert!(text.starts_with("# seihai-listserver machines v1"));
        assert_eq!(text.matches("# seihai").count(), 1, "one header");
        assert!(!text.contains("9200"), "no OS version stored");
    }

    #[test]
    fn one_match_is_enough_when_asked() {
        let dir = tempfile::tempdir().unwrap();
        let m = Machines::open(&dir.path().join("m.tsv")).unwrap();
        let a = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
        let b = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";
        let c = "cccccccccccccccccccccccccccccccc";
        let one = |id: &[u8]| m.assign(&keys(id, &[]), 1).unwrap();
        assert_eq!(one(&win(a, b, c, "")), Some(1));
        assert_eq!(one(&win("", "", c, "")), Some(1));
        assert_eq!(
            one(&win("dddddddddddddddddddddddddddddddd", "", c, "")),
            Some(1)
        );
        assert_eq!(
            one(&win("eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee", "", "", "")),
            Some(2)
        );
    }

    #[test]
    fn a_split_machine_does_not_keep_making_new_ones() {
        // A Mac sends two digests. One changes: the new pair is a new
        // machine, and the same pair again finds it.
        let dir = tempfile::tempdir().unwrap();
        let m = Machines::open(&dir.path().join("m.tsv")).unwrap();
        let a = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
        let b = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";
        let a2 = "abababababababababababababababab";
        let mac = |x: &str, y: &str| format!("mac,{x},{y},\"\"").into_bytes();
        assert_eq!(pcid(&m, &mac(a, b)), Some(1));
        assert_eq!(pcid(&m, &mac(a2, b)), Some(2));
        assert_eq!(pcid(&m, &mac(a2, b)), Some(2));
        assert_eq!(pcid(&m, &mac(a, b)), Some(1));
    }

    #[test]
    fn a_bad_file_is_an_error_and_an_unwritable_one_gives_no_pcid() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("m.tsv");
        std::fs::write(&path, "1\twin\t1\tnot-a-digest\n").unwrap();
        assert!(Machines::open(&path).is_err());
        std::fs::write(&path, "x\n").unwrap();
        assert!(Machines::open(&path).is_err());
        // A folder that does not exist: the file cannot be made.
        let m = Machines::open(&dir.path().join("missing").join("m.tsv")).unwrap();
        assert!(m.assign(&keys(&win(OS, "", "", ""), &[]), 2).is_err());
        assert_eq!(m.counts(), (0, 0), "nothing kept that was not written");
    }
}
