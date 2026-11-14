//! Buddy lists (design §6).
//!
//! What the sources say:
//! - The real 4.04r2 and 4.20r8 send `GraalEngine,lister,verifybuddies,
//!   <flag>,<crc>` when the Login server accepts them: `<flag>` is the
//!   `loadbuddiesfromserver` setting (0/1) and `<crc>` the CRC-32 of their
//!   buddy list joined with commas, in decimal, 0 when empty (Graal_analysis
//!   `protocol/v4x-clients.md`, live 4.04 login `…,verifybuddies,1,0`).
//! - GServer-v2 passes `verifybuddies`, `addbuddy` and `deletebuddy` from a
//!   logged-in non-guest player to the listserver in `REQUESTLIST` (26), and
//!   hands the listserver's `REQUESTTEXT` (19) to the client unchanged. It
//!   stores nothing.
//! - An open listserver answers with `<weapon>,lister,buddylist,acc1,…`
//!   (Graal_analysis `client-internals/feature-specs/14-friends-ignore.md`).
//!
//! Checked with a real 4.20r8 (`docs/lab/2026-11-14-buddies-pm-tab-4.20r8.md`):
//! the client sends one account with `addbuddy` / `deletebuddy` and wants
//! no answer, and it takes `buddylist` and rewrites its own list to match.
//! Chosen here before that run, and still how it works: `addbuddy` / `deletebuddy` carry one or more accounts after the
//! option; the listserver answers `verifybuddies` only when the client
//! asks to load from the server (flag 1) and its CRC differs from the
//! stored list's; `addbuddy` / `deletebuddy` change the stored list and
//! answer nothing (the client has already changed its own).
//!
//! With the `data` setting the lists live in the SQLite store instead
//! (`crate::store`), and the text file is only read once, to import it.

use crate::store::{Source, Store};
use crate::wire::GCHAR_MAX;
use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};

/// Most buddies kept for one account.
pub const MAX_BUDDIES: usize = 100;

/// The buddy store: account (lower case) to its buddies, in the order they
/// were added, as the player wrote them.
pub struct Buddies {
    backing: Backing,
    map: Mutex<BTreeMap<Vec<u8>, Vec<Vec<u8>>>>,
}

/// Where changes are written.
enum Backing {
    Memory,
    File(PathBuf),
    Data(Arc<Store>),
}

fn key(account: &[u8]) -> Vec<u8> {
    account.to_ascii_lowercase()
}

/// Read a buddies text file. A missing file is empty.
fn read_file(path: &Path) -> Result<BTreeMap<Vec<u8>, Vec<Vec<u8>>>, String> {
    let mut map = BTreeMap::new();
    match std::fs::read(path) {
        Ok(data) => {
            for line in data.split(|&b| b == b'\n').filter(|l| !l.is_empty()) {
                let mut parts = line.split(|&b| b == b'\t');
                let Some(account) = parts.next() else {
                    continue;
                };
                let list: Vec<Vec<u8>> = parts
                    .filter(|p| !p.is_empty())
                    .take(MAX_BUDDIES)
                    .map(<[u8]>::to_vec)
                    .collect();
                map.insert(key(account), list);
            }
        }
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
        Err(e) => return Err(format!("{}: {e}", path.display())),
    }
    Ok(map)
}

impl Buddies {
    pub fn memory() -> Self {
        Self {
            backing: Backing::Memory,
            map: Mutex::new(BTreeMap::new()),
        }
    }

    /// Load `path`: one line per account, the account, a tab, then its
    /// buddies separated by tabs. A missing file is empty; an empty path
    /// is [`Self::memory`].
    pub fn open(path: &Path) -> Result<Self, String> {
        if path.as_os_str().is_empty() {
            return Ok(Self::memory());
        }
        Ok(Self {
            backing: Backing::File(path.to_path_buf()),
            map: Mutex::new(read_file(path)?),
        })
    }

    /// Keep buddy lists in the `data` store. When `file` (the `buddies`
    /// setting) is not empty and was never imported into this store, its
    /// lists are copied in first. Returns the store and how many accounts
    /// were imported.
    pub fn with_store(store: Arc<Store>, file: &Path) -> Result<(Self, Option<usize>), String> {
        let mut imported = None;
        if !file.as_os_str().is_empty() && !store.imported(Source::Buddies)? {
            imported = store.import_buddies(file, &read_file(file)?)?;
        }
        let map = store.buddies()?;
        Ok((
            Self {
                backing: Backing::Data(store),
                map: Mutex::new(map),
            },
            imported,
        ))
    }

    /// How many accounts have a buddy list.
    pub fn len(&self) -> usize {
        self.lock().len()
    }

    /// `true` when no account has a list.
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// The account's buddies.
    pub fn list(&self, account: &[u8]) -> Vec<Vec<u8>> {
        self.lock().get(&key(account)).cloned().unwrap_or_default()
    }

    /// Add `buddies` to the account's list (no repeats, ASCII case
    /// ignored, at most [`MAX_BUDDIES`]). Returns the list.
    pub fn add(&self, account: &[u8], buddies: &[Vec<u8>]) -> Result<Vec<Vec<u8>>, String> {
        self.change(account, |list| {
            for b in buddies {
                if b.is_empty() || b.len() > GCHAR_MAX || !valid(b) {
                    continue;
                }
                if list.len() < MAX_BUDDIES && !list.iter().any(|x| x.eq_ignore_ascii_case(b)) {
                    list.push(b.clone());
                }
            }
        })
    }

    /// Take `buddies` off the account's list. Returns the list.
    pub fn remove(&self, account: &[u8], buddies: &[Vec<u8>]) -> Result<Vec<Vec<u8>>, String> {
        self.change(account, |list| {
            list.retain(|x| !buddies.iter().any(|b| x.eq_ignore_ascii_case(b)));
        })
    }

    fn change(
        &self,
        account: &[u8],
        f: impl FnOnce(&mut Vec<Vec<u8>>),
    ) -> Result<Vec<Vec<u8>>, String> {
        let mut map = self.lock();
        let k = key(account);
        let list = map.entry(k.clone()).or_default();
        let before = list.clone();
        f(list);
        let now = list.clone();
        if now.is_empty() {
            map.remove(&k);
        }
        if now == before {
            return Ok(now);
        }
        if let Backing::Data(store) = &self.backing {
            store.put_buddies(&k, &now)?;
        }
        if let Backing::File(path) = &self.backing {
            let mut out = Vec::new();
            for (account, list) in map.iter() {
                out.extend_from_slice(account);
                for b in list {
                    out.push(b'\t');
                    out.extend_from_slice(b);
                }
                out.push(b'\n');
            }
            let tmp = path.with_extension("tmp");
            std::fs::write(&tmp, &out)
                .and_then(|()| std::fs::rename(&tmp, path))
                .map_err(|e| format!("{}: {e}", path.display()))?;
        }
        Ok(now)
    }

    fn lock(&self) -> std::sync::MutexGuard<'_, BTreeMap<Vec<u8>, Vec<Vec<u8>>>> {
        self.map.lock().unwrap_or_else(|e| e.into_inner())
    }
}

/// An account name that can sit in the buddy file and a comma list.
fn valid(b: &[u8]) -> bool {
    !b.iter().any(|&c| matches!(c, b'\t' | b'\n' | b'\r' | b','))
}

/// The CRC-32 (zlib's) of the list joined with commas, as the 4.x client
/// sends it in `verifybuddies`. 0 for an empty list.
pub fn list_crc(list: &[Vec<u8>]) -> u32 {
    if list.is_empty() {
        return 0;
    }
    crc32(&list.join(&b","[..]))
}

fn crc32(data: &[u8]) -> u32 {
    let mut c = 0xFFFF_FFFFu32;
    for &b in data {
        c ^= b as u32;
        for _ in 0..8 {
            c = if c & 1 != 0 {
                (c >> 1) ^ 0xEDB8_8320
            } else {
                c >> 1
            };
        }
    }
    !c
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn crc_is_zlibs_and_zero_when_empty() {
        assert_eq!(crc32(b"123456789"), 0xCBF4_3926);
        assert_eq!(list_crc(&[]), 0);
        assert_eq!(
            list_crc(&[b"alice".to_vec(), b"bob".to_vec()]),
            crc32(b"alice,bob")
        );
    }

    #[test]
    fn add_remove_and_reload() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("buddies.tsv");
        let s = Buddies::open(&path).unwrap();
        let l = s
            .add(
                b"Me",
                &[
                    b"alice".to_vec(),
                    b"ALICE".to_vec(),
                    b"bad,name".to_vec(),
                    b"bob".to_vec(),
                ],
            )
            .unwrap();
        assert_eq!(l, vec![b"alice".to_vec(), b"bob".to_vec()]);
        assert_eq!(Buddies::open(&path).unwrap().list(b"me"), l);
        assert_eq!(
            s.remove(b"me", &[b"Alice".to_vec()]).unwrap(),
            vec![b"bob".to_vec()]
        );
        assert!(s.remove(b"me", &[b"bob".to_vec()]).unwrap().is_empty());
        assert!(Buddies::open(&path).unwrap().list(b"me").is_empty());
    }

    #[test]
    fn a_list_stops_at_the_cap() {
        let s = Buddies::memory();
        let many: Vec<Vec<u8>> = (0..150).map(|n| format!("p{n}").into_bytes()).collect();
        assert_eq!(s.add(b"me", &many).unwrap().len(), MAX_BUDDIES);
    }
}
