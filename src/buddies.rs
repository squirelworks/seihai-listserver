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
//! Not yet seen on the wire, so chosen here and to be checked in a lab
//! run: `addbuddy` / `deletebuddy` carry one or more accounts after the
//! option; the listserver answers `verifybuddies` only when the client
//! asks to load from the server (flag 1) and its CRC differs from the
//! stored list's; `addbuddy` / `deletebuddy` change the stored list and
//! answer nothing (the client has already changed its own).

use crate::wire::GCHAR_MAX;
use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::sync::Mutex;

/// Most buddies kept for one account.
pub const MAX_BUDDIES: usize = 100;

/// The buddy store: account (lower case) to its buddies, in the order they
/// were added, as the player wrote them.
pub struct Buddies {
    path: Option<PathBuf>,
    map: Mutex<BTreeMap<Vec<u8>, Vec<Vec<u8>>>>,
}

fn key(account: &[u8]) -> Vec<u8> {
    account.to_ascii_lowercase()
}

impl Buddies {
    pub fn memory() -> Self {
        Self {
            path: None,
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
        Ok(Self {
            path: Some(path.to_path_buf()),
            map: Mutex::new(map),
        })
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
        let list = map.entry(key(account)).or_default();
        f(list);
        let now = list.clone();
        if now.is_empty() {
            map.remove(&key(account));
        }
        if let Some(path) = &self.path {
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
