//! Player profiles for `GETPROF` / `SETPROF` (design §1).
//!
//! Nine text fields per account, kept in memory and, when the `profiles`
//! setting names a file, written to it after each change. The file is one
//! account per line: the account, then the nine fields, separated by tabs,
//! with `\`, tab and line breaks escaped. Accounts are matched without
//! ASCII case.

use crate::wire::GCHAR_MAX;
use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::sync::Mutex;

/// The profile fields, in wire order: name, age, sex, country, messenger,
/// email, url, hangout, quote.
pub const FIELDS: usize = 9;

/// One account's profile.
pub type Profile = [Vec<u8>; FIELDS];

/// The profile store.
pub struct Profiles {
    path: Option<PathBuf>,
    map: Mutex<BTreeMap<Vec<u8>, Profile>>,
}

fn key(account: &[u8]) -> Vec<u8> {
    account.to_ascii_lowercase()
}

impl Profiles {
    /// Memory only.
    pub fn memory() -> Self {
        Self {
            path: None,
            map: Mutex::new(BTreeMap::new()),
        }
    }

    /// Load `path` (a missing file is an empty store). An empty path is
    /// [`Self::memory`].
    pub fn open(path: &Path) -> Result<Self, String> {
        if path.as_os_str().is_empty() {
            return Ok(Self::memory());
        }
        let mut map = BTreeMap::new();
        match std::fs::read(path) {
            Ok(data) => {
                for line in data.split(|&b| b == b'\n').filter(|l| !l.is_empty()) {
                    let mut parts = line.split(|&b| b == b'\t').map(unescape);
                    let Some(account) = parts.next() else {
                        continue;
                    };
                    let mut p: Profile = Default::default();
                    for f in p.iter_mut() {
                        *f = parts.next().unwrap_or_default();
                    }
                    map.insert(key(&account), p);
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

    /// The account's profile, if one was ever set.
    pub fn get(&self, account: &[u8]) -> Option<Profile> {
        self.lock().get(&key(account)).cloned()
    }

    /// Store the account's profile, each field cut to 223 bytes, and write
    /// the file. A write error is returned; the profile stays in memory.
    pub fn set(&self, account: &[u8], mut p: Profile) -> Result<(), String> {
        for f in p.iter_mut() {
            f.truncate(GCHAR_MAX);
        }
        let mut map = self.lock();
        map.insert(key(account), p);
        let Some(path) = &self.path else {
            return Ok(());
        };
        let mut out = Vec::new();
        for (account, p) in map.iter() {
            out.extend(escape(account));
            for f in p {
                out.push(b'\t');
                out.extend(escape(f));
            }
            out.push(b'\n');
        }
        let tmp = path.with_extension("tmp");
        std::fs::write(&tmp, &out)
            .and_then(|()| std::fs::rename(&tmp, path))
            .map_err(|e| format!("{}: {e}", path.display()))
    }

    fn lock(&self) -> std::sync::MutexGuard<'_, BTreeMap<Vec<u8>, Profile>> {
        self.map.lock().unwrap_or_else(|e| e.into_inner())
    }
}

fn escape(s: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(s.len());
    for &b in s {
        match b {
            b'\\' => out.extend_from_slice(b"\\\\"),
            b'\t' => out.extend_from_slice(b"\\t"),
            b'\n' => out.extend_from_slice(b"\\n"),
            b'\r' => out.extend_from_slice(b"\\r"),
            b => out.push(b),
        }
    }
    out
}

fn unescape(s: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(s.len());
    let mut it = s.iter();
    while let Some(&b) = it.next() {
        if b != b'\\' {
            out.push(b);
            continue;
        }
        match it.next() {
            Some(b't') => out.push(b'\t'),
            Some(b'n') => out.push(b'\n'),
            Some(b'r') => out.push(b'\r'),
            Some(&o) => out.push(o),
            None => out.push(b'\\'),
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    fn profile(name: &[u8], quote: &[u8]) -> Profile {
        let mut p: Profile = Default::default();
        p[0] = name.to_vec();
        p[8] = quote.to_vec();
        p
    }

    #[test]
    fn a_profile_survives_a_restart_and_ignores_case() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("profiles.tsv");
        let s = Profiles::open(&path).unwrap();
        assert!(s.get(b"Alice").is_none());
        s.set(b"Alice", profile(b"Al\tice", b"a\\b\nc")).unwrap();
        let again = Profiles::open(&path).unwrap();
        assert_eq!(again.get(b"alice"), Some(profile(b"Al\tice", b"a\\b\nc")));
    }

    #[test]
    fn fields_are_cut_to_a_gstring() {
        let s = Profiles::memory();
        s.set(b"bob", profile(&[b'x'; 300], b"")).unwrap();
        assert_eq!(s.get(b"BOB").unwrap()[0].len(), GCHAR_MAX);
    }
}
