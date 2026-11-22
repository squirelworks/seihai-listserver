//! Player profiles for `GETPROF` / `SETPROF` (design §1).
//!
//! Nine text fields per account, kept in memory and, when the `profiles`
//! setting names a file, written to it after each change. The file is one
//! account per line: the account, then the nine fields, separated by tabs,
//! with `\`, tab and line breaks escaped. Accounts are matched without
//! ASCII case.
//!
//! With the `data` setting the profiles live in the SQLite store instead
//! (`crate::store`), and the text file is only read once, to import it.

use crate::store::{Source, Store};
use crate::wire::GCHAR_MAX;
use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};

/// The profile fields, in wire order: name, age, sex, country, messenger,
/// email, url, hangout, quote.
pub const FIELDS: usize = 9;

/// One account's profile.
pub type Profile = [Vec<u8>; FIELDS];

/// The profile store.
pub struct Profiles {
    backing: Backing,
    map: Mutex<BTreeMap<Vec<u8>, Profile>>,
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

/// Read a profiles text file; `None` when the file is missing.
fn read_file(path: &Path) -> Result<Option<BTreeMap<Vec<u8>, Profile>>, String> {
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
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(e) => return Err(format!("{}: {e}", path.display())),
    }
    Ok(Some(map))
}

impl Profiles {
    /// Memory only.
    pub fn memory() -> Self {
        Self {
            backing: Backing::Memory,
            map: Mutex::new(BTreeMap::new()),
        }
    }

    /// Load `path` (a missing file is an empty store). An empty path is
    /// [`Self::memory`].
    pub fn open(path: &Path) -> Result<Self, String> {
        if path.as_os_str().is_empty() {
            return Ok(Self::memory());
        }
        Ok(Self {
            backing: Backing::File(path.to_path_buf()),
            map: Mutex::new(read_file(path)?.unwrap_or_default()),
        })
    }

    /// Keep profiles in the `data` store. When `file` (the `profiles`
    /// setting) names an existing file not yet imported into this store, its
    /// rows are copied in first. Returns the store and how many accounts
    /// were imported.
    pub fn with_store(store: Arc<Store>, file: &Path) -> Result<(Self, Option<usize>), String> {
        let mut imported = None;
        if !file.as_os_str().is_empty() && !store.imported(Source::Profiles)? {
            imported = match read_file(file)? {
                Some(rows) => store.import_profiles(file, &rows)?,
                None => None,
            };
        }
        let map = store.profiles()?;
        Ok((
            Self {
                backing: Backing::Data(store),
                map: Mutex::new(map),
            },
            imported,
        ))
    }

    /// How many accounts have a profile.
    pub fn len(&self) -> usize {
        self.lock().len()
    }

    /// `true` when no profile is stored.
    pub fn is_empty(&self) -> bool {
        self.len() == 0
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
        let k = key(account);
        let path = match &self.backing {
            Backing::Memory => {
                map.insert(k, p);
                return Ok(());
            }
            Backing::Data(store) => {
                let r = store.put_profile(&k, &p);
                map.insert(k, p);
                return r;
            }
            Backing::File(path) => path,
        };
        map.insert(k, p);
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

    #[test]
    fn a_missing_profile_import_is_deferred_until_the_file_exists() {
        let dir = tempfile::tempdir().unwrap();
        let db = dir.path().join("data.sqlite");
        let file = dir.path().join("profiles.tsv");
        let kept = profile(b"kept", b"retained quote");
        assert!(Profiles::open(&file).unwrap().is_empty());
        assert!(!file.exists());
        {
            let store = Arc::new(Store::open(&db).unwrap());
            store.put_profile(b"alice", &kept).unwrap();
            let (profiles, imported) = Profiles::with_store(Arc::clone(&store), &file).unwrap();
            assert_eq!(imported, None);
            assert!(!store.imported(Source::Profiles).unwrap());
            assert_eq!(profiles.len(), 1);
            assert_eq!(profiles.get(b"ALICE"), Some(kept.clone()));
            assert_eq!(profiles.get(b"bob"), None);
        }
        std::fs::write(&file, b"Alice\tignored\nBob\tBob\n").unwrap();
        {
            let store = Arc::new(Store::open(&db).unwrap());
            let (profiles, imported) = Profiles::with_store(Arc::clone(&store), &file).unwrap();
            assert_eq!(imported, Some(1));
            assert!(store.imported(Source::Profiles).unwrap());
            assert_eq!(profiles.len(), 2);
            assert_eq!(profiles.get(b"alice"), Some(kept.clone()));
            assert_eq!(profiles.get(b"BOB"), Some(profile(b"Bob", b"")));
        }
        std::fs::write(&file, b"Alice\toverwritten\nBob\toverwritten\nCarol\tnew\n").unwrap();
        {
            let store = Arc::new(Store::open(&db).unwrap());
            let (profiles, imported) = Profiles::with_store(Arc::clone(&store), &file).unwrap();
            assert_eq!(imported, None);
            assert!(store.imported(Source::Profiles).unwrap());
            assert_eq!(profiles.len(), 2);
            assert_eq!(profiles.get(b"alice"), Some(kept));
            assert_eq!(profiles.get(b"bob"), Some(profile(b"Bob", b"")));
            assert_eq!(profiles.get(b"carol"), None);
        }
    }

    #[test]
    fn empty_profile_imports_complete_but_read_errors_do_not() {
        for directory in [false, true] {
            let dir = tempfile::tempdir().unwrap();
            let db = dir.path().join("data.sqlite");
            let file = dir.path().join("profiles.tsv");
            if directory {
                std::fs::create_dir(&file).unwrap();
            } else {
                std::fs::write(&file, b"").unwrap();
            }
            {
                let store = Arc::new(Store::open(&db).unwrap());
                if directory {
                    assert!(Profiles::with_store(Arc::clone(&store), &file).is_err());
                    assert!(!store.imported(Source::Profiles).unwrap());
                } else {
                    let (profiles, imported) =
                        Profiles::with_store(Arc::clone(&store), &file).unwrap();
                    assert_eq!(imported, Some(0));
                    assert!(profiles.is_empty());
                    assert!(store.imported(Source::Profiles).unwrap());
                }
            }
            if directory {
                std::fs::remove_dir(&file).unwrap();
            }
            std::fs::write(&file, b"Bob\tBob\n").unwrap();
            {
                let store = Arc::new(Store::open(&db).unwrap());
                let (profiles, imported) = Profiles::with_store(Arc::clone(&store), &file).unwrap();
                assert!(store.imported(Source::Profiles).unwrap());
                if directory {
                    assert_eq!(imported, Some(1));
                    assert_eq!(profiles.get(b"bob"), Some(profile(b"Bob", b"")));
                } else {
                    assert_eq!(imported, None);
                    assert!(profiles.is_empty());
                }
            }
        }
    }

    #[test]
    fn an_unterminated_profile_record_keeps_its_final_cr_and_spaces() {
        let dir = tempfile::tempdir().unwrap();
        let file = dir.path().join("profiles.tsv");
        let mut expected: Profile = Default::default();
        expected[0] = b"name ".to_vec();
        expected[8] = b" \r".to_vec();
        // Preserve the existing reader's bytes outside a consumed LF delimiter.
        let mut raw = b"Alice".to_vec();
        for field in &expected {
            raw.push(b'\t');
            raw.extend_from_slice(field);
        }
        std::fs::write(&file, raw).unwrap();
        assert_eq!(Profiles::open(&file).unwrap().get(b"alice"), Some(expected));
    }

    #[test]
    fn lf_and_crlf_profile_records_preserve_fields_in_text_and_sqlite() {
        for crlf in [false, true] {
            let dir = tempfile::tempdir().unwrap();
            let file = dir.path().join("profiles.tsv");
            let db = dir.path().join("data.sqlite");
            let mut alice: Profile = std::array::from_fn(|i| format!("field{i}").into_bytes());
            alice[0] = b"Al\\ice".to_vec();
            alice[2] = vec![0xff, b'x'];
            alice[3] = b"one\ttwo".to_vec();
            alice[8] = b"literal\r".to_vec();
            let mut bob: Profile = Default::default();
            bob[0] = b"Bob".to_vec();
            {
                let text = Profiles::open(&file).unwrap();
                text.set(b"Alice", alice.clone()).unwrap();
                text.set(b"Bob", bob.clone()).unwrap();
            }
            let canonical = std::fs::read(&file).unwrap();
            assert!(canonical.windows(2).any(|b| b == b"\\r"));
            let mut input = Vec::new();
            for byte in canonical {
                if crlf && byte == b'\n' {
                    input.push(b'\r');
                }
                input.push(byte);
            }
            std::fs::write(&file, &input).unwrap();
            {
                let text = Profiles::open(&file).unwrap();
                assert_eq!(text.len(), 2);
                assert_eq!(text.get(b"ALICE"), Some(alice.clone()), "CRLF={crlf}");
                assert_eq!(text.get(b"bob"), Some(bob.clone()), "CRLF={crlf}");
            }
            {
                let store = Arc::new(Store::open(&db).unwrap());
                let (profiles, imported) = Profiles::with_store(Arc::clone(&store), &file).unwrap();
                assert_eq!(imported, Some(2));
                assert!(store.imported(Source::Profiles).unwrap());
                assert_eq!(profiles.get(b"alice"), Some(alice.clone()));
                assert_eq!(profiles.get(b"BOB"), Some(bob.clone()));
            }
            {
                let store = Arc::new(Store::open(&db).unwrap());
                let (profiles, imported) =
                    Profiles::with_store(Arc::clone(&store), Path::new("")).unwrap();
                assert_eq!(imported, None);
                assert!(store.imported(Source::Profiles).unwrap());
                assert_eq!(profiles.get(b"alice"), Some(alice));
                assert_eq!(profiles.get(b"bob"), Some(bob));
            }
        }
    }
}
