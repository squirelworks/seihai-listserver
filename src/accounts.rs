//! Who may log in: open mode, or an accounts file of argon2 password hashes.
//!
//! File format: one account per line, `ACCOUNT HASH`, where HASH is an
//! argon2 PHC string (`$argon2id$...`). Blank lines and lines starting with
//! `#` are skipped. A line whose second field is not an argon2 hash (such as
//! the Python lab listserver's plain passwords) is skipped with a warning, so
//! that account cannot log in until it is added again.
//!
//! The file is read again whenever its modification time changes, so
//! `add-account` works on a running listserver.

use argon2::password_hash::rand_core::OsRng;
use argon2::password_hash::SaltString;
use argon2::{Argon2, PasswordHash, PasswordHasher, PasswordVerifier};
use std::collections::HashMap;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::sync::Mutex;
use std::time::SystemTime;

/// Error text for an account that is not in the file.
pub const NO_ACCOUNT: &[u8] = b"Account does not exist.";
/// Error text for a wrong password.
pub const BAD_PASSWORD: &[u8] = b"Your password is incorrect.";

/// The account check.
pub enum Accounts {
    /// Every account and password gets in.
    Open,
    /// Only the accounts in the file get in.
    File(Mutex<FileAccounts>),
}

pub struct FileAccounts {
    path: PathBuf,
    modified: Option<SystemTime>,
    hashes: HashMap<Vec<u8>, String>,
}

impl Accounts {
    /// Open mode for an empty path, else the accounts in `path`.
    pub fn new(path: &Path) -> Result<Self, String> {
        if path.as_os_str().is_empty() {
            return Ok(Self::Open);
        }
        let mut f = FileAccounts {
            path: path.to_path_buf(),
            modified: None,
            hashes: HashMap::new(),
        };
        f.reload()?;
        Ok(Self::File(Mutex::new(f)))
    }

    /// `None` when the login is allowed, else the error text for the client.
    pub fn check(&self, account: &[u8], password: &[u8]) -> Option<&'static [u8]> {
        let Self::File(f) = self else { return None };
        let hash = {
            let mut f = f.lock().unwrap_or_else(|e| e.into_inner());
            if let Err(e) = f.reload_if_changed() {
                crate::log::line(&format!("accounts: {e}; keeping the accounts read before"));
            }
            f.hashes.get(account).cloned()
        };
        let Some(hash) = hash else {
            return Some(NO_ACCOUNT);
        };
        if verify(&hash, password) {
            None
        } else {
            Some(BAD_PASSWORD)
        }
    }

    /// A short description for the log.
    pub fn describe(&self) -> String {
        match self {
            Self::Open => "open (every account gets in)".into(),
            Self::File(f) => {
                let f = f.lock().unwrap_or_else(|e| e.into_inner());
                format!("{} account(s) from {}", f.hashes.len(), f.path.display())
            }
        }
    }
}

impl FileAccounts {
    fn reload_if_changed(&mut self) -> Result<(), String> {
        let modified = std::fs::metadata(&self.path)
            .and_then(|m| m.modified())
            .ok();
        if modified.is_none() || modified != self.modified {
            self.reload()?;
        }
        Ok(())
    }

    fn reload(&mut self) -> Result<(), String> {
        let modified = std::fs::metadata(&self.path)
            .and_then(|m| m.modified())
            .ok();
        let text =
            std::fs::read(&self.path).map_err(|e| format!("{}: {e}", self.path.display()))?;
        self.hashes = parse(&text, &self.path);
        self.modified = modified;
        Ok(())
    }
}

fn parse(text: &[u8], path: &Path) -> HashMap<Vec<u8>, String> {
    let mut out = HashMap::new();
    for (n, line) in text.split(|&b| b == b'\n').enumerate() {
        let mut parts = line
            .split(|b| b.is_ascii_whitespace())
            .filter(|p| !p.is_empty());
        let (Some(account), Some(hash)) = (parts.next(), parts.next()) else {
            continue;
        };
        if account.starts_with(b"#") {
            continue;
        }
        match std::str::from_utf8(hash) {
            Ok(h) if h.starts_with("$argon2") && PasswordHash::new(h).is_ok() => {
                out.insert(account.to_vec(), h.to_string());
            }
            _ => crate::log::line(&format!(
                "accounts: {} line {}: {} has no argon2 hash, skipped (add it again with add-account)",
                path.display(),
                n + 1,
                crate::wire::show(account)
            )),
        }
    }
    out
}

fn verify(hash: &str, password: &[u8]) -> bool {
    PasswordHash::new(hash).is_ok_and(|h| Argon2::default().verify_password(password, &h).is_ok())
}

/// An argon2id hash of `password`.
pub fn hash_password(password: &[u8]) -> Result<String, String> {
    let salt = SaltString::generate(&mut OsRng);
    Argon2::default()
        .hash_password(password, &salt)
        .map(|h| h.to_string())
        .map_err(|e| e.to_string())
}

/// Check an account name: what the gserver and the list can carry.
pub fn valid_account(account: &str) -> Result<(), String> {
    if account.is_empty() || account.len() > crate::wire::GCHAR_MAX {
        return Err(format!(
            "an account name is 1 to {} bytes",
            crate::wire::GCHAR_MAX
        ));
    }
    if account.starts_with('#')
        || account
            .bytes()
            .any(|b| b.is_ascii_whitespace() || b.is_ascii_control())
    {
        return Err(
            "an account name has no spaces or control characters and does not start with #".into(),
        );
    }
    Ok(())
}

/// Add `account` to the file at `path`, or replace its password. The file is
/// created when missing and written whole through a temporary file.
pub fn add_account(path: &Path, account: &str, password: &[u8]) -> Result<bool, String> {
    valid_account(account)?;
    if password.is_empty() {
        return Err("the password is empty".into());
    }
    let hash = hash_password(password)?;
    let old = match std::fs::read(path) {
        Ok(t) => t,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Vec::new(),
        Err(e) => return Err(format!("{}: {e}", path.display())),
    };
    let mut out = Vec::new();
    let mut replaced = false;
    for line in old.split(|&b| b == b'\n').filter(|l| !l.is_empty()) {
        let first = line
            .split(|b| b.is_ascii_whitespace())
            .find(|p| !p.is_empty());
        if first == Some(account.as_bytes()) {
            replaced = true;
            continue;
        }
        out.extend_from_slice(line);
        out.push(b'\n');
    }
    out.extend_from_slice(format!("{account} {hash}\n").as_bytes());
    let tmp = path.with_extension("tmp");
    let write = || -> std::io::Result<()> {
        let mut f = std::fs::File::create(&tmp)?;
        f.write_all(&out)?;
        f.sync_all()?;
        std::fs::rename(&tmp, path)
    };
    write().map_err(|e| format!("{}: {e}", path.display()))?;
    Ok(replaced)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn open_mode_lets_everyone_in() {
        let a = Accounts::new(Path::new("")).unwrap();
        assert_eq!(a.check(b"anyone", b"anything"), None);
    }

    #[test]
    fn file_accounts_check_hashes_and_skip_plain_passwords() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("accounts.txt");
        std::fs::write(&path, "# comment\nplain hunter2\n").unwrap();
        assert!(!add_account(&path, "test1", b"labpw").unwrap());
        let a = Accounts::new(&path).unwrap();
        assert_eq!(a.check(b"test1", b"labpw"), None);
        assert_eq!(a.check(b"test1", b"wrong"), Some(BAD_PASSWORD));
        assert_eq!(a.check(b"plain", b"hunter2"), Some(NO_ACCOUNT));
        assert_eq!(a.check(b"nobody", b"x"), Some(NO_ACCOUNT));
        let text = std::fs::read_to_string(&path).unwrap();
        assert!(
            !text.contains("labpw"),
            "the password is stored as a hash only"
        );
    }

    #[test]
    fn add_account_replaces_and_is_picked_up_live() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("accounts.txt");
        add_account(&path, "a", b"one").unwrap();
        let acc = Accounts::new(&path).unwrap();
        assert_eq!(acc.check(b"a", b"one"), None);
        // Make sure the modification time moves on filesystems with coarse times.
        std::thread::sleep(std::time::Duration::from_millis(20));
        assert!(add_account(&path, "a", b"two").unwrap());
        add_account(&path, "b", b"three").unwrap();
        let f = std::fs::File::options().write(true).open(&path).unwrap();
        f.set_modified(SystemTime::now() + std::time::Duration::from_secs(5))
            .unwrap();
        assert_eq!(acc.check(b"a", b"two"), None);
        assert_eq!(acc.check(b"a", b"one"), Some(BAD_PASSWORD));
        assert_eq!(acc.check(b"b", b"three"), None);
        assert_eq!(std::fs::read_to_string(&path).unwrap().lines().count(), 2);
    }

    #[test]
    fn bad_account_names_are_refused() {
        assert!(valid_account("ok_name").is_ok());
        for bad in ["", "two words", "#x", "tab\there"] {
            assert!(valid_account(bad).is_err(), "{bad:?}");
        }
    }
}
