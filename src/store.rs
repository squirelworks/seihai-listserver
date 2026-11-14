//! The `data` file: one SQLite database for what the listserver writes
//! while it runs (design §7, issue #39). Today that is player profiles and
//! buddy lists; accounts stay in the accounts file.
//!
//! The listserver still answers from memory. At start it reads every
//! profile and buddy list from the database, and each change is written to
//! the database before the reply goes out, one small transaction per change,
//! instead of rewriting a whole text file. With `data` empty nothing here is
//! used and the `profiles` / `buddies` text files (or memory) work as before.
//!
//! **One-shot import.** When `data` is set and the `profiles` or `buddies`
//! setting names a text file that exists, its rows are copied into the
//! database the first time, and the import is recorded so it never runs
//! again. A row already in the database wins over the file. After that the
//! text file is neither read nor written.
//!
//! Accounts are keyed in lower case (ASCII), as in memory. Every text
//! column is a BLOB because Graal text is bytes, not UTF-8.

use crate::profiles::{Profile, FIELDS};
use rusqlite::{params, Connection, OptionalExtension};
use std::collections::BTreeMap;
use std::path::Path;
use std::sync::{Mutex, MutexGuard};

/// The schema version kept in `PRAGMA user_version`.
const SCHEMA: i64 = 1;

const CREATE: &str = "
CREATE TABLE IF NOT EXISTS profiles (
    account   BLOB PRIMARY KEY,
    name      BLOB NOT NULL, age   BLOB NOT NULL, sex     BLOB NOT NULL,
    country   BLOB NOT NULL, messenger BLOB NOT NULL, email BLOB NOT NULL,
    url       BLOB NOT NULL, hangout   BLOB NOT NULL, quote BLOB NOT NULL
) WITHOUT ROWID;
CREATE TABLE IF NOT EXISTS buddies (
    account BLOB NOT NULL,
    pos     INTEGER NOT NULL,
    buddy   BLOB NOT NULL,
    PRIMARY KEY (account, pos)
) WITHOUT ROWID;
CREATE TABLE IF NOT EXISTS imports (
    source TEXT PRIMARY KEY,
    file   TEXT NOT NULL,
    rows   INTEGER NOT NULL,
    at     INTEGER NOT NULL
);
";

/// Which text file an import came from.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Source {
    Profiles,
    Buddies,
}

impl Source {
    fn name(self) -> &'static str {
        match self {
            Source::Profiles => "profiles",
            Source::Buddies => "buddies",
        }
    }
}

/// An open `data` file.
pub struct Store {
    conn: Mutex<Connection>,
}

fn err(path: &Path) -> impl Fn(rusqlite::Error) -> String + '_ {
    move |e| format!("{}: {e}", path.display())
}

fn db(e: rusqlite::Error) -> String {
    format!("data: {e}")
}

impl Store {
    /// Open or create the database at `path` and bring its tables up to
    /// date. A database from a newer listserver is refused.
    pub fn open(path: &Path) -> Result<Self, String> {
        let conn = Connection::open(path).map_err(err(path))?;
        conn.busy_timeout(std::time::Duration::from_secs(5))
            .map_err(err(path))?;
        // WAL: a reader (a backup, sqlite3 on the side) never blocks a write.
        conn.pragma_update(None, "journal_mode", "WAL")
            .map_err(err(path))?;
        conn.pragma_update(None, "synchronous", "NORMAL")
            .map_err(err(path))?;
        let version: i64 = conn
            .pragma_query_value(None, "user_version", |r| r.get(0))
            .map_err(err(path))?;
        if version > SCHEMA {
            return Err(format!(
                "{}: made by a newer listserver (schema {version}, this one knows {SCHEMA})",
                path.display()
            ));
        }
        conn.execute_batch(CREATE).map_err(err(path))?;
        conn.pragma_update(None, "user_version", SCHEMA)
            .map_err(err(path))?;
        Ok(Self {
            conn: Mutex::new(conn),
        })
    }

    /// An in-memory database, for tests.
    pub fn memory() -> Self {
        let conn = Connection::open_in_memory().expect("sqlite in memory");
        conn.execute_batch(CREATE).expect("schema");
        Self {
            conn: Mutex::new(conn),
        }
    }

    fn lock(&self) -> MutexGuard<'_, Connection> {
        self.conn.lock().unwrap_or_else(|e| e.into_inner())
    }

    /// Every stored profile, keyed by lower-case account.
    pub fn profiles(&self) -> Result<BTreeMap<Vec<u8>, Profile>, String> {
        let conn = self.lock();
        let mut q = conn
            .prepare(
                "SELECT account, name, age, sex, country, messenger, email, url, hangout, quote
                 FROM profiles",
            )
            .map_err(db)?;
        let rows = q
            .query_map([], |r| {
                let account: Vec<u8> = r.get(0)?;
                let mut p: Profile = Default::default();
                for (i, f) in p.iter_mut().enumerate() {
                    *f = r.get(i + 1)?;
                }
                Ok((account, p))
            })
            .map_err(db)?;
        rows.collect::<Result<_, _>>().map_err(db)
    }

    /// Store one account's profile (`account` already lower case).
    pub fn put_profile(&self, account: &[u8], p: &Profile) -> Result<(), String> {
        self.lock()
            .execute(
                "INSERT OR REPLACE INTO profiles
                 (account, name, age, sex, country, messenger, email, url, hangout, quote)
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10)",
                params![account, p[0], p[1], p[2], p[3], p[4], p[5], p[6], p[7], p[8]],
            )
            .map(drop)
            .map_err(db)
    }

    /// Every stored buddy list, keyed by lower-case account, in the order
    /// the buddies were added.
    pub fn buddies(&self) -> Result<BTreeMap<Vec<u8>, Vec<Vec<u8>>>, String> {
        let conn = self.lock();
        let mut q = conn
            .prepare("SELECT account, buddy FROM buddies ORDER BY account, pos")
            .map_err(db)?;
        let rows = q
            .query_map([], |r| {
                Ok((r.get::<_, Vec<u8>>(0)?, r.get::<_, Vec<u8>>(1)?))
            })
            .map_err(db)?;
        let mut map: BTreeMap<Vec<u8>, Vec<Vec<u8>>> = BTreeMap::new();
        for row in rows {
            let (account, buddy) = row.map_err(db)?;
            map.entry(account).or_default().push(buddy);
        }
        Ok(map)
    }

    /// Replace one account's buddy list (`account` already lower case). An
    /// empty list removes the account.
    pub fn put_buddies(&self, account: &[u8], list: &[Vec<u8>]) -> Result<(), String> {
        let mut conn = self.lock();
        let tx = conn.transaction().map_err(db)?;
        write_buddies(&tx, account, list)?;
        tx.commit().map_err(db)
    }

    /// Copy `rows` from the text file `file` into the database, once. An
    /// account already in the database keeps its row. Returns how many
    /// accounts were copied, or `None` when this source was imported before.
    pub fn import_profiles(
        &self,
        file: &Path,
        rows: &BTreeMap<Vec<u8>, Profile>,
    ) -> Result<Option<usize>, String> {
        self.import(Source::Profiles, file, |tx| {
            let mut n = 0;
            let mut q = tx
                .prepare(
                    "INSERT OR IGNORE INTO profiles
                     (account, name, age, sex, country, messenger, email, url, hangout, quote)
                     VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10)",
                )
                .map_err(db)?;
            for (account, p) in rows {
                n += q
                    .execute(params![
                        account, p[0], p[1], p[2], p[3], p[4], p[5], p[6], p[7], p[8]
                    ])
                    .map_err(db)?;
            }
            Ok(n)
        })
    }

    /// As [`Self::import_profiles`], for buddy lists.
    pub fn import_buddies(
        &self,
        file: &Path,
        rows: &BTreeMap<Vec<u8>, Vec<Vec<u8>>>,
    ) -> Result<Option<usize>, String> {
        self.import(Source::Buddies, file, |tx| {
            let mut n = 0;
            for (account, list) in rows {
                let have: Option<i64> = tx
                    .query_row(
                        "SELECT 1 FROM buddies WHERE account = ?1 LIMIT 1",
                        [account],
                        |r| r.get(0),
                    )
                    .optional()
                    .map_err(db)?;
                if have.is_none() && !list.is_empty() {
                    write_buddies(tx, account, list)?;
                    n += 1;
                }
            }
            Ok(n)
        })
    }

    /// `true` when `source` has been imported into this database.
    pub fn imported(&self, source: Source) -> Result<bool, String> {
        self.lock()
            .query_row(
                "SELECT 1 FROM imports WHERE source = ?1",
                [source.name()],
                |_| Ok(()),
            )
            .optional()
            .map(|r| r.is_some())
            .map_err(db)
    }

    fn import(
        &self,
        source: Source,
        file: &Path,
        copy: impl FnOnce(&rusqlite::Transaction) -> Result<usize, String>,
    ) -> Result<Option<usize>, String> {
        let mut conn = self.lock();
        let tx = conn.transaction().map_err(db)?;
        let done: Option<i64> = tx
            .query_row(
                "SELECT 1 FROM imports WHERE source = ?1",
                [source.name()],
                |r| r.get(0),
            )
            .optional()
            .map_err(db)?;
        if done.is_some() {
            return Ok(None);
        }
        let n = copy(&tx)?;
        let at = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map_or(0, |d| d.as_secs() as i64);
        tx.execute(
            "INSERT INTO imports (source, file, rows, at) VALUES (?1, ?2, ?3, ?4)",
            params![source.name(), file.display().to_string(), n as i64, at],
        )
        .map_err(db)?;
        tx.commit().map_err(db)?;
        Ok(Some(n))
    }
}

fn write_buddies(
    tx: &rusqlite::Transaction,
    account: &[u8],
    list: &[Vec<u8>],
) -> Result<(), String> {
    tx.execute("DELETE FROM buddies WHERE account = ?1", [account])
        .map_err(db)?;
    let mut q = tx
        .prepare("INSERT INTO buddies (account, pos, buddy) VALUES (?1, ?2, ?3)")
        .map_err(db)?;
    for (pos, b) in list.iter().enumerate() {
        q.execute(params![account, pos as i64, b]).map_err(db)?;
    }
    Ok(())
}

/// The number of profile fields, checked against the table at compile time.
const _: () = assert!(FIELDS == 9);

#[cfg(test)]
mod tests {
    use super::*;

    fn profile(name: &[u8]) -> Profile {
        let mut p: Profile = Default::default();
        p[0] = name.to_vec();
        p[8] = b"\xffnot utf-8\t".to_vec();
        p
    }

    #[test]
    fn rows_survive_reopening_the_file() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("data.sqlite");
        {
            let s = Store::open(&path).unwrap();
            s.put_profile(b"alice", &profile(b"Al")).unwrap();
            s.put_profile(b"alice", &profile(b"Alice")).unwrap();
            s.put_buddies(b"alice", &[b"bob".to_vec(), b"carol".to_vec()])
                .unwrap();
            s.put_buddies(b"bob", &[b"alice".to_vec()]).unwrap();
            s.put_buddies(b"bob", &[]).unwrap();
        }
        let s = Store::open(&path).unwrap();
        let p = s.profiles().unwrap();
        assert_eq!(p.len(), 1);
        assert_eq!(p[&b"alice".to_vec()], profile(b"Alice"));
        let b = s.buddies().unwrap();
        assert_eq!(b.len(), 1);
        assert_eq!(
            b[&b"alice".to_vec()],
            vec![b"bob".to_vec(), b"carol".to_vec()]
        );
    }

    #[test]
    fn an_import_runs_once_and_keeps_rows_already_there() {
        let s = Store::memory();
        s.put_profile(b"alice", &profile(b"kept")).unwrap();
        let mut rows = BTreeMap::new();
        rows.insert(b"alice".to_vec(), profile(b"from file"));
        rows.insert(b"bob".to_vec(), profile(b"Bob"));
        assert!(!s.imported(Source::Profiles).unwrap());
        assert_eq!(
            s.import_profiles(Path::new("p.tsv"), &rows).unwrap(),
            Some(1)
        );
        assert!(s.imported(Source::Profiles).unwrap());
        assert_eq!(s.import_profiles(Path::new("p.tsv"), &rows).unwrap(), None);
        let p = s.profiles().unwrap();
        assert_eq!(p[&b"alice".to_vec()], profile(b"kept"));
        assert_eq!(p[&b"bob".to_vec()], profile(b"Bob"));

        s.put_buddies(b"alice", &[b"x".to_vec()]).unwrap();
        let mut lists = BTreeMap::new();
        lists.insert(b"alice".to_vec(), vec![b"y".to_vec()]);
        lists.insert(b"bob".to_vec(), vec![b"z".to_vec(), b"w".to_vec()]);
        assert_eq!(
            s.import_buddies(Path::new("b.tsv"), &lists).unwrap(),
            Some(1)
        );
        assert_eq!(s.import_buddies(Path::new("b.tsv"), &lists).unwrap(), None);
        let b = s.buddies().unwrap();
        assert_eq!(b[&b"alice".to_vec()], vec![b"x".to_vec()]);
        assert_eq!(b[&b"bob".to_vec()], vec![b"z".to_vec(), b"w".to_vec()]);
    }

    #[test]
    fn a_newer_schema_is_refused() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("data.sqlite");
        Connection::open(&path)
            .unwrap()
            .pragma_update(None, "user_version", SCHEMA + 1)
            .unwrap();
        let Err(e) = Store::open(&path) else {
            panic!("a newer schema was opened");
        };
        assert!(e.contains("newer listserver"), "{e}");
    }
}
