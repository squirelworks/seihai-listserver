//! A timestamped log to standard error and, optionally, a file.

use std::fs::File;
use std::io::Write;
use std::path::Path;
use std::sync::Mutex;
use std::time::{SystemTime, UNIX_EPOCH};

static FILE: Mutex<Option<File>> = Mutex::new(None);

/// Also append the log to `path`.
pub fn open(path: &Path) -> std::io::Result<()> {
    let f = File::options().create(true).append(true).open(path)?;
    *FILE.lock().unwrap_or_else(|e| e.into_inner()) = Some(f);
    Ok(())
}

/// Stop appending the log to a file. Standard error is unchanged.
pub fn close() {
    *FILE.lock().unwrap_or_else(|e| e.into_inner()) = None;
}

/// Write one log line, prefixed with the UTC time.
pub fn line(msg: &str) {
    let secs = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |d| d.as_secs());
    let (h, m, s) = ((secs / 3600) % 24, (secs / 60) % 60, secs % 60);
    let text = format!("{h:02}:{m:02}:{s:02} {msg}\n");
    eprint!("{text}");
    if let Some(f) = FILE.lock().unwrap_or_else(|e| e.into_inner()).as_mut() {
        let _ = f.write_all(text.as_bytes());
    }
}

/// `log!("...", args)`: format and write one log line.
#[macro_export]
macro_rules! log {
    ($($arg:tt)*) => { $crate::log::line(&format!($($arg)*)) };
}
