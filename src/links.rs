//! Sending to gserver links from any thread (design §0.2).
//!
//! Each gserver link has an outbox: a bounded queue of message lines and a
//! writer thread that owns the link's sending half. The link's own replies
//! and messages pushed by other links (cross-server PMs, channel chat,
//! player counts) go through the same queue, so they never interleave mid
//! frame, and a slow gserver never blocks the link that pushes to it.

use crate::wire::show;
use seihai_core::protocol::seclogin::{ChannelRecv, ChannelSend};
use seihai_core::protocol::write_zlib_frame;
use std::collections::BTreeMap;
use std::io::{self, BufReader, Read, Write};
use std::net::TcpStream;
use std::sync::mpsc::{self, Receiver, SyncSender, TrySendError};
use std::sync::Mutex;
use std::time::Duration;

/// Lines waiting for one gserver before more are dropped.
const QUEUE: usize = 1024;

/// How long a write to a gserver may block before the link is given up.
const WRITE_TIMEOUT: Duration = Duration::from_secs(30);

/// Where a link's frames go: in the clear, or sealed into the encrypted
/// link's records.
pub enum Sink {
    Plain(TcpStream),
    Sealed(TcpStream, ChannelSend),
}

impl Sink {
    fn send(&mut self, frame: &[u8]) -> io::Result<()> {
        match self {
            Sink::Plain(s) => {
                s.write_all(frame)?;
                s.flush()
            }
            Sink::Sealed(s, ch) => {
                s.write_all(&ch.seal(frame))?;
                s.flush()
            }
        }
    }

    fn stream(&self) -> &TcpStream {
        match self {
            Sink::Plain(s) | Sink::Sealed(s, _) => s,
        }
    }
}

/// The sending side of one link: lines in, frames out on the writer thread.
#[derive(Clone)]
pub struct Outbox {
    tx: SyncSender<Vec<u8>>,
}

impl Outbox {
    /// Start the writer thread for `sink`. It ends when every [`Outbox`]
    /// clone is dropped, or when a write fails (the link is then shut so
    /// its reader ends too).
    pub fn start(id: u64, sink: Sink) -> io::Result<Outbox> {
        sink.stream().set_write_timeout(Some(WRITE_TIMEOUT))?;
        let (tx, rx) = mpsc::sync_channel(QUEUE);
        std::thread::Builder::new()
            .name(format!("gserver-{id}-out"))
            .spawn(move || write_loop(id, sink, rx))?;
        Ok(Outbox { tx })
    }

    /// An outbox whose lines are kept, for tests.
    #[cfg(test)]
    pub fn for_test() -> (Outbox, Receiver<Vec<u8>>) {
        let (tx, rx) = mpsc::sync_channel(QUEUE);
        (Outbox { tx }, rx)
    }

    /// Queue one or more message lines (each ending in `\n`) to go out as
    /// one frame. `false` when the queue is full or the link has closed;
    /// the lines are dropped.
    pub fn send(&self, lines: Vec<u8>) -> bool {
        match self.tx.try_send(lines) {
            Ok(()) => true,
            Err(TrySendError::Full(l)) => {
                log!("gserver outbox full, dropped {}", show(&l));
                false
            }
            Err(TrySendError::Disconnected(_)) => false,
        }
    }
}

fn write_loop(id: u64, mut sink: Sink, rx: Receiver<Vec<u8>>) {
    while let Ok(lines) = rx.recv() {
        let r = write_zlib_frame(&lines).and_then(|frame| sink.send(&frame));
        if let Err(e) = r {
            log!("gserver {id} write failed ({e}), closing the link");
            let _ = sink.stream().shutdown(std::net::Shutdown::Both);
            return;
        }
    }
}

/// Authenticated gserver links' outboxes, by link id. Intentionally open
/// mode links are eligible immediately; password-gated links are added
/// by the session only after their HQ password is accepted.
#[derive(Default)]
pub struct Links {
    out: Mutex<BTreeMap<u64, Outbox>>,
}

impl Links {
    pub fn add(&self, id: u64, outbox: Outbox) {
        self.lock().insert(id, outbox);
    }

    pub fn remove(&self, id: u64) {
        self.lock().remove(&id);
    }

    /// Queue `lines` to link `id`. A closed or unknown link is ignored.
    pub fn send(&self, id: u64, lines: Vec<u8>) -> bool {
        let outbox = self.lock().get(&id).cloned();
        outbox.is_some_and(|o| o.send(lines))
    }

    /// Queue `lines` to every link except `except`.
    pub fn send_others(&self, except: u64, lines: &[u8]) {
        let targets: Vec<Outbox> = self
            .lock()
            .iter()
            .filter(|(&id, _)| id != except)
            .map(|(_, o)| o.clone())
            .collect();
        for o in targets {
            o.send(lines.to_vec());
        }
    }

    fn lock(&self) -> std::sync::MutexGuard<'_, BTreeMap<u64, Outbox>> {
        self.out.lock().unwrap_or_else(|e| e.into_inner())
    }
}

/// The reading half of the encrypted link: records opened in order from
/// the buffered stream the hello was read with.
pub struct SealedRead {
    inner: BufReader<TcpStream>,
    ch: ChannelRecv,
    buf: Vec<u8>,
    at: usize,
}

impl SealedRead {
    pub fn new(inner: BufReader<TcpStream>, ch: ChannelRecv) -> Self {
        Self {
            inner,
            ch,
            buf: Vec::new(),
            at: 0,
        }
    }
}

impl Read for SealedRead {
    fn read(&mut self, out: &mut [u8]) -> io::Result<usize> {
        while self.at >= self.buf.len() {
            match self.ch.read_record(&mut self.inner)? {
                Some(rec) => {
                    self.buf = rec;
                    self.at = 0;
                }
                None => return Ok(0),
            }
        }
        let n = out.len().min(self.buf.len() - self.at);
        out[..n].copy_from_slice(&self.buf[self.at..self.at + n]);
        self.at += n;
        Ok(n)
    }
}
