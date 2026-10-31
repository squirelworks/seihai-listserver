//! The client side: every login shape gets the list it expects.
//!
//! Every link starts with plain zlib frames (`u16be` length + zlib body).
//!
//! - id 0 and the list name alone (2.00, 2.05; shape A): id 0 list, then
//!   id 2 status, in one frame.
//! - id 0 and id 1 (account, password) in one frame (2.17; shape B): the
//!   same reply, once, after the account.
//! - id 4, key, token (gen 4, 2.19 to 2.21): from then on every frame is
//!   bz2 and partly XORed, with no compression byte.
//! - id 5, key, token (the RC list) and id 7, key, token, list name (gen 5,
//!   2.22, 2.31 and 3.x): from then on gen-5 frames. After id 1 the reply
//!   is two zlib frames: id 0 list; then id 2 status, id 3 site URL and
//!   id 5 upgrade URL.
//!
//! The list is tagged with the HQ level for gen 4 and gen 5 only. A refused
//! login gets id 4 (the error text) and the link is closed.

use crate::server::Shared;
use crate::state::{plo, status_message};
use crate::wire::{self, gchar, show, Fields};
use seihai_core::protocol::{
    bz2_compress, bz2_decompress, zlib_compress, zlib_decompress, Gen5, Gen5Comp,
};
use std::io::{self, BufReader, Write};
use std::net::{Shutdown, TcpStream};

/// Client to listserver ids.
pub mod pli {
    pub const V1VER: usize = 0;
    pub const SERVERLIST: usize = 1;
    pub const V2VER: usize = 4;
    pub const V2SERVERLISTRC: usize = 5;
    pub const V2ENCRYPTKEYCL: usize = 7;
}

/// How the link's frames are coded.
enum Coding {
    /// zlib, no cipher (the first frame of every link, and 2.00 to 2.17).
    Plain,
    /// bz2 and the partial XOR, no compression byte (2.19 to 2.21).
    Gen4 { cin: Gen5, cout: Gen5 },
    /// Compression byte and the partial XOR (2.22 and later, the RC list).
    Gen5 { cin: Gen5, cout: Gen5 },
}

impl Coding {
    fn decode(&mut self, body: Vec<u8>) -> io::Result<Vec<u8>> {
        match self {
            Self::Plain => zlib_decompress(&body),
            Self::Gen4 { cin, .. } => bz2_decompress(&cin.decode(body, Gen5Comp::Bz2)),
            Self::Gen5 { cin, .. } => {
                let (&ctype, rest) = body.split_first().ok_or_else(|| {
                    io::Error::new(io::ErrorKind::InvalidData, "empty gen-5 frame")
                })?;
                let comp = match ctype {
                    0x02 => Gen5Comp::None,
                    0x04 => Gen5Comp::Zlib,
                    0x06 => Gen5Comp::Bz2,
                    b => {
                        return Err(io::Error::new(
                            io::ErrorKind::InvalidData,
                            format!("unknown gen-5 compression byte {b:#04x}"),
                        ))
                    }
                };
                let rest = cin.decode(rest.to_vec(), comp);
                match comp {
                    Gen5Comp::None => Ok(rest),
                    Gen5Comp::Zlib => zlib_decompress(&rest),
                    Gen5Comp::Bz2 => bz2_decompress(&rest),
                }
            }
        }
    }

    /// One frame body holding `msgs`, each followed by a line feed.
    fn encode(&mut self, msgs: &[Vec<u8>]) -> io::Result<Vec<u8>> {
        let mut data = Vec::new();
        for m in msgs {
            data.extend_from_slice(m);
            data.push(b'\n');
        }
        Ok(match self {
            Self::Plain => zlib_compress(&data)?,
            Self::Gen4 { cout, .. } => cout.encode(bz2_compress(&data)?, Gen5Comp::Bz2),
            Self::Gen5 { cout, .. } => {
                let mut body = vec![Gen5Comp::Zlib as u8];
                body.extend(cout.encode(zlib_compress(&data)?, Gen5Comp::Zlib));
                body
            }
        })
    }

    fn tagged(&self) -> bool {
        !matches!(self, Self::Plain)
    }
}

pub fn serve(stream: TcpStream, id: u64, port: u16, shared: &Shared) {
    let peer = stream
        .peer_addr()
        .map(|a| a.to_string())
        .unwrap_or_default();
    log!("client {id} on {port} from {peer}");
    match run(stream, id, shared) {
        Ok(()) => log!("client {id} closed"),
        Err(e) => log!("client {id} closed ({e})"),
    }
}

// TODO(docs/NEXT.md item 3): send the shape A reply to a link that stays
// silent (real 1.41 rev 1 waits for the listserver to speak first).
fn run(stream: TcpStream, id: u64, shared: &Shared) -> io::Result<()> {
    stream.set_read_timeout(Some(shared.config.client_timeout()))?;
    let mut writer = stream.try_clone()?;
    let mut reader = BufReader::new(stream);
    let mut coding = Coding::Plain;

    loop {
        let body = match wire::read_frame(&mut reader) {
            Ok(b) => b,
            Err(e) if e.kind() == io::ErrorKind::UnexpectedEof => return Ok(()),
            Err(e) => return Err(e),
        };
        let raw = match coding.decode(body) {
            Ok(r) => r,
            Err(e) => {
                log!("client {id} undecodable frame ({e})");
                continue;
            }
        };
        let msgs: Vec<&[u8]> = wire::lines(&raw).collect();
        let has_account = msgs
            .iter()
            .any(|l| l[0].wrapping_sub(32) as usize == pli::SERVERLIST);
        for line in msgs {
            let pid = line[0].wrapping_sub(32) as usize;
            let payload = &line[1..];
            match pid {
                pli::SERVERLIST => {
                    let mut f = Fields::new(payload);
                    let (Some(account), Some(password)) = (f.gstr(), f.gstr()) else {
                        log!("client {id} bad account message: {}", show(payload));
                        continue;
                    };
                    log!("client {id} account {}", show(account));
                    if let Some(err) = shared.accounts.check(account, password) {
                        log!("client {id} refused {}: {}", show(account), show(err));
                        let mut msg = vec![gchar(plo::ERROR)];
                        msg.extend_from_slice(err);
                        send(&mut writer, &mut coding, &[msg])?;
                        let _ = writer.shutdown(Shutdown::Write);
                        return Ok(());
                    }
                    let list = shared.servers.list_message(coding.tagged());
                    let status = status(shared, account);
                    if let Coding::Gen5 { .. } = coding {
                        send(&mut writer, &mut coding, &[list])?;
                        let site = [
                            vec![gchar(plo::SITEURL)],
                            shared.config.site_url.as_bytes().to_vec(),
                        ]
                        .concat();
                        let upgrade = [
                            vec![gchar(plo::UPGURL)],
                            shared.config.upgrade_url.as_bytes().to_vec(),
                        ]
                        .concat();
                        send(&mut writer, &mut coding, &[status, site, upgrade])?;
                    } else {
                        send(&mut writer, &mut coding, &[list, status])?;
                    }
                }
                pli::V1VER => {
                    log!("client {id} list name {}", show(payload));
                    // 2.00 and 2.05 send the list name only and get the list at once.
                    if !has_account {
                        let list = shared.servers.list_message(false);
                        send(&mut writer, &mut coding, &[list, status(shared, b"player")])?;
                    }
                }
                pli::V2VER | pli::V2SERVERLISTRC | pli::V2ENCRYPTKEYCL => {
                    let Some(&key) = payload.first() else {
                        continue;
                    };
                    let key = key.wrapping_sub(32);
                    let (cin, cout) = (Gen5::new(key), Gen5::new(key));
                    coding = if pid == pli::V2VER {
                        Coding::Gen4 { cin, cout }
                    } else {
                        Coding::Gen5 { cin, cout }
                    };
                    let token = payload.get(1..9).unwrap_or_default();
                    let list = payload.get(9..).unwrap_or_default();
                    log!(
                        "client {id} handshake id {pid}, gen {}, token {}, list {}",
                        if pid == pli::V2VER { 4 } else { 5 },
                        show(token),
                        show(list)
                    );
                }
                _ => log!("client {id} unhandled id {pid}: {}", show(payload)),
            }
        }
    }
}

fn status(shared: &Shared, account: &[u8]) -> Vec<u8> {
    status_message(
        &shared.config.status,
        &shared.config.list_name,
        account,
        shared.servers.listed(),
    )
}

fn send(w: &mut TcpStream, coding: &mut Coding, msgs: &[Vec<u8>]) -> io::Result<()> {
    let body = coding.encode(msgs)?;
    wire::write_frame(w, &body)?;
    w.flush()
}
