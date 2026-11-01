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
//! - id 7 with the token `SEI00001` (the Seihai secure login): the server
//!   hello in a plain frame, then the sealed id 1 in a plain frame, then the
//!   gen-5 reply as for id 7. See Seihai's `documentation/secure-login.md`.
//!
//! The list is tagged with the HQ level for gen 4 and gen 5 only. A refused
//! login gets id 4 (the error text) and the link is closed.
//!
//! Shape S (real 1.41 rev 1) sends nothing. When `silent_list_after_ms` is
//! set and no byte arrives in that time, the shape A reply goes out.

use crate::accounts::GuessKind;
use crate::server::Shared;
use crate::state::{plo, status_message};
use crate::wire::{self, gchar, show, Fields};
use seihai_core::protocol::seclogin::{self, ClientHello};
use seihai_core::protocol::{
    bz2_compress, bz2_decompress, zlib_compress, zlib_decompress, Gen5, Gen5Comp,
};
use std::io::{self, BufReader, Read, Write};
use std::net::{IpAddr, Shutdown, TcpStream};
use std::time::Duration;

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
    let peer_ip = stream.peer_addr().ok().map(|a| a.ip());
    let peer = peer_ip.map(|ip| ip.to_string()).unwrap_or_default();
    log!("client {id} on {port} from {peer}");
    match run(stream, id, shared, peer_ip) {
        Ok(()) => log!("client {id} closed"),
        Err(e) => log!("client {id} closed ({e})"),
    }
}

fn run(stream: TcpStream, id: u64, shared: &Shared, peer: Option<IpAddr>) -> io::Result<()> {
    let timeout = shared.config().client_timeout();
    stream.set_read_timeout(Some(timeout))?;
    let mut writer = stream.try_clone()?;
    let mut reader = BufReader::new(stream);
    let mut coding = Coding::Plain;

    let silent = shared.config().silent_list_after();
    if !silent.is_zero() {
        match first_byte_ready(reader.get_ref(), silent) {
            Ok(false) => {
                log!("client {id} sent nothing; sending the list");
                let list = shared.servers.list_message(false);
                send(&mut writer, &mut coding, &[list, status(shared, b"player")])?;
            }
            Ok(true) => {}
            Err(e) if e.kind() == io::ErrorKind::UnexpectedEof => return Ok(()),
            Err(e) => return Err(e),
        }
        reader.get_ref().set_read_timeout(Some(timeout))?;
    }

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
                    if shared.config().require_secure_login {
                        log!("client {id} sent its account in the clear; refused (require_secure_login)");
                        return refuse(&mut writer, &mut coding, NEED_SECURE);
                    }
                    if answer_account(&mut writer, &mut coding, id, shared, peer, payload)? {
                        return Ok(());
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
                pli::V2ENCRYPTKEYCL if payload.get(1..9).is_some_and(seclogin::is_token) => {
                    // The Seihai secure login: C1 here, S1 back, then C2
                    // with id 1's payload sealed. Anything after C1 in its
                    // frame is ignored.
                    return secure_login(
                        &mut reader,
                        &mut writer,
                        &mut coding,
                        id,
                        shared,
                        peer,
                        line,
                    );
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

/// Error text for a classic account login when `require_secure_login` is on.
pub const NEED_SECURE: &[u8] = b"This listserver needs the Seihai secure login.";
/// Error text for a secure login when it is turned off.
pub const SECURE_OFF: &[u8] = b"Secure login is turned off on this listserver.";

/// `Ok(false)` when `wait` passes with nothing to read (shape S).
fn first_byte_ready(stream: &TcpStream, wait: Duration) -> io::Result<bool> {
    stream.set_read_timeout(Some(wait))?;
    let mut b = [0u8; 1];
    loop {
        match stream.peek(&mut b) {
            Ok(0) => {
                return Err(io::Error::new(
                    io::ErrorKind::UnexpectedEof,
                    "closed before a frame",
                ))
            }
            Ok(_) => return Ok(true),
            Err(e) if e.kind() == io::ErrorKind::Interrupted => continue,
            Err(e)
                if e.kind() == io::ErrorKind::TimedOut || e.kind() == io::ErrorKind::WouldBlock =>
            {
                return Ok(false);
            }
            Err(e) => return Err(e),
        }
    }
}

/// Answer id 1 (`payload`: account and password GSTRINGs). `true` when the
/// login was refused and the link is to close.
fn answer_account(
    writer: &mut TcpStream,
    coding: &mut Coding,
    id: u64,
    shared: &Shared,
    peer: Option<IpAddr>,
    payload: &[u8],
) -> io::Result<bool> {
    let mut f = Fields::new(payload);
    let (Some(account), Some(password)) = (f.gstr(), f.gstr()) else {
        log!("client {id} bad account message: {}", show(payload));
        return Ok(false);
    };
    log!("client {id} account {}", show(account));
    if let Some(err) = shared.check_login(GuessKind::Client, peer, account, password) {
        log!("client {id} refused {}: {}", show(account), show(err));
        refuse(writer, coding, err)?;
        return Ok(true);
    }
    let list = shared.servers.list_message(coding.tagged());
    let status = status(shared, account);
    if let Coding::Gen5 { .. } = coding {
        send(writer, coding, &[list])?;
        let cfg = shared.config();
        let site = [vec![gchar(plo::SITEURL)], cfg.site_url.into_bytes()].concat();
        let upgrade = [vec![gchar(plo::UPGURL)], cfg.upgrade_url.into_bytes()].concat();
        send(writer, coding, &[status, site, upgrade])?;
    } else {
        send(writer, coding, &[list, status])?;
    }
    Ok(false)
}

/// Send id 4 with `err` and close the sending side.
fn refuse(writer: &mut TcpStream, coding: &mut Coding, err: &[u8]) -> io::Result<()> {
    let mut msg = vec![gchar(plo::ERROR)];
    msg.extend_from_slice(err);
    send(writer, coding, &[msg])?;
    let _ = writer.shutdown(Shutdown::Write);
    Ok(())
}

/// The Seihai secure login (`SEI00001`) from C1 (`line`, the whole id 7
/// message) to the list reply. See Seihai's `documentation/secure-login.md`.
fn secure_login<R: Read>(
    reader: &mut R,
    writer: &mut TcpStream,
    coding: &mut Coding,
    id: u64,
    shared: &Shared,
    peer: Option<IpAddr>,
    line: &[u8],
) -> io::Result<()> {
    let bad = |what: String| {
        log!("client {id} secure login failed: {what}");
        Ok(())
    };
    let hello = match ClientHello::parse(line, 2) {
        Some(Ok(h)) => h,
        Some(Err(e)) => return bad(e.to_string()),
        None => return bad("no token".into()),
    };
    let key = hello.prefix[1].wrapping_sub(32);
    log!(
        "client {id} secure login SEI00001, inner token {}, list {}",
        show(&hello.inner),
        show(&hello.suffix)
    );
    let (s1, opener) = {
        let guard = shared.identity();
        let Some(identity) = guard.as_ref() else {
            log!("client {id} secure login refused: secure_login_key is empty");
            return refuse(writer, coding, SECURE_OFF);
        };
        match hello.respond(identity) {
            Ok(r) => r,
            Err(e) => return bad(e.to_string()),
        }
    };
    send(writer, coding, &[s1])?;
    let body = wire::read_frame(reader)?;
    let raw = match coding.decode(body) {
        Ok(r) => r,
        Err(e) => return bad(format!("undecodable C2 frame ({e})")),
    };
    let Some(c2) = wire::lines(&raw).next() else {
        return bad("empty C2 frame".into());
    };
    let tail = match opener.open(c2) {
        Ok(t) => t,
        Err(e) => return bad(e.to_string()),
    };
    *coding = Coding::Gen5 {
        cin: Gen5::new(key),
        cout: Gen5::new(key),
    };
    answer_account(writer, coding, id, shared, peer, &tail)?;
    Ok(())
}

fn status(shared: &Shared, account: &[u8]) -> Vec<u8> {
    let cfg = shared.config();
    status_message(
        &cfg.status,
        &cfg.list_name,
        account,
        shared.servers.listed(),
    )
}

fn send(w: &mut TcpStream, coding: &mut Coding, msgs: &[Vec<u8>]) -> io::Result<()> {
    let body = coding.encode(msgs)?;
    wire::write_frame(w, &body)?;
    w.flush()
}
