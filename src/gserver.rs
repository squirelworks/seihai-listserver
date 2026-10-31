//! The gserver side: registration, the list entry, player counts and
//! account checks.
//!
//! A gserver first sends `SVO_REGISTERV3` as one uncompressed line, then
//! zlib frames (`u16be` length + zlib body of lines). The listserver
//! answers only `VERIACC2`, with `SVI_VERIACC2`. The entry is dropped when
//! the link closes or stays silent past `gserver_timeout_secs`.

use crate::server::Shared;
use crate::wire::{self, gchar, put_gstr, show, Fields};
use seihai_core::protocol::{write_zlib_frame, zlib_decompress};
use std::io::{self, BufRead, BufReader, Read, Write};
use std::net::TcpStream;

/// Gserver to listserver ids.
pub mod svo {
    pub const SETIP: usize = 5;
    pub const SETPLYR: usize = 7;
    pub const PLYRADD: usize = 14;
    pub const PLYRREM: usize = 15;
    pub const PING: usize = 16;
    pub const VERIACC2: usize = 17;
    pub const NEWSERVER: usize = 22;
    pub const SERVERHQPASS: usize = 23;
    pub const SERVERHQLEVEL: usize = 24;
    pub const REGISTERV3: usize = 30;
    pub const SENDTEXT: usize = 31;
}

/// Listserver to gserver ids.
pub mod svi {
    pub const VERIACC2: usize = 11;
}

/// The longest `REGISTERV3` line taken.
const MAX_REGISTER: u64 = 1024;

pub fn serve(stream: TcpStream, id: u64, shared: &Shared) {
    let peer = stream
        .peer_addr()
        .map(|a| a.ip().to_string())
        .unwrap_or_default();
    log!("gserver {id} connected from {peer}");
    shared.servers.insert(id);
    let result = run(stream, id, &peer, shared);
    let entry = shared.servers.remove(id);
    let name = entry
        .and_then(|e| e.name)
        .map(|n| show(&n))
        .unwrap_or_else(|| "(no name)".into());
    match result {
        Ok(()) => log!("gserver {id} closed: {name}, entry dropped"),
        Err(e) => log!("gserver {id} closed ({e}): {name}, entry dropped"),
    }
}

// TODO(docs/NEXT.md item 2): an allow-list of gserver addresses and HQ
// passwords; today any link to the gserver port can register.
fn run(stream: TcpStream, id: u64, peer: &str, shared: &Shared) -> io::Result<()> {
    stream.set_read_timeout(Some(shared.config.gserver_timeout()))?;
    let mut writer = stream.try_clone()?;
    let mut reader = BufReader::new(stream);

    let mut reg = Vec::new();
    (&mut reader)
        .take(MAX_REGISTER)
        .read_until(b'\n', &mut reg)?;
    if !reg.ends_with(b"\n") {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "no REGISTERV3 line",
        ));
    }
    let reg_id = reg[0].wrapping_sub(32) as usize;
    let reg = &reg[1..reg.len() - 1];
    if reg_id == svo::REGISTERV3 {
        log!("gserver {id} register {}", show(reg));
    } else {
        log!(
            "gserver {id} first line has id {reg_id}, not REGISTERV3: {}",
            show(reg)
        );
    }

    loop {
        let body = match wire::read_frame(&mut reader) {
            Ok(b) => b,
            Err(e) if e.kind() == io::ErrorKind::UnexpectedEof => return Ok(()),
            Err(e) => return Err(e),
        };
        let raw = match zlib_decompress(&body) {
            Ok(r) => r,
            Err(e) => {
                log!("gserver {id} undecodable frame ({e})");
                continue;
            }
        };
        for line in wire::lines(&raw) {
            if let Some(reply) = handle(line, id, peer, shared) {
                writer.write_all(&write_zlib_frame(&reply)?)?;
            }
        }
    }
}

/// Handle one message; the reply line (with its line feed), if any.
fn handle(line: &[u8], id: u64, peer: &str, shared: &Shared) -> Option<Vec<u8>> {
    let pid = line[0].wrapping_sub(32) as usize;
    let mut p = Fields::new(&line[1..]);
    match pid {
        svo::NEWSERVER => {
            let mut f: Vec<Vec<u8>> = Vec::with_capacity(8);
            for _ in 0..8 {
                // The last field (local IP) may be missing on some gservers.
                f.push(p.gstr().unwrap_or_default().to_vec());
            }
            let [name, desc, lang, ver, url, sent_ip, port, _local_ip]: [Vec<u8>; 8] =
                f.try_into().ok()?;
            let ip = match shared.config.gserver_ip {
                crate::config::GserverIp::Sent
                    if !sent_ip.is_empty() && !sent_ip.eq_ignore_ascii_case(b"AUTO") =>
                {
                    sent_ip
                }
                _ => peer.as_bytes().to_vec(),
            };
            log!(
                "gserver {id} newserver {} port {} version {} ip {}",
                show(&name),
                show(&port),
                show(&ver),
                show(&ip)
            );
            shared.servers.update(id, |e| {
                e.name = Some(name);
                e.description = desc;
                e.language = lang;
                e.version = ver;
                e.url = url;
                e.ip = ip;
                e.port = port;
            });
            None
        }
        svo::SERVERHQLEVEL => {
            let level = p.gchar()?;
            shared.servers.update(id, |e| e.hq_level = level);
            log!("gserver {id} hq level {level}");
            None
        }
        svo::SETPLYR => {
            shared.servers.update(id, |e| e.players.clear());
            None
        }
        svo::PLYRADD => {
            let player = p.gshort()?;
            let kind = p.gchar().unwrap_or(0);
            let now = shared.servers.update(id, |e| {
                e.players.insert(player);
                e.players.len()
            });
            log!(
                "gserver {id} player add {player} type {kind}, now {}",
                now.unwrap_or(0)
            );
            None
        }
        svo::PLYRREM => {
            let player = p.gshort()?;
            let now = shared.servers.update(id, |e| {
                e.players.remove(&player);
                e.players.len()
            });
            log!("gserver {id} player rem {player}, now {}", now.unwrap_or(0));
            None
        }
        svo::VERIACC2 => {
            let account = p.gstr()?;
            let password = p.gstr()?;
            let player = p.bytes(2)?;
            let kind = p.bytes(1)?;
            // beta4 appends a GSHORT length and an identity string.
            let identity = p
                .gshort()
                .map(|n| format!(", identity {n} bytes"))
                .unwrap_or_default();
            let err = shared.accounts.check(account, password);
            log!(
                "gserver {id} veriacc2 {} type {}{identity}: {}",
                show(account),
                kind[0].wrapping_sub(32),
                err.map_or("ok".into(), |e| format!("refused, {}", show(e)))
            );
            let mut out = vec![gchar(svi::VERIACC2)];
            put_gstr(&mut out, account);
            out.extend_from_slice(player);
            out.extend_from_slice(kind);
            out.extend_from_slice(err.unwrap_or(b"SUCCESS"));
            out.push(b'\n');
            Some(out)
        }
        // Keep-alive, pong and HQ password: nothing to answer.
        svo::SETIP | svo::PING | svo::SERVERHQPASS => None,
        svo::SENDTEXT => {
            log!("gserver {id} sendtext {}", show(p.rest()));
            None
        }
        _ => {
            log!("gserver {id} unhandled id {pid}: {}", show(p.rest()));
            None
        }
    }
}
