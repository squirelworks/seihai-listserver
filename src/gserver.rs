//! The gserver side: registration, the list entry, player counts and
//! account checks.
//!
//! A gserver first sends `SVO_REGISTERV3` as one uncompressed line, then
//! zlib frames (`u16be` length + zlib body of lines). The listserver
//! answers `VERIACC2` with `SVI_VERIACC2`, and `SERVERINFO` (a server warp
//! request for one player) with `SVI_SERVERINFO`. An enrolled link is sent
//! an empty ping (id 99) every `gserver_ping_secs`. The gserver's pong is
//! id 16 and is not answered, so the two cannot loop. The entry is dropped
//! when the link closes or stays silent past `gserver_timeout_secs`.
//!
//! A Seihai gserver may instead open with the encrypted link (Seihai's
//! `documentation/secure-login.md`, "Gserver to listserver link"): C1 with
//! the inner token `SVLINK01`, S1 back, then the same classic link inside
//! ChaCha20-Poly1305 records, so players' passwords in `VERIACC2` never
//! cross the wire in the clear.
//!
//! Each link has an outbox ([`crate::links`]), so other links can push to
//! it: cross-server PMs, channel chat and player counts. Profiles, global
//! guilds, the PM server and player lists, channels and buddies are in
//! `docs/design/gserver-text-profiles-guilds.md`.
//!
//! When `gservers` is set, a link from any other address is dropped, and
//! `NEWSERVER` (and account checks) are ignored until `SERVERHQPASS`
//! matches that address's password. Broadcasts are withheld until then too.
//! An empty list keeps the open behaviour.

use crate::accounts::GuessKind;
use crate::config::Config;
use crate::links::{Outbox, SealedRead, Sink};
use crate::server::Shared;
use crate::state::{hq_tag, Player};
use crate::text;
use crate::wire::{self, gchar, put_gstr, show, Fields};
use seihai_core::protocol::seclogin::{self, ClientHello};
use seihai_core::protocol::zlib_decompress;
use std::collections::BTreeMap;
use std::io::{self, BufRead, BufReader, Read, Write};
use std::net::{IpAddr, TcpStream};
use std::time::{Duration, Instant};

/// Gserver to listserver ids.
pub mod svo {
    pub const SETIP: usize = 5;
    pub const VERIGUILD: usize = 9;
    pub const GETPROF: usize = 12;
    pub const SETPROF: usize = 13;
    pub const SETPLYR: usize = 7;
    pub const PLYRADD: usize = 14;
    pub const PLYRREM: usize = 15;
    pub const PING: usize = 16;
    pub const VERIACC2: usize = 17;
    pub const NEWSERVER: usize = 22;
    pub const SERVERHQPASS: usize = 23;
    pub const SERVERHQLEVEL: usize = 24;
    pub const SERVERINFO: usize = 25;
    pub const REQUESTLIST: usize = 26;
    pub const REQUESTBUDDIES: usize = 28;
    pub const PMPLAYER: usize = 29;
    pub const REGISTERV3: usize = 30;
    pub const SENDTEXT: usize = 31;
}

/// Listserver to gserver ids.
pub mod svi {
    pub const VERIGUILD: usize = 1;
    pub const PROFILE: usize = 7;
    pub const VERIACC2: usize = 11;
    pub const SERVERINFO: usize = 18;
    pub const REQUESTTEXT: usize = 19;
    pub const SENDTEXT: usize = 20;
    pub const PMPLAYER: usize = 29;
    pub const ASSIGNPCID: usize = 30;
    /// Empty liveness check. The gserver answers with [`svo::PING`] and
    /// nothing else; this id is never sent in reply to that pong.
    pub const PING: usize = 99;
}

/// Cross-server PMs one link may send in a second; more are dropped.
const PM_PER_SEC: u32 = 20;

/// The `PLYRADD` prop ids read for the player's account and nickname.
const PROP_NICKNAME: usize = 0;
const PROP_ACCOUNTNAME: usize = 34;

/// The longest `REGISTERV3` line taken.
const MAX_REGISTER: u64 = 1024;

pub fn serve(stream: TcpStream, id: u64, shared: &Shared) {
    let peer_ip = stream.peer_addr().ok().map(|a| a.ip());
    let peer = peer_ip.map(|ip| ip.to_string()).unwrap_or_default();
    let Some(auth) = auth_for(&shared.config(), peer_ip) else {
        log!("gserver {id} refused: {peer} is not in the gserver allow-list");
        return;
    };
    log!("gserver {id} connected from {peer}");
    shared.servers.insert(id);
    let result = run(stream, id, &peer, shared, auth);
    shared.links.remove(id);
    shared
        .channels
        .lock()
        .unwrap_or_else(|e| e.into_inner())
        .retain(|(link, _), _| *link != id);
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

/// Read one line (with its line feed) of at most [`MAX_REGISTER`] bytes.
fn first_line<R: BufRead>(r: &mut R) -> io::Result<Vec<u8>> {
    let mut line = Vec::new();
    r.take(MAX_REGISTER).read_until(b'\n', &mut line)?;
    if !line.ends_with(b"\n") || line.len() < 2 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "no REGISTERV3 line",
        ));
    }
    Ok(line)
}

fn run(stream: TcpStream, id: u64, peer: &str, shared: &Shared, mut auth: Auth) -> io::Result<()> {
    stream.set_read_timeout(Some(shared.config().gserver_timeout()))?;
    let mut writer = stream.try_clone()?;
    let mut reader = BufReader::new(stream);
    let line = first_line(&mut reader)?;
    if !line.starts_with(seclogin::TOKEN.as_bytes()) {
        if shared.config().require_secure_gserver_link {
            log!("gserver {id} plain link refused (require_secure_gserver_link)");
            return Ok(());
        }
        let outbox = Outbox::start(id, Sink::Plain(writer))?;
        return session(&mut reader, line, id, peer, shared, &mut auth, outbox);
    }
    // The encrypted link: C1 here, S1 back, then records both ways.
    let hello = match ClientHello::parse(&line, 0) {
        Some(Ok(h)) if h.inner == *seclogin::LINK_TOKEN.as_bytes() => h,
        _ => {
            log!("gserver {id} bad encrypted-link hello: {}", show(&line));
            return Ok(());
        }
    };
    let (mut s1, opener) = {
        let guard = shared.identity();
        let Some(identity) = guard.as_ref() else {
            log!("gserver {id} encrypted link refused: secure_login_key is empty");
            return Ok(());
        };
        hello
            .respond(identity)
            .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e.to_string()))?
    };
    s1.push(b'\n');
    writer.write_all(&s1)?;
    writer.flush()?;
    log!(
        "gserver {id} encrypted link (SEI00001 {})",
        seclogin::LINK_TOKEN
    );
    let (send, recv) = opener.into_channel().split();
    let outbox = Outbox::start(id, Sink::Sealed(writer, send))?;
    let mut inner = BufReader::new(SealedRead::new(reader, recv));
    let line = first_line(&mut inner)?;
    session(&mut inner, line, id, peer, shared, &mut auth, outbox)
}

/// The classic link from its first line (`reg`, the `REGISTERV3` line) on:
/// messages read from `link` (plain, or opened from the encrypted
/// channel), answers queued to `outbox`.
fn session<R: Read>(
    link: &mut BufReader<R>,
    reg: Vec<u8>,
    id: u64,
    peer: &str,
    shared: &Shared,
    auth: &mut Auth,
    outbox: Outbox,
) -> io::Result<()> {
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
    if auth.ok {
        shared.links.add(id, outbox.clone());
    }
    let mut pm = PmRate::default();

    loop {
        let body = match wire::read_frame(link) {
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
            let was_authenticated = auth.ok;
            let step = handle(line, id, peer, shared, auth, &mut pm);
            if !was_authenticated && auth.ok {
                shared.links.add(id, outbox.clone());
            }
            match step {
                Step::Quiet => {}
                Step::Reply(reply) => {
                    outbox.send(reply);
                }
                Step::Close => return Ok(()),
            }
        }
    }
}

/// A link's cross-server PM budget: [`PM_PER_SEC`] in each second.
#[derive(Default)]
struct PmRate {
    since: Option<Instant>,
    sent: u32,
}

impl PmRate {
    fn allow(&mut self, now: Instant) -> bool {
        match self.since {
            Some(t) if now.duration_since(t) < Duration::from_secs(1) => {}
            _ => {
                self.since = Some(now);
                self.sent = 0;
            }
        }
        self.sent += 1;
        self.sent <= PM_PER_SEC
    }
}

/// What one gserver message asks the link to do.
enum Step {
    Quiet,
    Reply(Vec<u8>),
    Close,
}

/// Whether this link may change the list or check accounts.
///
/// `passwords` is `None` when `gservers` is empty (any link may register).
/// Otherwise it holds the HQ passwords configured for this address, and
/// `ok` stays false until `SERVERHQPASS` matches one of them.
struct Auth {
    passwords: Option<Vec<Vec<u8>>>,
    ok: bool,
}

impl Auth {
    fn open() -> Self {
        Self {
            passwords: None,
            ok: true,
        }
    }

    fn waiting(passwords: Vec<Vec<u8>>) -> Self {
        Self {
            passwords: Some(passwords),
            ok: false,
        }
    }
}

/// `None` drops the link. An empty allow-list is open for every address.
fn auth_for(cfg: &Config, peer: Option<IpAddr>) -> Option<Auth> {
    if cfg.gservers.is_empty() {
        return Some(Auth::open());
    }
    let peer = peer?;
    let passwords: Vec<Vec<u8>> = cfg
        .gservers
        .iter()
        .filter(|g| g.ip.parse::<IpAddr>().ok() == Some(peer))
        .map(|g| g.hq_password.as_bytes().to_vec())
        .collect();
    if passwords.is_empty() {
        None
    } else {
        Some(Auth::waiting(passwords))
    }
}

/// `true` when `payload` matches a configured HQ password. A mismatch
/// leaves `auth` unchanged.
fn accept_password(auth: &mut Auth, payload: &[u8]) -> bool {
    let Some(passwords) = &auth.passwords else {
        return true;
    };
    if matches_any(passwords, payload) {
        auth.ok = true;
        true
    } else {
        false
    }
}

fn matches_any(passwords: &[Vec<u8>], payload: &[u8]) -> bool {
    let mut ok = false;
    for password in passwords {
        ok |= bytes_eq(password, payload);
    }
    ok
}

fn bytes_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    let mut diff = 0u8;
    for (x, y) in a.iter().zip(b.iter()) {
        diff |= x ^ y;
    }
    diff == 0
}

/// Handle one message.
fn handle(
    line: &[u8],
    id: u64,
    peer: &str,
    shared: &Shared,
    auth: &mut Auth,
    pm: &mut PmRate,
) -> Step {
    let pid = line[0].wrapping_sub(32) as usize;
    let mut p = Fields::new(&line[1..]);
    // Account checks and the list entry stay closed until the HQ password
    // matches. SETIP and PING carry no list state.
    if !auth.ok && !matches!(pid, svo::SERVERHQPASS | svo::SETIP | svo::PING) {
        log!("gserver {id} ignored id {pid}: hq password not accepted yet");
        return Step::Quiet;
    }
    match pid {
        svo::NEWSERVER => {
            let mut f: Vec<Vec<u8>> = Vec::with_capacity(8);
            for _ in 0..8 {
                // The last field (local IP) may be missing on some gservers.
                f.push(p.gstr().unwrap_or_default().to_vec());
            }
            let Ok([name, desc, lang, ver, url, sent_ip, port, _local_ip]): Result<
                [Vec<u8>; 8],
                _,
            > = f.try_into() else {
                return Step::Quiet;
            };
            let ip = match shared.config().gserver_ip {
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
            let first = shared
                .servers
                .update(id, |e| e.name.is_none())
                .unwrap_or(false);
            shared.servers.update(id, |e| {
                e.name = Some(name);
                e.description = desc;
                e.language = lang;
                e.version = ver;
                e.url = url;
                e.ip = ip;
                e.port = port;
            });
            if first {
                // Tell the new gserver how many players the others have;
                // later changes come from `push_counts`.
                for (_, name, _, n) in shared.servers.public(Some(id)) {
                    shared.links.send(id, count_text(&name, n as i64));
                }
            }
            Step::Quiet
        }
        svo::SERVERHQLEVEL => {
            let Some(level) = p.gchar() else {
                return Step::Quiet;
            };
            shared.servers.update(id, |e| e.hq_level = level);
            log!("gserver {id} hq level {level}");
            Step::Quiet
        }
        svo::SETPLYR => {
            shared.servers.update(id, |e| e.players.clear());
            shared
                .channels
                .lock()
                .unwrap_or_else(|e| e.into_inner())
                .retain(|(link, _), _| *link != id);
            Step::Quiet
        }
        svo::PLYRADD => {
            let Some(player) = p.gshort() else {
                return Step::Quiet;
            };
            let kind = p.gchar().unwrap_or(0);
            let mut who = Player {
                kind,
                ..Player::default()
            };
            // ACCOUNTNAME and NICKNAME come first; stop at any other prop.
            while let Some(prop) = p.gchar() {
                let field = match prop {
                    PROP_ACCOUNTNAME => &mut who.account,
                    PROP_NICKNAME => &mut who.nickname,
                    _ => break,
                };
                let Some(v) = p.gstr() else { break };
                *field = v.to_vec();
            }
            log!(
                "gserver {id} player add {player} type {kind} {}",
                show(&who.account)
            );
            let now = shared.servers.update(id, |e| {
                e.players.insert(player, who);
                e.players.len()
            });
            log!("gserver {id} now {} player(s)", now.unwrap_or(0));
            Step::Quiet
        }
        svo::PLYRREM => {
            let Some(player) = p.gshort() else {
                return Step::Quiet;
            };
            let now = shared.servers.update(id, |e| {
                e.players.remove(&player);
                e.players.len()
            });
            shared
                .channels
                .lock()
                .unwrap_or_else(|e| e.into_inner())
                .remove(&(id, player));
            log!("gserver {id} player rem {player}, now {}", now.unwrap_or(0));
            Step::Quiet
        }
        svo::VERIACC2 => {
            let Some(account) = p.gstr() else {
                return Step::Quiet;
            };
            let Some(password) = p.gstr() else {
                return Step::Quiet;
            };
            let Some(player) = p.bytes(2) else {
                return Step::Quiet;
            };
            let Some(kind) = p.bytes(1) else {
                return Step::Quiet;
            };
            // GServer-v2 (beta4 on) appends a GSHORT length and the
            // client's machine list, unchanged.
            let identity = p.gshort().map(|n| {
                let rest = p.rest();
                &rest[..rest.len().min(n as usize)]
            });
            let err = shared.check_login(GuessKind::Veriacc, peer.parse().ok(), account, password);
            // A PC id only for a login that got in: a refused guess must
            // not grow the table.
            let pcid = match (err, identity) {
                (None, Some(identity)) => pcid_for(shared, id, identity),
                _ => None,
            };
            log!(
                "gserver {id} veriacc2 {} type {}{}{}: {}",
                show(account),
                kind[0].wrapping_sub(32),
                identity.map_or(String::new(), |i| format!(", identity {} bytes", i.len())),
                pcid.map_or(String::new(), |n| format!(", pc id {n}")),
                err.map_or("ok".into(), |e| format!("refused, {}", show(e)))
            );
            let mut out = Vec::new();
            // GServer-v2 ignores ASSIGNPCID for a player who is already
            // loaded, and SUCCESS loads the player, so the PC id goes first.
            if let Some(n) = pcid {
                out.push(gchar(svi::ASSIGNPCID));
                out.extend_from_slice(player);
                out.extend_from_slice(kind);
                put_gstr(&mut out, n.to_string().as_bytes());
                out.push(b'\n');
            }
            out.push(gchar(svi::VERIACC2));
            put_gstr(&mut out, account);
            out.extend_from_slice(player);
            out.extend_from_slice(kind);
            out.extend_from_slice(err.unwrap_or(b"SUCCESS"));
            out.push(b'\n');
            Step::Reply(out)
        }
        // The password is the raw rest of the line, not a GSTRING. Gservers
        // send it before NEWSERVER; a later repeat must still match.
        svo::SERVERHQPASS => {
            if auth.passwords.is_none() {
                return Step::Quiet;
            }
            let was_ok = auth.ok;
            if accept_password(auth, p.rest()) {
                if !was_ok {
                    log!("gserver {id} hq password accepted");
                }
                Step::Quiet
            } else {
                log!("gserver {id} hq password refused");
                Step::Close
            }
        }
        svo::SERVERINFO => {
            let Some(player) = p.bytes(2) else {
                return Step::Quiet;
            };
            let wanted = p.rest();
            let Some((name, ip, port)) = shared.servers.warp_target(wanted) else {
                log!("gserver {id} serverinfo {}: no such server", show(wanted));
                return Step::Quiet;
            };
            log!(
                "gserver {id} serverinfo {}: {} {}",
                show(&name),
                show(&ip),
                show(&port)
            );
            let mut out = vec![gchar(svi::SERVERINFO)];
            out.extend_from_slice(player);
            out.extend_from_slice(&warp_text(&name, &ip, &port));
            out.push(b'\n');
            Step::Reply(out)
        }
        // SETIP is the gserver's own keep-alive. Id 16 is its pong to
        // our ping (99). Neither is answered: a 99 in reply to 16 would loop.
        svo::SETIP | svo::PING => Step::Quiet,
        svo::SENDTEXT => {
            log!("gserver {id} sendtext {}", show(p.rest()));
            Step::Quiet
        }
        svo::VERIGUILD => veriguild(&mut p, id, shared),
        svo::GETPROF => getprof(&mut p, id, shared),
        svo::SETPROF => setprof(&mut p, id, shared),
        svo::REQUESTLIST => {
            let Some(player) = p.bytes(2) else {
                return Step::Quiet;
            };
            requestlist(player, p.rest(), id, shared)
        }
        svo::REQUESTBUDDIES => {
            let Some(player) = p.bytes(2) else {
                return Step::Quiet;
            };
            requestbuddies(player, p.rest(), id, shared)
        }
        svo::PMPLAYER => {
            if p.bytes(2).is_none() {
                return Step::Quiet;
            }
            if !pm.allow(Instant::now()) {
                log!("gserver {id} pmplayer over {PM_PER_SEC} a second, dropped");
                return Step::Quiet;
            }
            pmplayer(p.rest(), id, shared);
            Step::Quiet
        }
        _ => {
            log!("gserver {id} unhandled id {pid}: {}", show(p.rest()));
            Step::Quiet
        }
    }
}

/// One message line: the id, `body`, then a line feed.
fn message(id: usize, body: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(body.len() + 2);
    out.push(gchar(id));
    out.extend_from_slice(body);
    out.push(b'\n');
    out
}

/// `REQUESTTEXT` (19) for one player: their raw GSHORT id, then `text`.
fn request_text(player: &[u8], text: &[u8]) -> Vec<u8> {
    message(svi::REQUESTTEXT, &[player, text].concat())
}

/// `VERIGUILD` (9): may the player wear the guild's tag? Answered only
/// when they may (design §2).
fn veriguild(p: &mut Fields, id: u64, shared: &Shared) -> Step {
    let (Some(player), Some(account), Some(nick), Some(guild)) =
        (p.bytes(2), p.gstr(), p.gstr(), p.gstr())
    else {
        return Step::Quiet;
    };
    let cfg = shared.config();
    let member = cfg.guilds.iter().any(|(g, members)| {
        g.as_bytes().eq_ignore_ascii_case(guild)
            && members
                .iter()
                .any(|m| m.as_bytes().eq_ignore_ascii_case(account))
    });
    log!(
        "gserver {id} veriguild {} guild {}: {}",
        show(account),
        show(guild),
        if member { "ok" } else { "not a member" }
    );
    if !member {
        return Step::Quiet;
    }
    let mut body = player.to_vec();
    put_gstr(&mut body, &[nick, b" (", guild, b")"].concat());
    Step::Reply(message(svi::VERIGUILD, &body))
}

/// `GETPROF` (12): answer `PROFILE` (7), with empty fields for an
/// account that never set one (design §1).
fn getprof(p: &mut Fields, id: u64, shared: &Shared) -> Step {
    let Some(requester) = p.bytes(2) else {
        return Step::Quiet;
    };
    // The client's own packet id, passed through by the gserver.
    if p.bytes(1).is_none() {
        return Step::Quiet;
    }
    let target = p.rest();
    let profile = shared.profiles.get(target).unwrap_or_default();
    log!("gserver {id} getprof {}", show(target));
    let mut body = requester.to_vec();
    put_gstr(&mut body, target);
    for f in &profile {
        put_gstr(&mut body, f);
    }
    Step::Reply(message(svi::PROFILE, &body))
}

/// `SETPROF` (13): store the nine fields, only for a player on this link.
fn setprof(p: &mut Fields, id: u64, shared: &Shared) -> Step {
    if p.bytes(1).is_none() {
        return Step::Quiet;
    }
    let Some(account) = p.gstr() else {
        return Step::Quiet;
    };
    let mut profile: crate::profiles::Profile = Default::default();
    for f in profile.iter_mut() {
        *f = p.gstr().unwrap_or_default().to_vec();
    }
    if player_on(shared, id, account).is_none() {
        log!(
            "gserver {id} setprof {} dropped: not a player on this server",
            show(account)
        );
        return Step::Quiet;
    }
    match shared.profiles.set(account, profile) {
        Ok(()) => log!("gserver {id} setprof {}", show(account)),
        Err(e) => log!("gserver {id} setprof {}: not saved ({e})", show(account)),
    }
    Step::Quiet
}

/// The player id on link `id` whose account is `account` (ASCII case
/// ignored).
fn player_on(shared: &Shared, id: u64, account: &[u8]) -> Option<u16> {
    let entry = shared.servers.get(id)?;
    entry
        .players
        .iter()
        .find(|(_, pl)| !pl.account.is_empty() && pl.account.eq_ignore_ascii_case(account))
        .map(|(&n, _)| n)
}

/// The account of `player` (a raw GSHORT) on link `id`.
fn account_of(shared: &Shared, id: u64, player: &[u8]) -> Option<Vec<u8>> {
    let n = Fields::new(player).gshort()?;
    let pl = shared.servers.get(id)?.players.get(&n)?.clone();
    (!pl.account.is_empty()).then_some(pl.account)
}

/// `REQUESTLIST` (26): a player's text request (design §3, §5, §6).
fn requestlist(player: &[u8], raw: &[u8], id: u64, shared: &Shared) -> Step {
    let f = text::split(raw);
    let field = |n: usize| f.get(n).map(Vec::as_slice).unwrap_or_default();
    let (weapon, kind, option) = (field(0), field(1), field(2));
    log!("gserver {id} requestlist {}", show(raw));
    match kind {
        b"pmservers" => {
            let mut out = f.clone();
            out.extend(shared.servers.public(Some(id)).into_iter().map(|s| s.1));
            Step::Reply(request_text(player, &text::join(&out)))
        }
        b"pmguilds" => {
            let mut out = f.clone();
            out.extend(shared.config().guilds.keys().map(|g| g.as_bytes().to_vec()));
            Step::Reply(request_text(player, &text::join(&out)))
        }
        b"pmserverplayers" => {
            let mut out = vec![weapon.to_vec(), kind.to_vec(), option.to_vec()];
            let server = shared
                .servers
                .public(None)
                .into_iter()
                .find(|s| s.1.eq_ignore_ascii_case(option));
            if let Some(entry) = server.and_then(|s| shared.servers.get(s.0)) {
                for pl in entry.players.values().filter(|pl| !pl.account.is_empty()) {
                    out.push(text::join(&[&pl.account, &pl.nickname]));
                }
            }
            Step::Reply(request_text(player, &text::join(&out)))
        }
        b"lister" => match option {
            // GServer-v2 turns the client's `simplelist` into this.
            b"simplelist" | b"simpleserverlist" => {
                let mut out = vec![weapon.to_vec(), kind.to_vec(), b"simpleserverlist".to_vec()];
                for (_, name, level, n) in shared.servers.public(None) {
                    let tagged = [hq_tag(level), &name].concat();
                    out.push(text::join(&[&name[..], &tagged, n.to_string().as_bytes()]));
                }
                Step::Reply(request_text(player, &text::join(&out)))
            }
            b"verifybuddies" | b"addbuddy" | b"deletebuddy" => {
                buddies(player, weapon, option, &f[3.min(f.len())..], id, shared)
            }
            _ => Step::Quiet,
        },
        b"irc" => irc(player, &f, id, shared),
        _ => Step::Quiet,
    }
}

/// `lister` buddy options (`crate::buddies` says which parts are seen on
/// the wire and which are chosen here).
fn buddies(
    player: &[u8],
    weapon: &[u8],
    option: &[u8],
    args: &[Vec<u8>],
    id: u64,
    shared: &Shared,
) -> Step {
    let Some(account) = account_of(shared, id, player) else {
        log!("gserver {id} {}: player has no account", show(option));
        return Step::Quiet;
    };
    let changed = match option {
        b"addbuddy" => shared.buddies.add(&account, args),
        b"deletebuddy" => shared.buddies.remove(&account, args),
        _ => {
            // verifybuddies,<load from server 0/1>,<CRC-32 of the list>
            let load = args.first().is_some_and(|a| a.as_slice() == b"1");
            let theirs: Option<u32> = args
                .get(1)
                .and_then(|c| std::str::from_utf8(c).ok())
                .and_then(|c| c.trim().parse().ok());
            let list = shared.buddies.list(&account);
            let ours = crate::buddies::list_crc(&list);
            log!(
                "gserver {id} verifybuddies {} load {load} crc {theirs:?} ours {ours}",
                show(&account)
            );
            if !load || theirs == Some(ours) {
                return Step::Quiet;
            }
            return Step::Reply(request_text(player, &buddylist(weapon, &list)));
        }
    };
    match changed {
        Ok(list) => log!(
            "gserver {id} {} {}: {} buddies",
            show(option),
            show(&account),
            list.len()
        ),
        Err(e) => log!("gserver {id} {}: not saved ({e})", show(option)),
    }
    Step::Quiet
}

/// `<weapon>,lister,buddylist,acc1,acc2,…`.
fn buddylist(weapon: &[u8], list: &[Vec<u8>]) -> Vec<u8> {
    let mut out = vec![weapon.to_vec(), b"lister".to_vec(), b"buddylist".to_vec()];
    out.extend(list.iter().cloned());
    text::join(&out)
}

/// `REQUESTBUDDIES` (28): `account,weapon,type` answered with the
/// account's buddy list. GServer-v2 never sends it; the layout is the open
/// listserver's.
fn requestbuddies(player: &[u8], raw: &[u8], id: u64, shared: &Shared) -> Step {
    let f = text::split(raw);
    let (Some(account), Some(weapon)) = (f.first(), f.get(1)) else {
        return Step::Quiet;
    };
    log!("gserver {id} requestbuddies {}", show(account));
    let list = shared.buddies.list(account);
    Step::Reply(request_text(player, &buddylist(weapon, &list)))
}

/// `irc` join, part and privmsg (design §5).
fn irc(player: &[u8], f: &[Vec<u8>], id: u64, shared: &Shared) -> Step {
    let field = |n: usize| f.get(n).map(Vec::as_slice).unwrap_or_default();
    let action = field(2);
    match action {
        b"join" | b"part" => {
            let mut chan = field(3).to_vec();
            if chan.is_empty() {
                return Step::Quiet;
            }
            if chan[0] != b'#' {
                chan.insert(0, b'#');
            }
            if let Some(n) = Fields::new(player).gshort() {
                let mut channels = shared.channels.lock().unwrap_or_else(|e| e.into_inner());
                let set = channels.entry((id, n)).or_default();
                if action == b"join" {
                    set.insert(chan.clone());
                } else {
                    set.remove(&chan);
                    if set.is_empty() {
                        channels.remove(&(id, n));
                    }
                }
            }
            let out = text::join(&[&b"GraalEngine"[..], b"irc", action, &chan[..]]);
            Step::Reply(request_text(player, &out))
        }
        b"privmsg" if f.len() >= 6 => {
            let out = text::join(&f[..6]);
            shared.links.send_others(id, &message(svi::SENDTEXT, &out));
            Step::Quiet
        }
        _ => Step::Quiet,
    }
}

/// `PMPLAYER` (29): pass a PM to the named gserver, with field 0 changed to
/// the sender's server so the reply finds its way back (design §4).
fn pmplayer(raw: &[u8], id: u64, shared: &Shared) {
    let mut f = text::split(raw);
    if f.len() < 7 {
        log!("gserver {id} pmplayer too short: {}", show(raw));
        return;
    }
    let Some(from) = shared.servers.get(id).and_then(|e| e.name) else {
        return;
    };
    let target = shared.servers.id_by_name(&f[0]);
    let to_account = f[5].clone();
    let Some(target) = target.filter(|&t| player_on(shared, t, &to_account).is_some()) else {
        log!(
            "gserver {id} pmplayer to {} on {}: no such player",
            show(&to_account),
            show(&f[0])
        );
        return;
    };
    f[0] = from;
    shared
        .links
        .send(target, message(svi::PMPLAYER, &text::join(&f)));
}

/// `Listserver,Modify,Server,<name>,players=<n>` as a `SENDTEXT` (20).
fn count_text(name: &[u8], players: i64) -> Vec<u8> {
    let n = format!("players={players}");
    message(
        svi::SENDTEXT,
        &text::join(&[&b"Listserver"[..], b"Modify", b"Server", name, n.as_bytes()]),
    )
}

/// The player counts other gservers were last told, by link id.
#[derive(Default)]
pub struct Counts {
    told: BTreeMap<u64, (Vec<u8>, usize)>,
}

/// Tell every other gserver about player counts that changed, servers
/// that appeared and servers that went (`players=-1`). Run about once a
/// second, so changes are pushed at most once a second (design §5).
pub fn push_counts(shared: &Shared, counts: &mut Counts) {
    let now: BTreeMap<u64, (Vec<u8>, usize)> = shared
        .servers
        .public(None)
        .into_iter()
        .map(|(id, name, _, n)| (id, (name, n)))
        .collect();
    for (id, (name, _)) in &counts.told {
        let same_name = now.get(id).is_some_and(|(n, _)| n == name);
        if !same_name {
            shared.links.send_others(*id, &count_text(name, -1));
        }
    }
    for (id, (name, n)) in &now {
        if counts.told.get(id) != Some(&(name.clone(), *n)) {
            shared.links.send_others(*id, &count_text(name, *n as i64));
        }
    }
    counts.told = now;
}

/// One empty ping (id 99) to every enrolled gserver. A link still waiting
/// on its HQ password is not enrolled, so it is not pinged. The gserver's
/// pong is not what schedules the next one.
pub fn push_pings(shared: &Shared) {
    if shared.config().gserver_ping_secs == 0 {
        return;
    }
    shared.links.send_all(&message(svi::PING, b""));
}

/// The PC id for a login's machine list, from the machines table. `None`
/// when PC ids are off, the list has no usable digest (old clients), or
/// the table cannot be written.
fn pcid_for(shared: &Shared, id: u64, identity: &[u8]) -> Option<u64> {
    let machines = shared.machines.as_ref()?;
    let cfg = shared.config();
    let keys = crate::machines::keys(identity, &cfg.pcid_ignore_hashes);
    match machines.assign(&keys, cfg.pcid_match_hashes) {
        Ok(n) => n,
        Err(e) => {
            log!("gserver {id} no pc id: {e}");
            None
        }
    }
}

/// The `SVI_SERVERINFO` text after the player id: `0,name,ip,port`. A
/// name holding a comma or a quote is quoted, with inner quotes doubled.
fn warp_text(name: &[u8], ip: &[u8], port: &[u8]) -> Vec<u8> {
    let mut out = b"0,".to_vec();
    if name.iter().any(|&b| b == b',' || b == b'"') {
        out.push(b'"');
        for &b in name {
            if b == b'"' {
                out.push(b'"');
            }
            out.push(b);
        }
        out.push(b'"');
    } else {
        out.extend_from_slice(name);
    }
    out.push(b',');
    out.extend_from_slice(ip);
    out.push(b',');
    out.extend_from_slice(port);
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::Ipv6Addr;

    fn cfg(text: &str) -> Config {
        Config::parse(text).unwrap()
    }

    #[test]
    fn empty_allow_list_is_open() {
        let auth = auth_for(&cfg(""), Some(IpAddr::from([127, 0, 0, 1]))).unwrap();
        assert!(auth.ok);
        assert!(auth.passwords.is_none());
    }

    #[test]
    fn other_loopback_is_refused_and_either_password_matches() {
        let c = cfg(r#"
            gservers = [
                { ip = "127.0.0.1", hq_password = "one" },
                { ip = "127.0.0.1", hq_password = "two" },
            ]
            "#);
        assert!(auth_for(&c, Some(IpAddr::V6(Ipv6Addr::LOCALHOST))).is_none());
        assert!(auth_for(&c, None).is_none());
        let mut auth = auth_for(&c, Some(IpAddr::from([127, 0, 0, 1]))).unwrap();
        assert!(!auth.ok);
        assert!(!accept_password(&mut auth, b"no"));
        assert!(!auth.ok);
        assert!(accept_password(&mut auth, b"two"));
        assert!(auth.ok);
        assert!(accept_password(&mut auth, b"one"));
        assert!(!accept_password(&mut auth, b"two-no"));
        assert!(
            auth.ok,
            "the helper leaves the flag; the link handler closes"
        );
    }

    #[test]
    fn warp_text_quotes_only_when_needed() {
        assert_eq!(
            warp_text(b"Lab Server", b"127.0.0.1", b"14805"),
            b"0,Lab Server,127.0.0.1,14805"
        );
        assert_eq!(
            warp_text(b"A, \"B\"", b"127.0.0.1", b"14802"),
            b"0,\"A, \"\"B\"\"\",127.0.0.1,14802"
        );
    }
}
