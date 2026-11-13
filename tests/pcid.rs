//! PC ids: a fake gserver sends `VERIACC2` with the machine lists the
//! graal-client-repro rebuilds send (made-up MD5 digests of SquirrelOS,
//! SquirrelNIC and SquirrelBIOS strings), and checks that `SVI_ASSIGNPCID`
//! (30) comes before `SVI_VERIACC2` (11), in the shape GServer-v2 reads:
//! GSHORT player id, GCHAR player type, GCHAR-length decimal text.

use seihai_core::protocol::{zlib_compress, zlib_decompress};
use seihai_listserver::{Config, Running};
use std::io::{ErrorKind, Read, Write};
use std::net::TcpStream;
use std::path::Path;
use std::time::Duration;

const WIN_512: &str = "win,c2482de76c59ac3c4ce0b7e065a2d09c,3c639304427ab3b3c6439a39c31c9df5,217767adb74e936b5ee209ed65ecc400,\"6.2 9200 \"";
const WIN_420: &str = "win,c2482de76c59ac3c4ce0b7e065a2d09c,3c639304427ab3b3c6439a39c31c9df5,217767adb74e936b5ee209ed65ecc400";
const MAC_6004: &str = "mac,136e7764c5e302092c02953b69eebed8,65e5a8ee6e0d22852a2e92a64056765e,\"\",\"Darwin Kernel Version 10.8.0\"";

fn gchar(n: usize) -> u8 {
    (n + 32) as u8
}

fn gstr(s: &[u8]) -> Vec<u8> {
    [&[gchar(s.len())][..], s].concat()
}

fn gshort(n: usize) -> [u8; 2] {
    [gchar(n >> 7), gchar(n & 0x7F)]
}

fn frame(body: &[u8]) -> Vec<u8> {
    [&(body.len() as u16).to_be_bytes()[..], body].concat()
}

fn start(dir: &Path, accounts: bool, extra: impl FnOnce(&mut Config)) -> Running {
    let mut cfg = Config {
        gserver_port: 0,
        client_ports: vec![0],
        secure_login_key: dir.join("seihai-login.key"),
        machines: dir.join("machines.tsv"),
        ..Config::default()
    };
    if accounts {
        let path = dir.join("accounts.txt");
        seihai_listserver::accounts::add_account(&path, "acct", b"pw").unwrap();
        cfg.accounts = path;
    }
    extra(&mut cfg);
    seihai_listserver::start(cfg).unwrap()
}

/// `VERIACC2` for player `player` (type 10, an RC-or-client GChar) with
/// the identity `identity`, or none (a gserver older than beta4).
fn veriacc2(password: &[u8], player: usize, identity: Option<&str>) -> Vec<u8> {
    let mut m = vec![gchar(17)];
    m.extend(gstr(b"acct"));
    m.extend(gstr(password));
    m.extend(gshort(player));
    m.push(gchar(10));
    if let Some(i) = identity {
        m.extend(gshort(i.len()));
        m.extend_from_slice(i.as_bytes());
    }
    m
}

/// Register, send `msgs` in one frame, and return the reply lines.
fn gserver(run: &Running, msgs: &[Vec<u8>]) -> Vec<Vec<u8>> {
    let mut g = TcpStream::connect(run.gserver_addr).unwrap();
    g.write_all(&[&[gchar(30)][..], b"lab-test\n"].concat())
        .unwrap();
    let body: Vec<u8> = msgs.iter().flat_map(|m| [&m[..], b"\n"].concat()).collect();
    g.write_all(&frame(&zlib_compress(&body).unwrap())).unwrap();
    g.set_read_timeout(Some(Duration::from_millis(1000)))
        .unwrap();
    let mut data = Vec::new();
    let mut buf = [0u8; 65536];
    loop {
        match g.read(&mut buf) {
            Ok(0) => break,
            Ok(n) => data.extend_from_slice(&buf[..n]),
            Err(e) if matches!(e.kind(), ErrorKind::WouldBlock | ErrorKind::TimedOut) => break,
            Err(e) => panic!("{e}"),
        }
    }
    let mut out = Vec::new();
    let mut rest = &data[..];
    while rest.len() >= 2 {
        let n = u16::from_be_bytes([rest[0], rest[1]]) as usize;
        let raw = zlib_decompress(&rest[2..2 + n]).unwrap();
        out.extend(
            raw.split(|&b| b == b'\n')
                .filter(|l| !l.is_empty())
                .map(<[u8]>::to_vec),
        );
        rest = &rest[2 + n..];
    }
    out
}

fn ids(lines: &[Vec<u8>]) -> Vec<usize> {
    lines.iter().map(|l| (l[0] - 32) as usize).collect()
}

/// The player id and PC id of an `SVI_ASSIGNPCID` line, read the way
/// GServer-v2 reads it.
fn read_pcid(l: &[u8]) -> (usize, usize, i64) {
    assert_eq!(l[0], gchar(30));
    let player = (((l[1] - 32) as usize & 0x7F) << 7) | ((l[2] - 32) as usize & 0x7F);
    let kind = (l[3] - 32) as usize;
    let n = (l[4] - 32) as usize;
    assert_eq!(l.len(), 5 + n, "nothing after the PC id");
    let text = std::str::from_utf8(&l[5..]).unwrap();
    assert!(text.bytes().all(|b| b.is_ascii_digit()), "{text}");
    (player, kind, text.parse().unwrap())
}

#[test]
fn pcid_comes_before_success_and_follows_the_machine() {
    let dir = tempfile::tempdir().unwrap();
    let run = start(dir.path(), false, |_| {});
    let got = gserver(
        &run,
        &[
            veriacc2(b"pw", 300, Some(WIN_512)),
            veriacc2(b"pw", 301, Some(WIN_420)),
            veriacc2(b"pw", 302, Some(MAC_6004)),
            veriacc2(b"pw", 303, Some("win")),
            veriacc2(b"pw", 304, None),
            veriacc2(b"pw", 305, Some("")),
        ],
    );
    assert_eq!(
        ids(&got),
        vec![30, 11, 30, 11, 30, 11, 11, 11, 11],
        "{got:?}"
    );
    let (player, kind, first) = read_pcid(&got[0]);
    assert_eq!((player, kind), (300, 10), "the VERIACC2 player and type");
    assert_eq!(first, 1);
    assert!(got[1].ends_with(b"SUCCESS"));
    // 4.20r8 sends no OS version: the same machine.
    assert_eq!(read_pcid(&got[2]), (301, 10, first));
    // The Mac rebuild is another machine.
    assert_eq!(read_pcid(&got[4]).2, 2);

    // A restart keeps the table.
    drop(run);
    let run = start(dir.path(), false, |_| {});
    let got = gserver(&run, &[veriacc2(b"pw", 7, Some(WIN_512))]);
    assert_eq!(ids(&got), vec![30, 11]);
    assert_eq!(read_pcid(&got[0]), (7, 10, first));
}

#[test]
fn a_refused_login_gets_no_pcid_and_adds_no_machine() {
    let dir = tempfile::tempdir().unwrap();
    let run = start(dir.path(), true, |_| {});
    let got = gserver(&run, &[veriacc2(b"wrong", 1, Some(WIN_512))]);
    assert_eq!(ids(&got), vec![11]);
    assert!(!got[0].ends_with(b"SUCCESS"));
    assert_eq!(run.shared.machines.as_ref().unwrap().counts(), (0, 0));
    assert!(!dir.path().join("machines.tsv").exists());
    let got = gserver(&run, &[veriacc2(b"pw", 1, Some(WIN_512))]);
    assert_eq!(ids(&got), vec![30, 11]);
}

#[test]
fn empty_machines_setting_and_ignored_digests_send_no_pcid() {
    let dir = tempfile::tempdir().unwrap();
    let run = start(dir.path(), false, |c| c.machines = Default::default());
    assert!(run.shared.machines.is_none());
    let got = gserver(&run, &[veriacc2(b"pw", 1, Some(WIN_512))]);
    assert_eq!(ids(&got), vec![11]);

    let dir = tempfile::tempdir().unwrap();
    let run = start(dir.path(), false, |c| {
        c.pcid_ignore_hashes = vec![
            "c2482de76c59ac3c4ce0b7e065a2d09c".into(),
            "3c639304427ab3b3c6439a39c31c9df5".into(),
            "217767adb74e936b5ee209ed65ecc400".into(),
        ]
    });
    let got = gserver(&run, &[veriacc2(b"pw", 1, Some(WIN_512))]);
    assert_eq!(ids(&got), vec![11], "every digest ignored: no PC id");
}
