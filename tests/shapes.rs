//! The lab listserver's shape tests (`docs/reference/test_listserver.py`),
//! against the Rust listserver on free loopback ports.
//!
//! A fake gserver registers (REGISTERV3, NEWSERVER, HQ level gold, two
//! players added and one removed, a VERIACC2), then each client login shape
//! is checked: shape A (id 0 only), shape B (id 0 + id 1), gen 4 (id 4),
//! gen 5 (id 7, 2.22/2.31), the RC list (id 5) and refused logins.

use seihai_core::protocol::{
    bz2_compress, bz2_decompress, zlib_compress, zlib_decompress, Gen5, Gen5Comp,
};
use seihai_listserver::{Config, Running};
use std::io::{ErrorKind, Read, Write};
use std::net::{SocketAddr, TcpStream};
use std::path::PathBuf;
use std::time::{Duration, Instant};

fn gchar(n: usize) -> u8 {
    (n + 32) as u8
}

fn gstr(s: &[u8]) -> Vec<u8> {
    [&[gchar(s.len())][..], s].concat()
}

fn frame(body: &[u8]) -> Vec<u8> {
    [&(body.len() as u16).to_be_bytes()[..], body].concat()
}

/// Every frame that arrives until the link is quiet for `wait` or closes.
fn read_frames(s: &mut TcpStream, wait: Duration) -> (Vec<Vec<u8>>, bool) {
    s.set_read_timeout(Some(wait)).unwrap();
    let mut data = Vec::new();
    let mut buf = [0u8; 65536];
    let closed = loop {
        match s.read(&mut buf) {
            Ok(0) => break true,
            Ok(n) => data.extend_from_slice(&buf[..n]),
            Err(e)
                if matches!(
                    e.kind(),
                    ErrorKind::ConnectionReset | ErrorKind::ConnectionAborted
                ) =>
            {
                break true
            }
            Err(_) => break false,
        }
    };
    let mut out = Vec::new();
    let mut rest = &data[..];
    while rest.len() >= 2 {
        let n = u16::from_be_bytes([rest[0], rest[1]]) as usize;
        out.push(rest[2..2 + n].to_vec());
        rest = &rest[2 + n..];
    }
    (out, closed)
}

fn lines(raw: &[u8]) -> Vec<Vec<u8>> {
    raw.split(|&b| b == b'\n')
        .filter(|l| !l.is_empty())
        .map(<[u8]>::to_vec)
        .collect()
}

fn ids(lines: &[Vec<u8>]) -> Vec<usize> {
    lines.iter().map(|l| (l[0] - 32) as usize).collect()
}

/// The rows of an id 0 list: 8 fields each.
fn parse_list(l: &[u8]) -> Vec<Vec<Vec<u8>>> {
    let n = (l[1] - 32) as usize;
    let mut i = 2;
    let mut rows = Vec::new();
    for _ in 0..n {
        i += 1;
        let mut row = Vec::new();
        for _ in 0..8 {
            let len = (l[i] - 32) as usize;
            row.push(l[i + 1..i + 1 + len].to_vec());
            i += 1 + len;
        }
        rows.push(row);
    }
    rows
}

const WAIT: Duration = Duration::from_millis(1000);

struct Lab {
    run: Running,
    _dir: tempfile::TempDir,
}

impl Lab {
    fn start(accounts: &[(&str, &[u8])]) -> Self {
        Self::start_gservers(accounts, Vec::new())
    }

    fn start_gservers(
        accounts: &[(&str, &[u8])],
        gservers: Vec<seihai_listserver::config::GserverAllow>,
    ) -> Self {
        let dir = tempfile::tempdir().unwrap();
        let mut cfg = Config {
            gserver_port: 0,
            client_ports: vec![0, 0, 0],
            site_url: "http://127.0.0.1/site".into(),
            secure_login_key: dir.path().join("seihai-login.key"),
            gservers,
            ..Config::default()
        };
        if !accounts.is_empty() {
            let path: PathBuf = dir.path().join("accounts.txt");
            for (a, p) in accounts {
                seihai_listserver::accounts::add_account(&path, a, p).unwrap();
            }
            cfg.accounts = path;
        }
        Lab {
            run: seihai_listserver::start(cfg).unwrap(),
            _dir: dir,
        }
    }

    fn client(&self, i: usize) -> SocketAddr {
        self.run.client_addrs[i]
    }

    /// Register the test gserver; returns its link and its replies.
    fn fake_gserver(&self, veri_account: &[u8], veri_password: &[u8]) -> (TcpStream, Vec<Vec<u8>>) {
        let mut g = TcpStream::connect(self.run.gserver_addr).unwrap();
        g.write_all(&[&[gchar(30)][..], b"lab-test\n"].concat())
            .unwrap(); // SVO_REGISTERV3, uncompressed
        let fields: [&[u8]; 8] = [
            b"TestWorld",
            b"A test server",
            b"English",
            b"3.0.9",
            b"http://x/",
            b"AUTO",
            b"14802",
            b"",
        ];
        let newserver: Vec<u8> = [
            vec![gchar(22)],
            fields.iter().flat_map(|f| gstr(f)).collect(),
        ]
        .concat();
        let veri = [
            vec![gchar(17)],
            gstr(veri_account),
            gstr(veri_password),
            vec![gchar(0), gchar(2), gchar(5), gchar(0), gchar(3)],
            b"win".to_vec(),
        ]
        .concat();
        let msgs: Vec<Vec<u8>> = vec![
            vec![gchar(23)], // SERVERHQPASS
            newserver,
            vec![gchar(24), gchar(3)], // HQ level gold
            vec![gchar(7)],            // SETPLYR (clear)
            [&[gchar(14), gchar(0), gchar(2), gchar(0)][..], b"props"].concat(),
            [&[gchar(14), gchar(0), gchar(3), gchar(0)][..], b"props"].concat(),
            vec![gchar(15), gchar(0), gchar(3)],
            veri,
            [vec![gchar(5)], gstr(b"AUTO")].concat(), // SETIP keep-alive
            vec![gchar(16)],                          // PING
        ];
        let body: Vec<u8> = msgs.iter().flat_map(|m| [&m[..], b"\n"].concat()).collect();
        g.write_all(&frame(&zlib_compress(&body).unwrap())).unwrap();
        let (frames, _) = read_frames(&mut g, WAIT);
        let replies = frames
            .iter()
            .flat_map(|f| lines(&zlib_decompress(f).unwrap()))
            .collect();
        (g, replies)
    }
}

fn shape_plain(addr: SocketAddr, with_account: bool) -> Vec<Vec<u8>> {
    let mut s = TcpStream::connect(addr).unwrap();
    let mut msg = [&[gchar(0)][..], b"newmain\n"].concat();
    if with_account {
        msg.extend([vec![gchar(1)], gstr(b"acct"), gstr(b"pw"), b"\n".to_vec()].concat());
    }
    s.write_all(&frame(&zlib_compress(&msg).unwrap())).unwrap();
    let (frames, _) = read_frames(&mut s, WAIT);
    frames
        .iter()
        .flat_map(|f| lines(&zlib_decompress(f).unwrap()))
        .collect()
}

/// What a gen-5 login got back: the ids per frame, the compression bytes,
/// the decoded frames and whether the server closed the link.
type Gen5Reply = (Vec<Vec<usize>>, Vec<u8>, Vec<Vec<Vec<u8>>>, bool);

/// Log in as gen 5 with `pid` (7 for 2.22/2.31, 5 for the RC list).
fn shape_gen5(addr: SocketAddr, pid: usize, account: &[u8], password: &[u8]) -> Gen5Reply {
    let key = 0x45;
    let mut s = TcpStream::connect(addr).unwrap();
    let list = if pid == 7 { &b"newmain"[..] } else { b"" };
    let hs = [&[gchar(pid), gchar(key)][..], b"GNW30123", list, b"\n"].concat();
    s.write_all(&frame(&zlib_compress(&hs).unwrap())).unwrap();
    let (mut cin, mut cout) = (Gen5::new(key as u8), Gen5::new(key as u8));
    let body = [
        vec![gchar(1)],
        gstr(account),
        gstr(password),
        b"\n".to_vec(),
    ]
    .concat();
    let body = [vec![0x02], cout.encode(body, Gen5Comp::None)].concat();
    s.write_all(&frame(&body)).unwrap();
    let (frames, closed) = read_frames(&mut s, WAIT);
    let (mut got, mut ctypes, mut decoded) = (Vec::new(), Vec::new(), Vec::new());
    for f in frames {
        ctypes.push(f[0]);
        let comp = if f[0] == 4 {
            Gen5Comp::Zlib
        } else {
            Gen5Comp::None
        };
        let raw = cin.decode(f[1..].to_vec(), comp);
        let raw = if f[0] == 4 {
            zlib_decompress(&raw).unwrap()
        } else {
            raw
        };
        let l = lines(&raw);
        got.push(ids(&l));
        decoded.push(l);
    }
    (got, ctypes, decoded, closed)
}

#[test]
fn gserver_registers_and_veriacc2_is_answered() {
    let lab = Lab::start(&[]);
    let (_g, replies) = lab.fake_gserver(b"acct", b"pw");
    assert_eq!(
        ids(&replies),
        vec![11],
        "one VERIACC2 answer, no answer to the ping"
    );
    let r = &replies[0];
    assert!(r.ends_with(b"SUCCESS"), "{r:?}");
    // id, account, player id, type, then SUCCESS.
    assert_eq!(
        &r[..],
        &[
            &[gchar(11)][..],
            &gstr(b"acct"),
            &[gchar(0), gchar(2), gchar(5)],
            b"SUCCESS"
        ]
        .concat()[..]
    );
}

#[test]
fn shape_a_and_b_get_an_untagged_list_once() {
    let lab = Lab::start(&[]);
    let (_g, _) = lab.fake_gserver(b"acct", b"pw");
    for (port, with_account, name) in [
        (0, false, "shape A (2.00/2.05)"),
        (2, true, "shape B (2.17)"),
    ] {
        let got = shape_plain(lab.client(port), with_account);
        assert_eq!(ids(&got), vec![0, 2], "{name}: list + status, once");
        let rows = parse_list(&got[0]);
        assert_eq!(rows.len(), 1, "{name}");
        assert_eq!(rows[0][0], b"TestWorld", "{name}: untagged");
        assert_eq!(rows[0][5], b"1", "{name}: one player");
        assert_eq!(
            rows[0][6], b"127.0.0.1",
            "{name}: AUTO becomes the gserver's address"
        );
        assert_eq!(rows[0][7], b"14802", "{name}");
        let status = &got[1][1..];
        assert!(
            status.starts_with(b"Welcome to Lab listserver, "),
            "{}",
            String::from_utf8_lossy(status)
        );
        assert!(status.ends_with(b".\rThere are 1 server(s) online."));
    }
}

#[test]
fn gen4_gets_list_and_status_in_one_bz2_frame() {
    let lab = Lab::start(&[]);
    let (_g, _) = lab.fake_gserver(b"acct", b"pw");
    let key = 0x21u8;
    let mut s = TcpStream::connect(lab.client(1)).unwrap();
    let hs = [&[gchar(4), gchar(key as usize)][..], b"GNW15053\n"].concat();
    s.write_all(&frame(&zlib_compress(&hs).unwrap())).unwrap();
    let (mut cin, mut cout) = (Gen5::new(key), Gen5::new(key));
    let login = [vec![gchar(1)], gstr(b"acct"), gstr(b"pw"), b"\n".to_vec()].concat();
    s.write_all(&frame(
        &cout.encode(bz2_compress(&login).unwrap(), Gen5Comp::Bz2),
    ))
    .unwrap();
    let (frames, _) = read_frames(&mut s, WAIT);
    let got: Vec<Vec<Vec<u8>>> = frames
        .into_iter()
        .map(|f| lines(&bz2_decompress(&cin.decode(f, Gen5Comp::Bz2)).unwrap()))
        .collect();
    assert_eq!(
        got.iter().map(|l| ids(l)).collect::<Vec<_>>(),
        vec![vec![0, 2]]
    );
    assert_eq!(
        parse_list(&got[0][0])[0][0],
        b"P TestWorld",
        "gen 4 is tagged"
    );
}

#[test]
fn gen5_and_rc_list_get_two_zlib_frames_tagged() {
    let lab = Lab::start(&[]);
    let (_g, _) = lab.fake_gserver(b"acct", b"pw");
    for (pid, name) in [(7, "gen 5 (2.22/2.31)"), (5, "RC list (id 5)")] {
        let (got, ctypes, decoded, _) = shape_gen5(lab.client(1), pid, b"acct", b"pw");
        assert_eq!(got, vec![vec![0], vec![2, 3, 5]], "{name}");
        assert_eq!(ctypes, vec![4, 4], "{name}");
        assert_eq!(
            parse_list(&decoded[0][0])[0][0],
            b"P TestWorld",
            "{name}: tagged gold"
        );
        assert_eq!(
            &decoded[1][1][1..],
            b"http://127.0.0.1/site",
            "{name}: site URL from the config"
        );
        assert_eq!(
            &decoded[1][2][1..],
            b"",
            "{name}: upgrade URL empty by default"
        );
    }
}

#[test]
fn every_client_port_answers_every_shape() {
    let lab = Lab::start(&[]);
    let (_g, _) = lab.fake_gserver(b"acct", b"pw");
    for port in 0..3 {
        assert_eq!(ids(&shape_plain(lab.client(port), false)), vec![0, 2]);
        assert_eq!(
            shape_gen5(lab.client(port), 7, b"acct", b"pw").0,
            vec![vec![0], vec![2, 3, 5]]
        );
    }
}

#[test]
fn refused_logins_get_id_4_and_the_link_closes() {
    let lab = Lab::start(&[("test1", b"labpw")]);
    let (_g, replies) = lab.fake_gserver(b"test1", b"nope");
    assert!(
        replies[0].ends_with(b"Your password is incorrect."),
        "{:?}",
        String::from_utf8_lossy(&replies[0])
    );

    let (got, _, decoded, closed) = shape_gen5(lab.client(1), 7, b"test1", b"wrong");
    assert_eq!(got, vec![vec![4]], "gen 5 bad password refused with id 4");
    assert_eq!(&decoded[0][0][1..], b"Your password is incorrect.");
    assert!(closed, "the link is closed after id 4");

    let (got, _, decoded, closed) = shape_gen5(lab.client(1), 7, b"nobody", b"x");
    assert_eq!(got, vec![vec![4]]);
    assert_eq!(&decoded[0][0][1..], b"Account does not exist.");
    assert!(closed);

    let got = shape_plain(lab.client(2), true);
    assert_eq!(
        ids(&got),
        vec![4],
        "shape B with an unknown account is refused"
    );

    let (got, ..) = shape_gen5(lab.client(1), 7, b"test1", b"labpw");
    assert_eq!(
        got,
        vec![vec![0], vec![2, 3, 5]],
        "the right password gets in"
    );
}

#[test]
fn entry_dropped_after_the_gserver_disconnects() {
    let lab = Lab::start(&[]);
    let (g, _) = lab.fake_gserver(b"acct", b"pw");
    assert_eq!(parse_list(&shape_plain(lab.client(2), true)[0]).len(), 1);
    drop(g);
    let deadline = Instant::now() + Duration::from_secs(5);
    loop {
        let got = shape_plain(lab.client(2), true);
        if got[0][1] - 32 == 0 {
            break;
        }
        assert!(
            Instant::now() < deadline,
            "entry still listed after the gserver left"
        );
        std::thread::sleep(Duration::from_millis(50));
    }
}

#[test]
fn garbage_does_not_take_the_listserver_down() {
    let lab = Lab::start(&[]);
    let (_g, _) = lab.fake_gserver(b"acct", b"pw");
    // Not zlib, then a frame that announces more than it sends, then a
    // gserver that never sends REGISTERV3's line feed.
    let mut s = TcpStream::connect(lab.client(0)).unwrap();
    s.write_all(&frame(b"not zlib at all")).unwrap();
    s.write_all(&[0xFF, 0xFF, 1, 2, 3]).unwrap();
    drop(s);
    let mut g = TcpStream::connect(lab.run.gserver_addr).unwrap();
    g.write_all(&[b'x'; 2000]).unwrap();
    drop(g);
    // Short and empty messages.
    let mut s = TcpStream::connect(lab.client(0)).unwrap();
    s.write_all(&frame(
        &zlib_compress(&[gchar(1), b'\n', gchar(7), b'\n', gchar(99), b'\n']).unwrap(),
    ))
    .unwrap();
    let (frames, _) = read_frames(&mut s, WAIT);
    assert!(frames.is_empty());
    assert_eq!(
        ids(&shape_plain(lab.client(0), false)),
        vec![0, 2],
        "still answering"
    );
}

fn allow(ip: &str, hq_password: &str) -> seihai_listserver::config::GserverAllow {
    seihai_listserver::config::GserverAllow {
        ip: ip.into(),
        hq_password: hq_password.into(),
    }
}

fn register_line(g: &mut TcpStream) {
    g.write_all(&[&[gchar(30)][..], b"lab-test\n"].concat())
        .unwrap();
}

fn send_lines(g: &mut TcpStream, msgs: &[Vec<u8>]) {
    let body: Vec<u8> = msgs.iter().flat_map(|m| [&m[..], b"\n"].concat()).collect();
    g.write_all(&frame(&zlib_compress(&body).unwrap())).unwrap();
}

fn hq_line(password: &[u8]) -> Vec<u8> {
    let mut m = vec![gchar(23)];
    m.extend_from_slice(password);
    m
}

fn newserver_line() -> Vec<u8> {
    let fields: [&[u8]; 8] = [
        b"TestWorld",
        b"A test server",
        b"English",
        b"3.0.9",
        b"http://x/",
        b"AUTO",
        b"14802",
        b"",
    ];
    [
        vec![gchar(22)],
        fields.iter().flat_map(|f| gstr(f)).collect(),
    ]
    .concat()
}

fn wait_listed(lab: &Lab, n: usize) {
    let deadline = Instant::now() + Duration::from_secs(2);
    while lab.run.shared.servers.listed() != n {
        assert!(
            Instant::now() < deadline,
            "listed count stayed {}, wanted {n}",
            lab.run.shared.servers.listed()
        );
        std::thread::sleep(Duration::from_millis(20));
    }
}

#[test]
fn allow_list_lists_a_server_only_after_the_hq_password() {
    let lab = Lab::start_gservers(&[], vec![allow("127.0.0.1", "lab-hq")]);
    let mut g = TcpStream::connect(lab.run.gserver_addr).unwrap();
    register_line(&mut g);
    send_lines(&mut g, &[newserver_line()]);
    let (frames, closed) = read_frames(&mut g, Duration::from_millis(300));
    assert!(frames.is_empty() && !closed);
    assert_eq!(
        lab.run.shared.servers.listed(),
        0,
        "NEWSERVER before SERVERHQPASS is not listed"
    );

    send_lines(
        &mut g,
        &[
            hq_line(b"lab-hq"),
            newserver_line(),
            vec![gchar(24), gchar(3)],
        ],
    );
    wait_listed(&lab, 1);
    let got = shape_plain(lab.client(0), false);
    assert_eq!(parse_list(&got[0])[0][0], b"TestWorld");
    assert_eq!(parse_list(&got[0])[0][6], b"127.0.0.1");

    // A later SERVERHQPASS that does not match closes the link and drops the entry.
    send_lines(&mut g, &[hq_line(b"nope")]);
    let (frames, closed) = read_frames(&mut g, WAIT);
    assert!(frames.is_empty() && closed);
    wait_listed(&lab, 0);
}

#[test]
fn allow_list_drops_other_addresses_and_a_wrong_hq_password() {
    // ::1 is loopback, and this link comes from 127.0.0.1, so it is not allowed.
    let other = Lab::start_gservers(&[], vec![allow("::1", "lab-hq")]);
    let mut g = TcpStream::connect(other.run.gserver_addr).unwrap();
    let _ = g.write_all(&[&[gchar(30)][..], b"nope\n"].concat());
    g.set_read_timeout(Some(WAIT)).unwrap();
    let mut buf = [0u8; 8];
    match g.read(&mut buf) {
        Ok(0) => {}
        Err(e)
            if matches!(
                e.kind(),
                ErrorKind::ConnectionReset | ErrorKind::ConnectionAborted | ErrorKind::BrokenPipe
            ) => {}
        other => panic!("expected the other address to be dropped, got {other:?}"),
    }
    assert_eq!(other.run.shared.servers.listed(), 0);

    let lab = Lab::start_gservers(&[], vec![allow("127.0.0.1", "lab-hq")]);
    let mut g = TcpStream::connect(lab.run.gserver_addr).unwrap();
    register_line(&mut g);
    let veri = [
        vec![gchar(17)],
        gstr(b"acct"),
        gstr(b"pw"),
        vec![gchar(0), gchar(2), gchar(5)],
    ]
    .concat();
    send_lines(&mut g, &[hq_line(b"wrong"), newserver_line(), veri]);
    let (frames, closed) = read_frames(&mut g, WAIT);
    assert!(closed, "a wrong hq password closes the link");
    assert!(
        frames.is_empty(),
        "no VERIACC2 answer when the hq password does not match: {frames:?}"
    );
    assert_eq!(lab.run.shared.servers.listed(), 0);
}
