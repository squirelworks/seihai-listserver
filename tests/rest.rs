//! Loopback checks for the steps after the gserver allow-list: a silent
//! 1.41 (shape S), the failed-login cap, and config reload.

use seihai_core::protocol::{zlib_compress, zlib_decompress};
use seihai_listserver::{accounts, start, start_at, Config};
use std::io::{ErrorKind, Read, Write};
use std::net::{SocketAddr, TcpStream};
use std::path::Path;
use std::time::{Duration, Instant, SystemTime};

fn gchar(n: usize) -> u8 {
    (n + 32) as u8
}

fn gstr(s: &[u8]) -> Vec<u8> {
    [&[gchar(s.len())][..], s].concat()
}

fn frame(body: &[u8]) -> Vec<u8> {
    [&(body.len() as u16).to_be_bytes()[..], body].concat()
}

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
        if rest.len() < 2 + n {
            break;
        }
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

fn shape_a(addr: SocketAddr) -> Vec<Vec<u8>> {
    let mut s = TcpStream::connect(addr).unwrap();
    let msg = [&[gchar(0)][..], b"newmain\n"].concat();
    s.write_all(&frame(&zlib_compress(&msg).unwrap())).unwrap();
    let (frames, _) = read_frames(&mut s, Duration::from_millis(800));
    assert_eq!(frames.len(), 1, "shape A is one frame");
    lines(&zlib_decompress(&frames[0]).unwrap())
}

fn shape_b(addr: SocketAddr, account: &[u8], password: &[u8]) -> Vec<Vec<u8>> {
    let mut s = TcpStream::connect(addr).unwrap();
    let mut msg = [&[gchar(0)][..], b"newmain\n"].concat();
    msg.extend(
        [
            vec![gchar(1)],
            gstr(account),
            gstr(password),
            b"\n".to_vec(),
        ]
        .concat(),
    );
    s.write_all(&frame(&zlib_compress(&msg).unwrap())).unwrap();
    let (frames, _) = read_frames(&mut s, Duration::from_millis(800));
    frames
        .iter()
        .flat_map(|f| lines(&zlib_decompress(f).unwrap()))
        .collect()
}

fn text(line: &[u8]) -> String {
    String::from_utf8_lossy(&line[1..]).into_owned()
}

#[test]
fn silent_client_gets_shape_a() {
    let dir = tempfile::tempdir().unwrap();
    let cfg = Config {
        gserver_port: 0,
        client_ports: vec![0],
        secure_login_key: dir.path().join("seihai-login.key"),
        silent_list_after_ms: 200,
        status_log_secs: 0,
        ..Config::default()
    };
    let run = start(cfg).unwrap();
    let mut s = TcpStream::connect(run.client_addrs[0]).unwrap();
    let (frames, closed) = read_frames(&mut s, Duration::from_millis(1500));
    assert!(!closed, "the link stays open after the list");
    assert_eq!(frames.len(), 1);
    let got = lines(&zlib_decompress(&frames[0]).unwrap());
    assert_eq!(ids(&got), vec![0, 2]);
    assert!(
        text(&got[1]).contains("player"),
        "shape S uses the same status account as shape A: {}",
        text(&got[1])
    );
}

#[test]
fn silent_wait_off_sends_nothing() {
    let dir = tempfile::tempdir().unwrap();
    let cfg = Config {
        gserver_port: 0,
        client_ports: vec![0],
        secure_login_key: dir.path().join("seihai-login.key"),
        silent_list_after_ms: 0,
        status_log_secs: 0,
        ..Config::default()
    };
    let run = start(cfg).unwrap();
    let mut s = TcpStream::connect(run.client_addrs[0]).unwrap();
    let (frames, closed) = read_frames(&mut s, Duration::from_millis(400));
    assert!(frames.is_empty(), "0 ms does not speak first: {frames:?}");
    assert!(!closed);
}

#[test]
fn a_client_that_speaks_is_not_answered_twice() {
    let dir = tempfile::tempdir().unwrap();
    let cfg = Config {
        gserver_port: 0,
        client_ports: vec![0],
        secure_login_key: dir.path().join("seihai-login.key"),
        silent_list_after_ms: 2000,
        status_log_secs: 0,
        ..Config::default()
    };
    let run = start(cfg).unwrap();
    let got = shape_a(run.client_addrs[0]);
    assert_eq!(ids(&got), vec![0, 2]);
}

#[test]
fn failed_guesses_stop_at_the_cap_and_veriacc_is_counted_apart() {
    let dir = tempfile::tempdir().unwrap();
    let accounts_path = dir.path().join("accounts.txt");
    accounts::add_account(&accounts_path, "test1", b"labpw").unwrap();
    let cfg = Config {
        gserver_port: 0,
        client_ports: vec![0],
        accounts: accounts_path,
        secure_login_key: dir.path().join("seihai-login.key"),
        login_fail_limit: 1,
        login_fail_window_secs: 60,
        silent_list_after_ms: 0,
        status_log_secs: 0,
        ..Config::default()
    };
    let run = start(cfg).unwrap();
    let addr = run.client_addrs[0];

    let first = shape_b(addr, b"test1", b"nope");
    assert_eq!(ids(&first), vec![4]);
    assert!(text(&first[0]).contains("password is incorrect"));

    let second = shape_b(addr, b"test1", b"labpw");
    assert_eq!(ids(&second), vec![4]);
    assert!(
        text(&second[0]).contains("Too many tries"),
        "the right password is not checked once the cap is full: {}",
        text(&second[0])
    );

    let mut g = TcpStream::connect(run.gserver_addr).unwrap();
    g.write_all(&[&[gchar(30)][..], b"lab-test\n"].concat())
        .unwrap();
    let veri = |password: &[u8]| {
        [
            vec![gchar(17)],
            gstr(b"test1"),
            gstr(password),
            vec![gchar(0), gchar(2), gchar(5)],
        ]
        .concat()
    };
    let send = |g: &mut TcpStream, password: &[u8]| {
        let body = [&veri(password)[..], b"\n"].concat();
        g.write_all(&frame(&zlib_compress(&body).unwrap())).unwrap();
        let (frames, _) = read_frames(g, Duration::from_millis(800));
        assert_eq!(frames.len(), 1);
        let got = lines(&zlib_decompress(&frames[0]).unwrap());
        assert_eq!(ids(&got), vec![11]);
        text(&got[0])
    };
    let v1 = send(&mut g, b"nope");
    assert!(
        v1.contains("password is incorrect"),
        "VERIACC2 does not share the client cap: {v1}"
    );
    let v2 = send(&mut g, b"labpw");
    assert!(
        v2.contains("Too many tries"),
        "a second VERIACC2 from the same address is capped: {v2}"
    );
}

#[test]
fn open_mode_does_not_count_a_login_as_a_failure() {
    let dir = tempfile::tempdir().unwrap();
    let cfg = Config {
        gserver_port: 0,
        client_ports: vec![0],
        secure_login_key: dir.path().join("seihai-login.key"),
        login_fail_limit: 1,
        status_log_secs: 0,
        ..Config::default()
    };
    let run = start(cfg).unwrap();
    for password in [b"one".as_slice(), b"two".as_slice()] {
        let got = shape_b(run.client_addrs[0], b"anyone", password);
        assert_eq!(ids(&got), vec![0, 2], "{password:?}");
    }
}

fn write_cfg(path: &Path, status: &str, extra: &str) {
    let body = format!(
        "\
bind = \"127.0.0.1\"
gserver_port = 0
client_ports = [0]
list_name = \"Lab\"
status = \"{status}\"
secure_login_key = \"\"
accounts = \"\"
status_log_secs = 0
silent_list_after_ms = 0
login_fail_limit = 30
login_fail_window_secs = 60
{extra}
"
    );
    let tmp = path.with_extension("tmp");
    std::fs::write(&tmp, body).unwrap();
    std::fs::rename(&tmp, path).unwrap();
}

fn touch_future(path: &Path) {
    let f = std::fs::File::options().write(true).open(path).unwrap();
    f.set_modified(SystemTime::now() + Duration::from_secs(5))
        .unwrap();
}

#[test]
fn reload_applies_the_file_and_a_later_edit_is_picked_up() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("list.toml");
    write_cfg(&path, "Before {account}.", "");
    let cfg = Config::load(&path).unwrap();
    let run = start_at(cfg, Some(path.clone())).unwrap();
    let addr = run.client_addrs[0];
    assert!(
        text(&shape_a(addr)[1]).contains("Before player"),
        "{}",
        text(&shape_a(addr)[1])
    );

    write_cfg(&path, "After {account}.", "");
    run.reload().unwrap();
    assert!(
        text(&shape_a(addr)[1]).contains("After player"),
        "reload() applies the new status"
    );

    write_cfg(
        &path,
        "Watched {account}.",
        "gservers = [{ ip = \"::1\", hq_password = \"lab-hq\" }]\n",
    );
    touch_future(&path);
    let deadline = Instant::now() + Duration::from_secs(3);
    loop {
        let status = text(&shape_a(addr)[1]);
        if status.contains("Watched player") {
            break;
        }
        assert!(
            Instant::now() < deadline,
            "the file change was not picked up: {status}"
        );
        std::thread::sleep(Duration::from_millis(50));
    }

    let mut g = TcpStream::connect(run.gserver_addr).unwrap();
    let _ = g.write_all(&[&[gchar(30)][..], b"nope\n"].concat());
    g.set_read_timeout(Some(Duration::from_millis(800)))
        .unwrap();
    let mut buf = [0u8; 8];
    match g.read(&mut buf) {
        Ok(0) => {}
        Err(e)
            if matches!(
                e.kind(),
                ErrorKind::ConnectionReset | ErrorKind::ConnectionAborted | ErrorKind::BrokenPipe
            ) => {}
        other => panic!("expected 127.0.0.1 to be dropped after reload, got {other:?}"),
    }
}

#[test]
fn a_bad_config_file_keeps_the_running_settings() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("list.toml");
    write_cfg(&path, "Still {account}.", "");
    let cfg = Config::load(&path).unwrap();
    let run = start_at(cfg, Some(path.clone())).unwrap();
    std::fs::write(&path, "port = 1\n").unwrap();
    touch_future(&path);
    std::thread::sleep(Duration::from_millis(600));
    assert!(run.reload().is_err());
    assert!(text(&shape_a(run.client_addrs[0])[1]).contains("Still player"));
}
