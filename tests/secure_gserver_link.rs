//! The encrypted gserver link (Seihai `documentation/secure-login.md`,
//! "Gserver to listserver link") on loopback: a gserver made from
//! seihai-core's handshake and channel registers, is listed, and checks an
//! account with `VERIACC2`, and no account or password crosses in the clear.

use seihai_core::protocol::seclogin::{self, ClientHandshake, ServerIdentity};
use seihai_core::protocol::{zlib_compress, zlib_decompress};
use seihai_listserver::{Config, Running};
use std::io::{BufRead, BufReader, Read, Write};
use std::net::TcpStream;
use std::path::Path;
use std::time::Duration;

fn gstr(s: &[u8]) -> Vec<u8> {
    [&[(s.len() + 32) as u8][..], s].concat()
}

fn lab(dir: &Path, require: bool) -> Running {
    let accounts = dir.join("accounts.txt");
    seihai_listserver::accounts::add_account(&accounts, "test1", b"labpw").unwrap();
    seihai_listserver::start(Config {
        gserver_port: 0,
        client_ports: vec![0],
        accounts,
        secure_login_key: dir.join("seihai-login.key"),
        require_secure_gserver_link: require,
        ..Config::default()
    })
    .unwrap()
}

fn frame(body: &[u8]) -> Vec<u8> {
    let z = zlib_compress(body).unwrap();
    [&(z.len() as u16).to_be_bytes()[..], &z].concat()
}

/// The classic link's messages: register, new server, one player, and an
/// account check for `password`.
fn classic_link(password: &[u8]) -> Vec<u8> {
    let mut out = b">lab\n".to_vec();
    let mut body = vec![22 + 32];
    for f in [
        &b"Secure World"[..],
        b"desc",
        b"English",
        b"2.31",
        b"",
        b"AUTO",
        b"14802",
        b"",
    ] {
        body.extend(gstr(f));
    }
    body.extend_from_slice(&[b'\n', 14 + 32, 32, 33, 32, b'\n']);
    body.push(17 + 32);
    body.extend(gstr(b"test1"));
    body.extend(gstr(password));
    body.extend_from_slice(&[32, 33, 32, b'\n']);
    out.extend(frame(&body));
    out
}

/// Connect, run the handshake, send the classic link through the channel
/// and return the listserver's first reply line. `wire` gets every byte
/// the gserver sent.
fn secure_gserver(
    run: &Running,
    key: [u8; 32],
    password: &[u8],
    wire: &mut Vec<u8>,
) -> Result<Vec<u8>, String> {
    let s = TcpStream::connect(run.gserver_addr).unwrap();
    s.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
    let mut w = s.try_clone().unwrap();
    let mut r = BufReader::new(s);
    let hs = ClientHandshake::new(b"", seclogin::LINK_TOKEN, b"").unwrap();
    let c1 = [hs.hello(), b"\n"].concat();
    w.write_all(&c1).unwrap();
    wire.extend(&c1);
    let mut s1 = Vec::new();
    r.read_until(b'\n', &mut s1).map_err(|e| e.to_string())?;
    let v = hs.finish(&s1).map_err(|e| e.to_string())?;
    if v.server_key != key {
        return Err("key mismatch".into());
    }
    let mut ch = v.sealer.into_channel();
    let records = ch.seal(&classic_link(password));
    w.write_all(&records).unwrap();
    wire.extend(&records);
    // Read the reply through the channel.
    struct Both(BufReader<TcpStream>, TcpStream);
    impl Read for Both {
        fn read(&mut self, b: &mut [u8]) -> std::io::Result<usize> {
            self.0.read(b)
        }
    }
    impl Write for Both {
        fn write(&mut self, b: &[u8]) -> std::io::Result<usize> {
            self.1.write(b)
        }
        fn flush(&mut self) -> std::io::Result<()> {
            self.1.flush()
        }
    }
    let mut sec = ch.wrap(Both(r, w));
    let mut len = [0u8; 2];
    sec.read_exact(&mut len).map_err(|e| e.to_string())?;
    let mut body = vec![0u8; u16::from_be_bytes(len) as usize];
    sec.read_exact(&mut body).map_err(|e| e.to_string())?;
    // Keep the link open while the caller looks at the list.
    std::mem::forget(sec);
    Ok(zlib_decompress(&body).unwrap())
}

fn key(dir: &Path) -> [u8; 32] {
    ServerIdentity::load_or_create(&dir.join("seihai-login.key"))
        .unwrap()
        .0
        .public_key()
}

#[test]
fn encrypted_link_registers_and_checks_accounts() {
    let dir = tempfile::tempdir().unwrap();
    let run = lab(dir.path(), true);
    let mut wire = Vec::new();
    let reply = secure_gserver(&run, key(dir.path()), b"labpw", &mut wire).unwrap();
    assert_eq!(reply[0], 11 + 32, "SVI_VERIACC2");
    assert!(reply.ends_with(b"SUCCESS\n"), "{reply:?}");
    for secret in [&b"labpw"[..], b"test1", b"Secure World"] {
        assert!(
            !wire.windows(secret.len()).any(|w| w == secret),
            "{secret:?} in the clear"
        );
    }
    for _ in 0..100 {
        if run.shared.servers.listed() == 1 {
            break;
        }
        std::thread::sleep(Duration::from_millis(20));
    }
    assert_eq!(run.shared.servers.listed(), 1);

    let reply = secure_gserver(&run, key(dir.path()), b"wrong", &mut Vec::new()).unwrap();
    assert!(String::from_utf8_lossy(&reply).contains("password is incorrect"));
}

#[test]
fn a_gserver_pinning_another_key_stops() {
    let dir = tempfile::tempdir().unwrap();
    let run = lab(dir.path(), false);
    let e = secure_gserver(
        &run,
        ServerIdentity::generate().public_key(),
        b"labpw",
        &mut Vec::new(),
    )
    .unwrap_err();
    assert_eq!(e, "key mismatch");
}

#[test]
fn require_secure_gserver_link_refuses_the_plain_link() {
    let dir = tempfile::tempdir().unwrap();
    let run = lab(dir.path(), true);
    let mut g = TcpStream::connect(run.gserver_addr).unwrap();
    g.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
    g.write_all(&classic_link(b"labpw")).unwrap();
    let mut rest = Vec::new();
    let _ = g.read_to_end(&mut rest);
    assert!(rest.is_empty(), "no answer on a refused plain link");
    assert_eq!(run.shared.servers.listed(), 0);
}

#[test]
fn plain_links_still_work_by_default() {
    let dir = tempfile::tempdir().unwrap();
    let run = lab(dir.path(), false);
    let mut g = TcpStream::connect(run.gserver_addr).unwrap();
    g.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
    g.write_all(&classic_link(b"labpw")).unwrap();
    let mut len = [0u8; 2];
    g.read_exact(&mut len).unwrap();
    let mut body = vec![0u8; u16::from_be_bytes(len) as usize];
    g.read_exact(&mut body).unwrap();
    assert!(zlib_decompress(&body).unwrap().ends_with(b"SUCCESS\n"));
}
