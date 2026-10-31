//! The Seihai secure login (`SEI00001`) against the Rust listserver on
//! loopback, with Seihai's own client from seihai-core: the list comes
//! back, the password is checked, and the key is pinned.

use seihai_core::net::{Connection, SecureLogin};
use seihai_core::protocol::seclogin::{self, ServerIdentity};
use seihai_core::protocol::{write_zlib_frame, zlib_decompress, ClientVersion};
use seihai_listserver::{Config, Running};
use std::io::{Read, Write};
use std::net::TcpStream;
use std::path::Path;

fn lab(dir: &Path, require: bool, key: bool) -> Running {
    let accounts = dir.join("accounts.txt");
    seihai_listserver::accounts::add_account(&accounts, "test1", b"labpw").unwrap();
    seihai_listserver::start(Config {
        gserver_port: 0,
        client_ports: vec![0],
        accounts,
        secure_login_key: if key {
            dir.join("seihai-login.key")
        } else {
            Default::default()
        },
        require_secure_login: require,
        ..Config::default()
    })
    .unwrap()
}

fn server_key(dir: &Path) -> [u8; 32] {
    ServerIdentity::load_or_create(&dir.join("seihai-login.key"))
        .unwrap()
        .0
        .public_key()
}

#[test]
fn secure_list_login_for_222_231_304() {
    let dir = tempfile::tempdir().unwrap();
    let run = lab(dir.path(), false, true);
    let addr = run.client_addrs[0].to_string();
    let secure = SecureLogin::pinned(server_key(dir.path()));
    for v in [
        ClientVersion::V222,
        ClientVersion::V231,
        ClientVersion::V304,
    ] {
        let reply = Connection::fetch_server_list_secure(&addr, v, "test1", "labpw", Some(&secure))
            .unwrap();
        assert_eq!(reply.error, None, "{v:?}");
        assert!(reply.status.unwrap().contains("test1"), "{v:?}");
        let reply = Connection::fetch_server_list_secure(&addr, v, "test1", "wrong", Some(&secure))
            .unwrap();
        assert_eq!(
            reply.error.as_deref(),
            Some("Your password is incorrect."),
            "{v:?}"
        );
    }
}

#[test]
fn a_different_server_key_is_refused_before_the_password_goes() {
    let dir = tempfile::tempdir().unwrap();
    let run = lab(dir.path(), false, true);
    let addr = run.client_addrs[0].to_string();
    let secure = SecureLogin::pinned(ServerIdentity::generate().public_key());
    let e = Connection::fetch_server_list_secure(
        &addr,
        ClientVersion::V231,
        "test1",
        "labpw",
        Some(&secure),
    )
    .unwrap_err();
    assert!(e.to_string().contains("not the given key"), "{e}");
}

#[test]
fn trust_on_first_use_pins_the_key() {
    let dir = tempfile::tempdir().unwrap();
    let run = lab(dir.path(), false, true);
    let addr = run.client_addrs[0].to_string();
    let pins = dir.path().join("known_servers.txt");
    let secure = SecureLogin {
        pin: seihai_core::net::PinSource::File(pins.clone()),
    };
    Connection::fetch_server_list_secure(
        &addr,
        ClientVersion::V231,
        "test1",
        "labpw",
        Some(&secure),
    )
    .unwrap();
    let text = std::fs::read_to_string(&pins).unwrap();
    assert_eq!(
        text.trim(),
        format!("{addr} {}", seclogin::encode_key(&server_key(dir.path())))
    );
}

#[test]
fn require_secure_login_refuses_the_classic_id_1() {
    let dir = tempfile::tempdir().unwrap();
    let run = lab(dir.path(), true, true);
    let addr = run.client_addrs[0].to_string();
    let reply =
        Connection::fetch_server_list(&addr, ClientVersion::V231, "test1", "labpw").unwrap();
    assert_eq!(
        reply.error.as_deref(),
        Some("This listserver needs the Seihai secure login.")
    );
    let secure = SecureLogin::pinned(server_key(dir.path()));
    let reply = Connection::fetch_server_list_secure(
        &addr,
        ClientVersion::V231,
        "test1",
        "labpw",
        Some(&secure),
    )
    .unwrap();
    assert_eq!(reply.error, None);
}

#[test]
fn secure_login_off_says_so() {
    let dir = tempfile::tempdir().unwrap();
    let run = lab(dir.path(), false, false);
    let addr = run.client_addrs[0].to_string();
    let secure = SecureLogin::pinned([0; 32]);
    let e = Connection::fetch_server_list_secure(
        &addr,
        ClientVersion::V231,
        "test1",
        "labpw",
        Some(&secure),
    )
    .unwrap_err();
    assert!(e.to_string().contains("turned off"), "{e}");
}

#[test]
fn a_tampered_seal_gets_no_list() {
    // A raw client: real C1, then a C2 that does not open. The listserver
    // sends nothing and closes.
    let dir = tempfile::tempdir().unwrap();
    let run = lab(dir.path(), false, true);
    let mut s = TcpStream::connect(run.client_addrs[0]).unwrap();
    s.set_read_timeout(Some(std::time::Duration::from_secs(5)))
        .unwrap();
    let hs = seclogin::ClientHandshake::new(&[7 + 32, 0x41], "GNW30123", b"newmain").unwrap();
    s.write_all(&write_zlib_frame(&[hs.hello(), b"\n"].concat()).unwrap())
        .unwrap();
    let mut len = [0u8; 2];
    s.read_exact(&mut len).unwrap();
    let mut body = vec![0u8; u16::from_be_bytes(len) as usize];
    s.read_exact(&mut body).unwrap();
    let s1 = zlib_decompress(&body).unwrap();
    assert!(s1.starts_with(b"SEI00001"));
    let bad = [&b"SEI00001"[..], &[b'A'; 120][..], b"\n"].concat();
    s.write_all(&write_zlib_frame(&bad).unwrap()).unwrap();
    let mut rest = Vec::new();
    let _ = s.read_to_end(&mut rest);
    assert!(rest.is_empty(), "no list after a bad seal");
}
