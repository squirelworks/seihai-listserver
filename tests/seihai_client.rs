//! Seihai's own listserver client (`seihai --list-only`, from seihai-core)
//! against the Rust listserver on loopback, for every login shape Seihai
//! sends: A (2.00, 2.05), B (2.17), C (2.22, 2.31) and D (3.04).

use seihai_core::net::Connection;
use seihai_core::protocol::{zlib_compress, ClientVersion};
use seihai_listserver::Config;
use std::io::Write;
use std::net::TcpStream;
use std::time::Duration;

fn gstr(s: &[u8]) -> Vec<u8> {
    [&[(s.len() + 32) as u8][..], s].concat()
}

#[test]
fn seihai_list_only_for_each_shape() {
    let dir = tempfile::tempdir().unwrap();
    let accounts = dir.path().join("accounts.txt");
    seihai_listserver::accounts::add_account(&accounts, "test1", b"labpw").unwrap();
    let cfg = Config {
        gserver_port: 0,
        client_ports: vec![0],
        accounts,
        secure_login_key: dir.path().join("seihai-login.key"),
        ..Config::default()
    };
    let run = seihai_listserver::start(cfg).unwrap();

    // A gold gserver with one player.
    let mut g = TcpStream::connect(run.gserver_addr).unwrap();
    g.write_all(b">lab\n").unwrap();
    let fields: [&[u8]; 8] = [
        b"Lab World",
        b"desc",
        b"English",
        b"2.22",
        b"",
        b"AUTO",
        b"14802",
        b"",
    ];
    let mut body = vec![22 + 32];
    for f in fields {
        body.extend(gstr(f));
    }
    body.extend_from_slice(&[b'\n', 24 + 32, 3 + 32, b'\n', 14 + 32, 32, 33, 32, b'\n']);
    let z = zlib_compress(&body).unwrap();
    g.write_all(&[&(z.len() as u16).to_be_bytes()[..], &z].concat())
        .unwrap();
    // Wait until it is listed.
    for _ in 0..100 {
        if run.shared.servers.listed() == 1 {
            break;
        }
        std::thread::sleep(Duration::from_millis(20));
    }

    let addr = run.client_addrs[0].to_string();
    for (label, kind) in [
        ("2.05", ""),
        ("2.17", ""),
        ("2.22", "P"),
        ("2.31", "P"),
        ("3.04", "P"),
    ] {
        let version =
            ClientVersion::from_label(label).unwrap_or_else(|| panic!("no Seihai profile {label}"));
        let reply = Connection::fetch_server_list(&addr, version, "test1", "labpw")
            .unwrap_or_else(|e| panic!("{label}: {e}"));
        assert_eq!(reply.error, None, "{label}");
        assert_eq!(reply.servers.len(), 1, "{label}");
        let s = &reply.servers[0];
        assert_eq!(
            (s.name.as_str(), s.kind.as_str()),
            ("Lab World", kind),
            "{label}"
        );
        assert_eq!(
            (s.host.as_str(), s.port, s.players),
            ("127.0.0.1", 14802, Some(1)),
            "{label}"
        );
        let status = reply.status.unwrap_or_default();
        assert!(
            status.contains("There are 1 server(s) online."),
            "{label}: {status:?}"
        );

        if label != "2.05" {
            // Shapes B to D send the account, so a wrong password is refused.
            let bad = Connection::fetch_server_list(&addr, version, "test1", "wrong");
            let refused = match bad {
                Ok(r) => r.error,
                Err(e) => Some(e.to_string()),
            };
            assert!(
                refused
                    .unwrap_or_default()
                    .contains("password is incorrect"),
                "{label}"
            );
        }
    }
}
