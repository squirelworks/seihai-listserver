//! The Seihai secure login (`SEI00001`) against the Rust listserver on
//! loopback, with Seihai's own client from seihai-core: the list comes
//! back, the password is checked, and the key is pinned.

use seihai_core::net::{Connection, SecureLogin};
use seihai_core::protocol::seclogin::{self, ServerIdentity};
use seihai_core::protocol::{
    write_zlib_frame, zlib_compress, zlib_decompress, ClientVersion, Gen5, Gen5Comp,
};
use seihai_listserver::{Config, Running};
use std::io::{Read, Write};
use std::net::TcpStream;
use std::path::Path;
use std::time::{Duration, Instant};

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

// The RC list (id 5) over the secure login, as seihai-rc's
// `servers --secure-login` sends it: id 5, the key byte, `SEI00001`, the RC
// token and the client's key, with no list name; then id 1's payload sealed.

fn gchar(n: usize) -> u8 {
    (n + 32) as u8
}

fn gstr(s: &[u8]) -> Vec<u8> {
    [&[gchar(s.len())][..], s].concat()
}

fn read_frame(s: &mut TcpStream) -> Option<Vec<u8>> {
    let mut len = [0u8; 2];
    s.read_exact(&mut len).ok()?;
    let mut body = vec![0u8; u16::from_be_bytes(len) as usize];
    s.read_exact(&mut body).ok()?;
    Some(body)
}

/// What the RC got back: the lines of each decoded gen-5 frame, and whether
/// the link was closed afterwards.
struct RcReply {
    frames: Vec<Vec<Vec<u8>>>,
    closed: bool,
}

impl RcReply {
    fn ids(&self) -> Vec<Vec<usize>> {
        self.frames
            .iter()
            .map(|f| f.iter().map(|l| (l[0] - 32) as usize).collect())
            .collect()
    }

    fn error(&self) -> Option<&[u8]> {
        self.frames
            .iter()
            .flatten()
            .find(|l| l[0] == gchar(4))
            .map(|l| &l[1..])
    }

    /// The server names on the id 0 list.
    fn names(&self) -> Vec<Vec<u8>> {
        let l = self
            .frames
            .iter()
            .flatten()
            .find(|l| l[0] == gchar(0))
            .unwrap();
        let n = (l[1] - 32) as usize;
        let mut i = 2;
        let mut names = Vec::new();
        for _ in 0..n {
            i += 1;
            for field in 0..8 {
                let len = (l[i] - 32) as usize;
                if field == 0 {
                    names.push(l[i + 1..i + 1 + len].to_vec());
                }
                i += 1 + len;
            }
        }
        names
    }
}

/// Log in for the RC list with the secure login, checking the server key.
fn secure_rc_list(
    addr: std::net::SocketAddr,
    pin: [u8; 32],
    account: &[u8],
    password: &[u8],
) -> RcReply {
    let key = 0x45u8;
    let mut s = TcpStream::connect(addr).unwrap();
    s.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
    let hs =
        seclogin::ClientHandshake::new(&[gchar(5), gchar(key as usize)], "GSERV025", b"").unwrap();
    s.write_all(&write_zlib_frame(&[hs.hello(), b"\n"].concat()).unwrap())
        .unwrap();
    let s1 = zlib_decompress(&read_frame(&mut s).unwrap()).unwrap();
    if s1.first() == Some(&gchar(4)) {
        // Refused before the handshake (secure login off).
        return RcReply {
            frames: vec![vec![s1.strip_suffix(b"\n").unwrap_or(&s1).to_vec()]],
            closed: true,
        };
    }
    let verified = hs.finish(&s1).unwrap();
    assert_eq!(verified.server_key, pin, "the listserver's key");
    let tail = [gstr(account), gstr(password)].concat();
    let c2 = verified.sealer.seal(&tail).unwrap();
    s.write_all(&write_zlib_frame(&[&c2[..], b"\n"].concat()).unwrap())
        .unwrap();

    let mut cin = Gen5::new(key);
    let mut frames = Vec::new();
    let closed = loop {
        let Some(f) = read_frame(&mut s) else {
            break true;
        };
        assert_eq!(f[0], 0x04, "gen-5 zlib frame");
        let raw = zlib_decompress(&cin.decode(f[1..].to_vec(), Gen5Comp::Zlib)).unwrap();
        frames.push(
            raw.split(|&b| b == b'\n')
                .filter(|l| !l.is_empty())
                .map(<[u8]>::to_vec)
                .collect::<Vec<_>>(),
        );
        if frames.len() == 2 || frames.last().unwrap().iter().any(|l| l[0] == gchar(4)) {
            // The whole reply is in; see whether the link stays open.
            s.set_read_timeout(Some(Duration::from_millis(300)))
                .unwrap();
            let mut b = [0u8; 1];
            break matches!(s.read(&mut b), Ok(0));
        }
    };
    RcReply { frames, closed }
}

/// Register a gserver at `hq_level` (0 is hidden) and wait for it to list.
fn register(run: &Running, name: &[u8], hq_level: usize) -> TcpStream {
    let mut g = TcpStream::connect(run.gserver_addr).unwrap();
    g.write_all(&[&[gchar(30)][..], b"lab-test\n"].concat())
        .unwrap();
    let fields: [&[u8]; 8] = [
        name,
        b"A test server",
        b"English",
        b"3.0.9",
        b"http://x/",
        b"AUTO",
        b"14802",
        b"",
    ];
    let newserver = [
        vec![gchar(22)],
        fields.iter().flat_map(|f| gstr(f)).collect(),
    ]
    .concat();
    let body: Vec<u8> = [vec![gchar(24), gchar(hq_level)], newserver]
        .iter()
        .flat_map(|m| [&m[..], b"\n"].concat())
        .collect();
    let z = zlib_compress(&body).unwrap();
    g.write_all(&[&(z.len() as u16).to_be_bytes()[..], &z].concat())
        .unwrap();
    g
}

fn wait_listed(run: &Running, n: usize) {
    let deadline = Instant::now() + Duration::from_secs(2);
    while run.shared.servers.listed() != n {
        assert!(
            Instant::now() < deadline,
            "listed count stayed {}",
            run.shared.servers.listed()
        );
        std::thread::sleep(Duration::from_millis(20));
    }
}

#[test]
fn secure_rc_list_includes_hidden_servers() {
    let dir = tempfile::tempdir().unwrap();
    let run = lab(dir.path(), false, true);
    let _hidden = register(&run, b"Quiet", 0);
    let _gold = register(&run, b"TestWorld", 3);
    wait_listed(&run, 2);
    let pin = server_key(dir.path());

    let rc = secure_rc_list(run.client_addrs[0], pin, b"test1", b"labpw");
    assert_eq!(rc.ids(), vec![vec![0], vec![2, 3, 5]]);
    assert_eq!(
        rc.names(),
        vec![b"U Quiet".to_vec(), b"P TestWorld".to_vec()]
    );
    assert!(rc.frames[1][0].ends_with(b"There are 2 server(s) online."));

    // The secure player list (id 7) still leaves the hidden server off.
    let reply = Connection::fetch_server_list_secure(
        &run.client_addrs[0].to_string(),
        ClientVersion::V231,
        "test1",
        "labpw",
        Some(&SecureLogin::pinned(pin)),
    )
    .unwrap();
    let names: Vec<_> = reply.servers.iter().map(|s| s.name.clone()).collect();
    assert_eq!(names.len(), 1, "{names:?}");
    assert!(names[0].ends_with("TestWorld"), "{names:?}");
}

#[test]
fn secure_rc_list_checks_the_password() {
    let dir = tempfile::tempdir().unwrap();
    let run = lab(dir.path(), false, true);
    let rc = secure_rc_list(
        run.client_addrs[0],
        server_key(dir.path()),
        b"test1",
        b"wrong",
    );
    assert_eq!(rc.ids(), vec![vec![4]]);
    assert_eq!(rc.error(), Some(&b"Your password is incorrect."[..]));
    assert!(rc.closed, "the link is closed after id 4");
}

#[test]
fn require_secure_login_refuses_the_classic_rc_list() {
    let dir = tempfile::tempdir().unwrap();
    let run = lab(dir.path(), true, true);
    // Classic RC: id 5 handshake in the clear, then id 1 in a gen-5 frame.
    let key = 0x45u8;
    let mut s = TcpStream::connect(run.client_addrs[0]).unwrap();
    s.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
    let hs = [&[gchar(5), gchar(key as usize)][..], b"GSERV025\n"].concat();
    s.write_all(&write_zlib_frame(&hs).unwrap()).unwrap();
    let (mut cin, mut cout) = (Gen5::new(key), Gen5::new(key));
    let body = [
        vec![gchar(1)],
        gstr(b"test1"),
        gstr(b"labpw"),
        b"\n".to_vec(),
    ]
    .concat();
    let body = [vec![0x02], cout.encode(body, Gen5Comp::None)].concat();
    s.write_all(&[&(body.len() as u16).to_be_bytes()[..], &body].concat())
        .unwrap();
    let f = read_frame(&mut s).unwrap();
    let raw = zlib_decompress(&cin.decode(f[1..].to_vec(), Gen5Comp::Zlib)).unwrap();
    assert_eq!(raw, b"$This listserver needs the Seihai secure login.\n");
    assert!(read_frame(&mut s).is_none(), "the link is closed");

    // The secure RC list still gets in.
    let rc = secure_rc_list(
        run.client_addrs[0],
        server_key(dir.path()),
        b"test1",
        b"labpw",
    );
    assert_eq!(rc.ids(), vec![vec![0], vec![2, 3, 5]]);
}

#[test]
fn failed_secure_rc_logins_count_towards_the_rate_limit() {
    let dir = tempfile::tempdir().unwrap();
    let accounts = dir.path().join("accounts.txt");
    seihai_listserver::accounts::add_account(&accounts, "test1", b"labpw").unwrap();
    let run = seihai_listserver::start(Config {
        gserver_port: 0,
        client_ports: vec![0],
        accounts,
        secure_login_key: dir.path().join("seihai-login.key"),
        login_fail_limit: 2,
        login_fail_window_secs: 600,
        ..Config::default()
    })
    .unwrap();
    let pin = server_key(dir.path());
    let addr = run.client_addrs[0];
    for _ in 0..2 {
        let rc = secure_rc_list(addr, pin, b"test1", b"wrong");
        assert_eq!(rc.error(), Some(&b"Your password is incorrect."[..]));
    }
    // Over the cap, even the right password is not checked.
    let rc = secure_rc_list(addr, pin, b"test1", b"labpw");
    assert_eq!(
        rc.error(),
        Some(&b"Too many tries. Wait and try again."[..])
    );
    // The cap is per address, not per login shape: id 7 is blocked too.
    let reply = Connection::fetch_server_list_secure(
        &addr.to_string(),
        ClientVersion::V231,
        "test1",
        "labpw",
        Some(&SecureLogin::pinned(pin)),
    )
    .unwrap();
    assert_eq!(
        reply.error.as_deref(),
        Some("Too many tries. Wait and try again.")
    );
}

#[test]
fn secure_rc_list_off_says_so() {
    let dir = tempfile::tempdir().unwrap();
    let run = lab(dir.path(), false, false);
    let rc = secure_rc_list(run.client_addrs[0], [0; 32], b"test1", b"labpw");
    assert_eq!(
        rc.error(),
        Some(&b"Secure login is turned off on this listserver."[..])
    );
}
