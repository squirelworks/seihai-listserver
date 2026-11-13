//! The gserver link's text features (`docs/design/gserver-text-profiles-guilds.md`)
//! on loopback: two fake gservers, "Alpha" and "Beta", on one listserver.
//! Profiles, global guilds, the PM server and player lists, the simple
//! list, cross-server PMs, channel chat, player-count pushes and buddies.

use seihai_core::protocol::{zlib_compress, zlib_decompress};
use seihai_listserver::{Config, Running};
use std::collections::BTreeMap;
use std::io::{ErrorKind, Read, Write};
use std::net::TcpStream;
use std::time::{Duration, Instant};

fn gchar(n: usize) -> u8 {
    (n + 32) as u8
}

fn gstr(s: &[u8]) -> Vec<u8> {
    [&[gchar(s.len())][..], s].concat()
}

fn gshort(n: u16) -> [u8; 2] {
    [gchar((n >> 7) as usize), gchar((n & 0x7F) as usize)]
}

fn line(id: usize, body: &[u8]) -> Vec<u8> {
    [&[gchar(id)][..], body, b"\n"].concat()
}

struct Gs {
    s: TcpStream,
    got: Vec<Vec<u8>>,
    buf: Vec<u8>,
}

impl Gs {
    fn open(run: &Running, name: &[u8]) -> Gs {
        let mut s = TcpStream::connect(run.gserver_addr).unwrap();
        s.write_all(&[&[gchar(30)][..], b"lab-test\n"].concat())
            .unwrap();
        let mut g = Gs {
            s,
            got: Vec::new(),
            buf: Vec::new(),
        };
        let mut body = Vec::new();
        for f in [
            name, b"desc", b"English", b"2.31", b"", b"AUTO", b"14802", b"",
        ] {
            body.extend(gstr(f));
        }
        g.send(&[line(22, &body), line(24, &[gchar(3)])]);
        g
    }

    fn send(&mut self, msgs: &[Vec<u8>]) {
        let z = zlib_compress(&msgs.concat()).unwrap();
        self.s
            .write_all(&[&(z.len() as u16).to_be_bytes()[..], &z].concat())
            .unwrap();
    }

    /// `PLYRADD` with the ACCOUNTNAME (34) and NICKNAME (0) props.
    fn add_player(&mut self, id: u16, account: &[u8], nick: &[u8]) {
        let body = [
            &gshort(id)[..],
            &[gchar(0), gchar(34)],
            &gstr(account),
            &[gchar(0)],
            &gstr(nick),
            &[gchar(1)],
            &gstr(b"onlinestartlocal.nw"),
        ]
        .concat();
        self.send(&[line(14, &body)]);
    }

    /// Read until a line with id `want` arrives, or `wait` passes.
    fn wait_for(&mut self, want: usize, wait: Duration) -> Option<Vec<u8>> {
        let end = Instant::now() + wait;
        loop {
            if let Some(i) = self.got.iter().position(|l| l[0] == gchar(want)) {
                return Some(self.got.remove(i));
            }
            let left = end.checked_duration_since(Instant::now())?;
            self.s
                .set_read_timeout(Some(left.max(Duration::from_millis(1))))
                .unwrap();
            let mut b = [0u8; 65536];
            match self.s.read(&mut b) {
                Ok(0) => return None,
                Ok(n) => self.buf.extend_from_slice(&b[..n]),
                Err(e) if matches!(e.kind(), ErrorKind::WouldBlock | ErrorKind::TimedOut) => {
                    return None
                }
                Err(e) => panic!("{e}"),
            }
            while self.buf.len() >= 2 {
                let n = u16::from_be_bytes([self.buf[0], self.buf[1]]) as usize;
                if self.buf.len() < 2 + n {
                    break;
                }
                let raw = zlib_decompress(&self.buf[2..2 + n]).unwrap();
                self.buf.drain(..2 + n);
                for l in raw.split(|&b| b == b'\n').filter(|l| !l.is_empty()) {
                    self.got.push(l.to_vec());
                }
            }
        }
    }

    /// The text of the next `REQUESTTEXT` (19) for player `pid`.
    fn request_text(&mut self, pid: u16) -> String {
        let l = self.wait_for(19, WAIT).expect("a REQUESTTEXT answer");
        assert_eq!(&l[1..3], &gshort(pid));
        String::from_utf8(l[3..].to_vec()).unwrap()
    }

    /// Every `SENDTEXT` (20) text that arrives within `wait`.
    fn sendtexts(&mut self, wait: Duration) -> Vec<String> {
        let mut out = Vec::new();
        let end = Instant::now() + wait;
        while let Some(l) = self.wait_for(20, end.saturating_duration_since(Instant::now())) {
            out.push(String::from_utf8(l[1..].to_vec()).unwrap());
        }
        out
    }

    fn requestlist(&mut self, pid: u16, text: &[u8]) {
        self.send(&[line(26, &[&gshort(pid)[..], text].concat())]);
    }
}

const WAIT: Duration = Duration::from_secs(3);

fn lab(dir: &std::path::Path) -> Running {
    let mut guilds = BTreeMap::new();
    guilds.insert("Staff".to_string(), vec!["Alice".to_string()]);
    seihai_listserver::start(Config {
        gserver_port: 0,
        client_ports: vec![0],
        secure_login_key: dir.join("seihai-login.key"),
        machines: Default::default(),
        profiles: dir.join("profiles.tsv"),
        buddies: dir.join("buddies.tsv"),
        guilds,
        ..Config::default()
    })
    .unwrap()
}

fn wait_listed(run: &Running, n: usize) {
    let end = Instant::now() + WAIT;
    while run.shared.servers.listed() < n && Instant::now() < end {
        std::thread::sleep(Duration::from_millis(20));
    }
    assert_eq!(run.shared.servers.listed(), n);
}

/// Two gservers with a player each: alice (id 3) on Alpha, bob (id 4) on Beta.
fn two(run: &Running) -> (Gs, Gs) {
    let mut a = Gs::open(run, b"Alpha");
    wait_listed(run, 1);
    let mut b = Gs::open(run, b"Beta");
    wait_listed(run, 2);
    a.add_player(3, b"alice", b"Alice A");
    b.add_player(4, b"bob", b"Bob");
    let end = Instant::now() + WAIT;
    while run.shared.servers.counts().1 < 2 && Instant::now() < end {
        std::thread::sleep(Duration::from_millis(20));
    }
    (a, b)
}

#[test]
fn profiles_are_set_by_the_own_server_and_read_from_any() {
    let dir = tempfile::tempdir().unwrap();
    let run = lab(dir.path());
    let (mut a, mut b) = two(&run);

    // No profile yet: still answered, with nine empty fields (our choice;
    // the reference release stays silent).
    b.send(&[line(12, &[&gshort(4)[..], b"x", b"alice"].concat())]);
    let p = b.wait_for(7, WAIT).expect("PROFILE");
    assert_eq!(&p[1..3], &gshort(4));
    assert_eq!(&p[3..], &[&gstr(b"alice")[..], &[gchar(0); 9]].concat()[..]);

    // Beta may not set alice's profile: she is on Alpha.
    let fields: Vec<&[u8]> = vec![b"Alice", b"20", b"f", b"NL", b"", b"", b"", b"Onnet", b"hi"];
    let set = |who: &[u8]| {
        let mut body = vec![b'x'];
        body.extend(gstr(who));
        for f in &fields {
            body.extend(gstr(f));
        }
        line(13, &body)
    };
    b.send(&[set(b"alice")]);
    a.send(&[set(b"ALICE")]);
    std::thread::sleep(Duration::from_millis(200));
    b.send(&[line(12, &[&gshort(4)[..], b"x", b"alice"].concat())]);
    let p = b.wait_for(7, WAIT).expect("PROFILE");
    let mut want = gstr(b"alice");
    for f in &fields {
        want.extend(gstr(f));
    }
    assert_eq!(&p[3..], &want[..]);
    assert!(std::fs::read(dir.path().join("profiles.tsv"))
        .unwrap()
        .starts_with(b"alice\tAlice"));
}

#[test]
fn a_guild_tag_is_answered_only_for_members() {
    let dir = tempfile::tempdir().unwrap();
    let run = lab(dir.path());
    let (mut a, _b) = two(&run);
    let ask = |acc: &[u8], guild: &[u8]| {
        line(
            9,
            &[&gshort(3)[..], &gstr(acc), &gstr(b"Alice A"), &gstr(guild)].concat(),
        )
    };
    a.send(&[
        ask(b"bob", b"Staff"),
        ask(b"alice", b"Nope"),
        ask(b"alice", b"staff"),
    ]);
    let l = a.wait_for(1, WAIT).expect("VERIGUILD");
    assert_eq!(
        &l[1..],
        &[&gshort(3)[..], &gstr(b"Alice A (staff)")].concat()[..]
    );
    assert!(
        a.wait_for(1, Duration::from_millis(300)).is_none(),
        "only one answer"
    );
}

#[test]
fn pm_tabs_list_other_servers_guilds_and_players() {
    let dir = tempfile::tempdir().unwrap();
    let run = lab(dir.path());
    let (mut a, mut b) = two(&run);

    a.requestlist(3, b"GraalEngine,pmservers,\"\"");
    assert_eq!(a.request_text(3), "GraalEngine,pmservers,\"\",Beta");
    a.requestlist(3, b"GraalEngine,pmguilds,\"\"");
    assert_eq!(a.request_text(3), "GraalEngine,pmguilds,\"\",Staff");
    b.requestlist(4, b"GraalEngine,pmserverplayers,alpha");
    assert_eq!(
        b.request_text(4),
        "GraalEngine,pmserverplayers,alpha,\"alice,\"\"Alice A\"\"\""
    );
    b.requestlist(4, b"-Serverlist,lister,simpleserverlist");
    assert_eq!(
        b.request_text(4),
        "-Serverlist,lister,simpleserverlist,\"Alpha,\"\"P Alpha\"\",1\",\"Beta,\"\"P Beta\"\",1\""
    );
}

#[test]
fn a_pm_reaches_the_other_server_with_the_senders_server_in_front() {
    let dir = tempfile::tempdir().unwrap();
    let run = lab(dir.path());
    let (mut a, mut b) = two(&run);
    let pm = b"Alpha,bob,Bob,GraalEngine,pmplayer,alice,\"hi there\"";
    b.send(&[line(29, &[&gshort(4)[..], &pm[..]].concat())]);
    let l = a.wait_for(29, WAIT).expect("PMPLAYER");
    assert_eq!(
        &l[1..],
        b"Beta,bob,Bob,GraalEngine,pmplayer,alice,\"hi there\""
    );
    // Nobody called carol on Alpha: dropped.
    let pm = b"Alpha,bob,Bob,GraalEngine,pmplayer,carol,hi";
    b.send(&[line(29, &[&gshort(4)[..], &pm[..]].concat())]);
    assert!(a.wait_for(29, Duration::from_millis(400)).is_none());
}

#[test]
fn channels_answer_join_and_relay_chat_to_the_other_servers() {
    let dir = tempfile::tempdir().unwrap();
    let run = lab(dir.path());
    let (mut a, mut b) = two(&run);
    a.requestlist(3, b"GraalEngine,irc,join,graal");
    assert_eq!(a.request_text(3), "GraalEngine,irc,join,#graal");
    a.requestlist(3, b"GraalEngine,irc,privmsg,alice,#graal,\"hello all\"");
    let texts = b.sendtexts(Duration::from_millis(1500));
    assert!(
        texts
            .iter()
            .any(|t| t == "GraalEngine,irc,privmsg,alice,#graal,\"hello all\""),
        "{texts:?}"
    );
    a.requestlist(3, b"GraalEngine,irc,part,#graal");
    assert_eq!(a.request_text(3), "GraalEngine,irc,part,#graal");
}

#[test]
fn player_counts_are_pushed_to_the_other_servers() {
    let dir = tempfile::tempdir().unwrap();
    let run = lab(dir.path());
    let (a, mut b) = two(&run);
    let texts = b.sendtexts(Duration::from_millis(2500));
    assert!(
        texts
            .iter()
            .any(|t| t == "Listserver,Modify,Server,Alpha,players=1"),
        "{texts:?}"
    );
    drop(a);
    let texts = b.sendtexts(Duration::from_millis(2500));
    assert!(
        texts
            .iter()
            .any(|t| t == "Listserver,Modify,Server,Alpha,players=-1"),
        "{texts:?}"
    );
}

#[test]
fn buddies_are_stored_and_sent_when_the_clients_crc_differs() {
    let dir = tempfile::tempdir().unwrap();
    let run = lab(dir.path());
    let (mut a, _b) = two(&run);
    a.send(&[
        line(
            26,
            &[&gshort(3)[..], b"GraalEngine,lister,addbuddy,bob"].concat(),
        ),
        line(
            26,
            &[&gshort(3)[..], b"GraalEngine,lister,addbuddy,carol"].concat(),
        ),
        line(
            26,
            &[&gshort(3)[..], b"GraalEngine,lister,deletebuddy,carol"].concat(),
        ),
    ]);
    assert!(
        a.wait_for(19, Duration::from_millis(300)).is_none(),
        "add/delete answer nothing"
    );
    // The real 4.04r2 at login with an empty local list.
    a.requestlist(3, b"GraalEngine,lister,verifybuddies,1,0");
    assert_eq!(a.request_text(3), "GraalEngine,lister,buddylist,bob");
    // CRC-32 of "bob": the lists agree, so nothing.
    let crc = format!("GraalEngine,lister,verifybuddies,1,{}", 0xF5CB_B140u32);
    a.requestlist(3, crc.as_bytes());
    assert!(a.wait_for(19, Duration::from_millis(300)).is_none());
    // Not loading from the server: nothing.
    a.requestlist(3, b"GraalEngine,lister,verifybuddies,0,0");
    assert!(a.wait_for(19, Duration::from_millis(300)).is_none());
    assert_eq!(
        std::fs::read(dir.path().join("buddies.tsv")).unwrap(),
        b"alice\tbob\n"
    );
    // REQUESTBUDDIES (28): account,weapon,type.
    a.send(&[line(
        28,
        &[&gshort(3)[..], b"alice,-Buddies,lister"].concat(),
    )]);
    assert_eq!(a.request_text(3), "-Buddies,lister,buddylist,bob");
}
