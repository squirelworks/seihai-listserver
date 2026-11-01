//! The registered gservers, and the list and status messages built from them.

use crate::wire::{gchar, put_gstr, GCHAR_MAX};
use std::collections::{BTreeMap, BTreeSet};
use std::sync::Mutex;

/// Listserver to client message ids.
pub mod plo {
    pub const SVRLIST: usize = 0;
    pub const STATUS: usize = 2;
    pub const SITEURL: usize = 3;
    pub const ERROR: usize = 4;
    pub const UPGURL: usize = 5;
}

/// One gserver's entry.
#[derive(Debug, Clone, Default)]
pub struct Entry {
    /// Set by `NEWSERVER`; an entry without a name is not listed.
    pub name: Option<Vec<u8>>,
    pub description: Vec<u8>,
    pub language: Vec<u8>,
    pub version: Vec<u8>,
    pub url: Vec<u8>,
    pub ip: Vec<u8>,
    pub port: Vec<u8>,
    /// HQ level from `SERVERHQLEVEL`; bronze until the gserver says.
    pub hq_level: usize,
    /// Player ids on the gserver.
    pub players: BTreeSet<u16>,
}

/// The tag in front of a server name in a tagged list (gen 4, gen 5, RC):
/// 0 hidden `U `, 1 bronze `H `, 2 classic (none), 3 gold `P `, 4 G3D `3 `.
///
/// HQ level 0 is not put on a public list at all. [`hq_tag`] is applied
/// only when the list includes that server (the RC list).
pub fn hq_tag(level: usize) -> &'static [u8] {
    match level {
        0 => b"U ",
        1 => b"H ",
        3 => b"P ",
        4 => b"3 ",
        _ => b"",
    }
}

/// Who the id 0 list is for.
///
/// HQ level 0 is hidden. It is included only for [`ListFor::Rc`] (client
/// id 5), tagged `U `. Every other list omits it, so those lists are not
/// tagged `U `. Squirrel, 2026-11-01 (`docs/NEXT.md`).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ListFor {
    /// No HQ tags (2.00 to 2.17, and a silent 1.41).
    Plain,
    /// HQ tags, hidden servers omitted (gen 4, gen 5, the secure login).
    Tagged,
    /// The RC list (client id 5): HQ tags, hidden servers included.
    Rc,
}

/// A named gserver is shown to `who`. HQ level 0 is shown only on the RC list.
fn shown(entry: &Entry, who: ListFor) -> bool {
    entry.name.is_some() && (who == ListFor::Rc || entry.hq_level != 0)
}

/// All gservers, in the order they connected.
#[derive(Default)]
pub struct Servers {
    entries: Mutex<BTreeMap<u64, Entry>>,
}

impl Servers {
    /// Add an empty entry for a new gserver link.
    pub fn insert(&self, id: u64) {
        self.lock().insert(
            id,
            Entry {
                hq_level: 1,
                ..Entry::default()
            },
        );
    }

    /// Drop a gserver's entry.
    pub fn remove(&self, id: u64) -> Option<Entry> {
        self.lock().remove(&id)
    }

    /// Change a gserver's entry.
    pub fn update<R>(&self, id: u64, f: impl FnOnce(&mut Entry) -> R) -> Option<R> {
        self.lock().get_mut(&id).map(f)
    }

    /// Number of named gservers, including hidden ones. The status log uses
    /// this. A client's `{servers}` figure is [`Self::listed_for`].
    pub fn listed(&self) -> usize {
        self.counts().0
    }

    /// Named gservers that `who` is shown. HQ level 0 counts only for the RC list.
    pub fn listed_for(&self, who: ListFor) -> usize {
        self.lock().values().filter(|e| shown(e, who)).count()
    }

    /// Named gservers, and the players on them, including hidden servers.
    pub fn counts(&self) -> (usize, usize) {
        let entries = self.lock();
        let mut servers = 0;
        let mut players = 0;
        for e in entries.values() {
            if e.name.is_some() {
                servers += 1;
                players += e.players.len();
            }
        }
        (servers, players)
    }

    /// One log line: how many servers and players are listed.
    pub fn status_line(&self) -> String {
        let (servers, players) = self.counts();
        format!("status: {servers} server(s), {players} player(s)")
    }

    /// The id 0 server list message for `who`.
    ///
    /// A named gserver with HQ level 0 is left out unless `who` is the RC
    /// list. Tags are applied for [`ListFor::Tagged`] and [`ListFor::Rc`].
    pub fn list_message(&self, who: ListFor) -> Vec<u8> {
        let entries = self.lock();
        let rows: Vec<&Entry> = entries
            .values()
            .filter(|e| shown(e, who))
            .take(GCHAR_MAX)
            .collect();
        let mut out = vec![gchar(plo::SVRLIST), gchar(rows.len())];
        for e in rows {
            let mut name = if who == ListFor::Plain {
                Vec::new()
            } else {
                hq_tag(e.hq_level).to_vec()
            };
            name.extend_from_slice(e.name.as_deref().unwrap_or_default());
            let players = e.players.len().to_string();
            out.push(gchar(8));
            for f in [
                &name[..],
                &e.language,
                &e.description,
                &e.url,
                &e.version,
                players.as_bytes(),
                &e.ip,
                &e.port,
            ] {
                put_gstr(&mut out, f);
            }
        }
        out
    }

    fn lock(&self) -> std::sync::MutexGuard<'_, BTreeMap<u64, Entry>> {
        self.entries.lock().unwrap_or_else(|e| e.into_inner())
    }
}

/// The id 2 status message: `template` with `{list}`, `{account}` and
/// `{servers}` filled in, line breaks as `\r`.
pub fn status_message(template: &str, list: &str, account: &[u8], servers: usize) -> Vec<u8> {
    let mut out = vec![gchar(plo::STATUS)];
    let mut rest = template;
    while let Some(start) = rest.find('{') {
        out.extend_from_slice(&rest.as_bytes()[..start]);
        let tail = &rest[start..];
        let (value, used): (Vec<u8>, usize) = if tail.starts_with("{list}") {
            (list.as_bytes().to_vec(), 6)
        } else if tail.starts_with("{account}") {
            (account.to_vec(), 9)
        } else if tail.starts_with("{servers}") {
            (servers.to_string().into_bytes(), 9)
        } else {
            (b"{".to_vec(), 1)
        };
        out.extend_from_slice(&value);
        rest = &tail[used..];
    }
    out.extend_from_slice(rest.as_bytes());
    for b in &mut out {
        if *b == b'\n' {
            *b = b'\r';
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn status_fills_placeholders() {
        let m = status_message(
            "Welcome to {list}, {account}.\nThere are {servers} server(s) {x}.",
            "Lab",
            b"me",
            2,
        );
        assert_eq!(&m[1..], b"Welcome to Lab, me.\rThere are 2 server(s) {x}.");
        assert_eq!(m[0], 32 + 2);
    }

    #[test]
    fn list_tags_only_when_asked_and_skips_unnamed() {
        let s = Servers::default();
        s.insert(1);
        s.insert(2);
        s.update(2, |e| {
            e.name = Some(b"World".to_vec());
            e.hq_level = 3;
            e.players.insert(7);
        });
        let parsed = seihai_core::protocol::parse_list_reply(
            &[s.list_message(ListFor::Tagged), b"\n".to_vec()].concat(),
        );
        assert_eq!(parsed.servers.len(), 1);
        assert_eq!(parsed.servers[0].kind, "P");
        assert_eq!(parsed.servers[0].name, "World");
        assert_eq!(parsed.servers[0].players, Some(1));
        let plain = seihai_core::protocol::parse_list_reply(
            &[s.list_message(ListFor::Plain), b"\n".to_vec()].concat(),
        );
        assert_eq!(plain.servers[0].kind, "");
    }

    #[test]
    fn status_line_counts_named_servers_and_their_players() {
        let s = Servers::default();
        s.insert(1);
        s.insert(2);
        s.update(2, |e| {
            e.name = Some(b"World".to_vec());
            e.players.insert(1);
            e.players.insert(2);
        });
        assert_eq!(s.counts(), (1, 2));
        assert_eq!(s.status_line(), "status: 1 server(s), 2 player(s)");
    }

    /// HQ level 0 is hidden: the RC list includes it, tagged `U `. Public
    /// lists omit it, so they are not tagged `U `. Squirrel, 2026-11-01
    /// (`docs/NEXT.md`).
    #[test]
    fn hq_level_zero_is_listed_only_on_the_rc_list() {
        let s = Servers::default();
        s.insert(1);
        s.update(1, |e| {
            e.name = Some(b"Quiet".to_vec());
            e.hq_level = 0;
        });
        s.insert(2);
        s.update(2, |e| {
            e.name = Some(b"World".to_vec());
            e.hq_level = 3;
        });
        // A hidden gserver with no name is not a list row for anyone.
        s.insert(3);
        s.update(3, |e| e.hq_level = 0);

        assert_eq!(s.listed(), 2, "the table still counts the hidden gserver");
        assert_eq!(s.listed_for(ListFor::Rc), 2);
        assert_eq!(s.listed_for(ListFor::Plain), 1);
        assert_eq!(s.listed_for(ListFor::Tagged), 1);

        let rc = seihai_core::protocol::parse_list_reply(
            &[s.list_message(ListFor::Rc), b"\n".to_vec()].concat(),
        );
        assert_eq!(rc.servers.len(), 2);
        assert_eq!(rc.servers[0].kind, "U");
        assert_eq!(rc.servers[0].name, "Quiet");
        assert_eq!(rc.servers[1].kind, "P");
        assert_eq!(rc.servers[1].name, "World");

        for who in [ListFor::Plain, ListFor::Tagged] {
            let parsed = seihai_core::protocol::parse_list_reply(
                &[s.list_message(who), b"\n".to_vec()].concat(),
            );
            assert_eq!(parsed.servers.len(), 1, "{who:?}");
            assert_eq!(parsed.servers[0].name, "World", "{who:?}");
            assert_ne!(parsed.servers[0].kind, "U", "{who:?}");
            let raw = s.list_message(who);
            assert!(
                !raw.windows(b"Quiet".len()).any(|w| w == b"Quiet"),
                "{who:?} omits the hidden server"
            );
            assert!(
                !raw.windows(2).any(|w| w == b"U "),
                "{who:?} is not tagged U"
            );
        }
    }
}
