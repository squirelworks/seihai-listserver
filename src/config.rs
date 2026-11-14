//! The listserver's settings, read from a TOML file.

use serde::Deserialize;
use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::time::Duration;

/// One gserver that may register when [`Config::gservers`] is not empty.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct GserverAllow {
    /// Address the gserver's link comes from, such as `127.0.0.1`.
    pub ip: String,
    /// Password carried as the raw rest of a `SERVERHQPASS` line (not a
    /// GSTRING). It must match before that link's `NEWSERVER` is listed.
    pub hq_password: String,
}

/// Which address the list gives clients for a gserver.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum GserverIp {
    /// The address the gserver's link comes from.
    Peer,
    /// The address the gserver sends in `NEWSERVER`; the link's address when
    /// it sends `AUTO` or nothing.
    Sent,
}

/// Everything in `seihai-listserver.toml`. Every key is optional.
#[derive(Debug, Clone, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct Config {
    /// Address to listen on.
    pub bind: String,
    /// Port gservers register on.
    pub gserver_port: u16,
    /// Ports clients ask for the list on. Every port answers every login shape.
    pub client_ports: Vec<u16>,
    /// Name of the list, used in the status text.
    pub list_name: String,
    /// Status text after a login. `{list}`, `{account}` and `{servers}` are
    /// filled in; a line break becomes the client's `\r` line break.
    pub status: String,
    /// Site URL sent to gen-5 clients (id 3). Empty by default.
    pub site_url: String,
    /// Upgrade URL sent to gen-5 clients (id 5). Empty by default.
    pub upgrade_url: String,
    /// Accounts file. Empty: open mode, every account and password gets in.
    pub accounts: PathBuf,
    /// Also write the log to this file. Empty: standard error only.
    pub log_file: PathBuf,
    /// Which address the list shows for each gserver.
    pub gserver_ip: GserverIp,
    /// Most links open at once, clients and gservers together.
    pub max_connections: usize,
    /// Seconds a client link may stay silent before it is closed.
    pub client_timeout_secs: u64,
    /// Seconds a gserver link may stay silent before its entry is dropped.
    /// GServer-v2 beta4 sends a keep-alive every 60 s.
    pub gserver_timeout_secs: u64,
    /// How often, in seconds, to send an empty ping (id 99) to each
    /// enrolled gserver. The gserver answers with an empty pong (id 16),
    /// which is not answered. 0: off.
    #[serde(default = "default_gserver_ping_secs")]
    pub gserver_ping_secs: u64,
    /// The Seihai secure login (`SEI00001`, Seihai's
    /// `documentation/secure-login.md`): the file with this listserver's
    /// Ed25519 key, created on first start. Empty: secure logins are refused.
    pub secure_login_key: PathBuf,
    /// Refuse an account and password sent in the clear (classic id 1).
    /// Off by default, so real clients keep working.
    pub require_secure_login: bool,
    /// Refuse gserver links that are not encrypted (GServer-v2 and the
    /// fork speak only the plain link). Off by default.
    pub require_secure_gserver_link: bool,
    /// When non-empty, only these addresses may register, and a server is
    /// listed only after `SERVERHQPASS` matches that address's
    /// `hq_password`. Empty: any link may register.
    pub gservers: Vec<GserverAllow>,
    /// How long to wait for a client's first frame. Real 1.41 rev 1 connects
    /// and waits, so when this is set and nothing arrives, the listserver
    /// sends the shape A reply (id 0 list, id 2 status). 0: off.
    #[serde(default = "default_silent_list_after_ms")]
    pub silent_list_after_ms: u64,
    /// Failed client logins, and failed `VERIACC2` checks, allowed from one
    /// address in [`Self::login_fail_window_secs`]. The two are counted
    /// apart. Further guesses are refused without checking the password. 0: no cap.
    #[serde(default = "default_login_fail_limit")]
    pub login_fail_limit: u32,
    /// Seconds one address's failure count covers. 0: no cap.
    #[serde(default = "default_login_fail_window_secs")]
    pub login_fail_window_secs: u64,
    /// The machines table (PC ids, see `src/machines.rs`). Empty: no PC
    /// ids are given out. Read at start; a change takes a restart.
    pub machines: PathBuf,
    /// MD5 digests (32 hex digits) that never identify a machine, such as a
    /// product id that many machines share. Read again on reload.
    pub pcid_ignore_hashes: Vec<String>,
    /// How many hardware digests a login must share with a known machine
    /// to get its PC id (1 to 3). A login that sends fewer must share all
    /// it sent. Read again on reload.
    #[serde(default = "default_pcid_match_hashes")]
    pub pcid_match_hashes: usize,
    /// How often to log how many servers and players are listed. 0: off.
    #[serde(default = "default_status_log_secs")]
    pub status_log_secs: u64,
    /// Player profiles (`GETPROF` / `SETPROF`). Empty: kept in memory
    /// only. Read at start; a change takes a restart.
    pub profiles: PathBuf,
    /// Buddy lists (`verifybuddies`, `addbuddy`, `deletebuddy`). Empty:
    /// kept in memory only. Read at start; a change takes a restart.
    pub buddies: PathBuf,
    /// The SQLite data file for profiles and buddy lists (`src/store.rs`).
    /// Empty: the `profiles` and `buddies` settings work as before. When
    /// set, a `profiles` or `buddies` text file is imported into it once and
    /// not used after. Read at start; a change takes a restart.
    pub data: PathBuf,
    /// Global guilds: guild name to member accounts (ASCII case ignored).
    /// A player may wear a guild's tag only when listed here. Read again
    /// on reload.
    pub guilds: BTreeMap<String, Vec<String>>,
}

fn default_silent_list_after_ms() -> u64 {
    0
}

fn default_login_fail_limit() -> u32 {
    30
}

fn default_login_fail_window_secs() -> u64 {
    60
}

fn default_pcid_match_hashes() -> usize {
    2
}

fn default_status_log_secs() -> u64 {
    300
}

fn default_gserver_ping_secs() -> u64 {
    60
}

impl Default for Config {
    fn default() -> Self {
        Self {
            bind: "127.0.0.1".into(),
            gserver_port: 14900,
            client_ports: vec![14921, 14922, 14923],
            list_name: "Lab listserver".into(),
            status: "Welcome to {list}, {account}.\nThere are {servers} server(s) online.".into(),
            site_url: String::new(),
            upgrade_url: String::new(),
            accounts: PathBuf::new(),
            log_file: PathBuf::new(),
            gserver_ip: GserverIp::Peer,
            max_connections: 256,
            client_timeout_secs: 30,
            gserver_timeout_secs: 300,
            gserver_ping_secs: default_gserver_ping_secs(),
            secure_login_key: PathBuf::from("seihai-login.key"),
            require_secure_login: false,
            require_secure_gserver_link: false,
            gservers: Vec::new(),
            silent_list_after_ms: default_silent_list_after_ms(),
            login_fail_limit: default_login_fail_limit(),
            login_fail_window_secs: default_login_fail_window_secs(),
            machines: PathBuf::from("seihai-machines.tsv"),
            pcid_ignore_hashes: Vec::new(),
            pcid_match_hashes: default_pcid_match_hashes(),
            status_log_secs: default_status_log_secs(),
            profiles: PathBuf::new(),
            buddies: PathBuf::new(),
            data: PathBuf::new(),
            guilds: BTreeMap::new(),
        }
    }
}

impl Config {
    /// Read a config file. A relative `accounts`, `log_file`, `machines` or
    /// `secure_login_key` path is taken from the config file's folder.
    pub fn load(path: &Path) -> Result<Self, String> {
        let text = std::fs::read_to_string(path).map_err(|e| format!("{}: {e}", path.display()))?;
        let mut cfg = Self::parse(&text).map_err(|e| format!("{}: {e}", path.display()))?;
        let dir = path.parent().unwrap_or(Path::new(""));
        for p in [
            &mut cfg.accounts,
            &mut cfg.log_file,
            &mut cfg.secure_login_key,
            &mut cfg.machines,
            &mut cfg.profiles,
            &mut cfg.buddies,
            &mut cfg.data,
        ] {
            if !p.as_os_str().is_empty() && p.is_relative() {
                *p = dir.join(&*p);
            }
        }
        Ok(cfg)
    }

    /// Parse config text.
    pub fn parse(text: &str) -> Result<Self, String> {
        let mut cfg: Self = toml::from_str(text).map_err(|e| e.to_string())?;
        cfg.check()?;
        for h in &mut cfg.pcid_ignore_hashes {
            h.make_ascii_lowercase();
        }
        Ok(cfg)
    }

    fn check(&self) -> Result<(), String> {
        if self.client_ports.is_empty() {
            return Err("client_ports is empty".into());
        }
        if self.max_connections == 0 {
            return Err("max_connections must be at least 1".into());
        }
        for (key, v) in [
            ("site_url", &self.site_url),
            ("upgrade_url", &self.upgrade_url),
            ("list_name", &self.list_name),
        ] {
            if v.contains(['\n', '\r']) {
                return Err(format!("{key} must be one line"));
            }
        }
        if !(1..=crate::machines::HARDWARE_SLOTS).contains(&self.pcid_match_hashes) {
            return Err("pcid_match_hashes must be 1, 2 or 3".into());
        }
        for h in &self.pcid_ignore_hashes {
            if h.len() != 32 || !h.bytes().all(|b| b.is_ascii_hexdigit()) {
                return Err(format!(
                    "pcid_ignore_hashes must be MD5 digests of 32 hex digits, not {h:?}"
                ));
            }
        }
        for (guild, members) in &self.guilds {
            if guild.is_empty() || guild.contains(['\n', '\r', ',', '"']) {
                return Err(format!(
                    "guild names must be one line with no comma or quote, not {guild:?}"
                ));
            }
            if members.iter().any(|m| m.contains(['\n', '\r'])) {
                return Err(format!("guild {guild:?} has a member name over two lines"));
            }
        }
        for g in &self.gservers {
            if g.ip.parse::<std::net::IpAddr>().is_err() {
                return Err(format!(
                    "gservers ip must be an address such as 127.0.0.1, not {:?}",
                    g.ip
                ));
            }
            if g.hq_password.contains(['\n', '\r']) {
                return Err("gservers hq_password must be one line".into());
            }
        }
        Ok(())
    }

    pub fn client_timeout(&self) -> Duration {
        Duration::from_secs(self.client_timeout_secs.max(1))
    }

    pub fn gserver_timeout(&self) -> Duration {
        Duration::from_secs(self.gserver_timeout_secs.max(1))
    }

    /// How long a new client may stay silent before the shape A list is sent.
    /// Zero: the listserver does not speak first.
    pub fn silent_list_after(&self) -> Duration {
        Duration::from_millis(self.silent_list_after_ms)
    }

    /// How long one address's failed-login count lasts. Zero, or a
    /// [`Self::login_fail_limit`] of zero, turns the cap off.
    pub fn login_fail_window(&self) -> Duration {
        Duration::from_secs(self.login_fail_window_secs)
    }
}

/// The sample config shipped with the release, with every key at its default.
pub const SAMPLE: &str = include_str!("../seihai-listserver.sample.toml");

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sample_matches_the_defaults() {
        let s = Config::parse(SAMPLE).unwrap();
        let d = Config::default();
        assert_eq!(s.bind, d.bind);
        assert_eq!(s.gserver_port, d.gserver_port);
        assert_eq!(s.client_ports, d.client_ports);
        assert_eq!(s.list_name, d.list_name);
        assert_eq!(s.status, d.status);
        assert_eq!(s.site_url, "");
        assert_eq!(s.upgrade_url, "");
        assert_eq!(s.accounts, d.accounts);
        assert_eq!(s.gserver_ip, d.gserver_ip);
        assert_eq!(s.max_connections, d.max_connections);
        assert_eq!(s.secure_login_key, d.secure_login_key);
        assert_eq!(s.require_secure_login, d.require_secure_login);
        assert_eq!(s.require_secure_gserver_link, d.require_secure_gserver_link);
        assert!(s.gservers.is_empty());
        assert_eq!(s.silent_list_after_ms, d.silent_list_after_ms);
        assert_eq!(s.login_fail_limit, d.login_fail_limit);
        assert_eq!(s.login_fail_window_secs, d.login_fail_window_secs);
        assert_eq!(s.status_log_secs, d.status_log_secs);
        assert_eq!(s.gserver_ping_secs, d.gserver_ping_secs);
        assert_eq!(s.machines, d.machines);
        assert!(s.pcid_ignore_hashes.is_empty());
        assert_eq!(s.pcid_match_hashes, d.pcid_match_hashes);
        assert_eq!(s.profiles, d.profiles);
        assert_eq!(s.buddies, d.buddies);
        assert_eq!(s.data, d.data);
        assert!(s.guilds.is_empty());
    }

    #[test]
    fn guilds_parse_and_bad_names_are_refused() {
        let c = Config::parse("[guilds]\n\"Staff\" = [\"alice\", \"Bob\"]\n").unwrap();
        assert_eq!(c.guilds["Staff"], vec!["alice", "Bob"]);
        assert!(Config::parse("[guilds]\n\"a,b\" = []\n").is_err());
        assert!(Config::parse("[guilds]\n\"\" = []\n").is_err());
    }

    #[test]
    fn gserver_allow_list_parses_loopback_and_rejects_bad_rows() {
        let c = Config::parse(
            "gservers = [{ ip = \"127.0.0.1\", hq_password = \"lab\" }, { ip = \"::1\", hq_password = \"\" }]",
        )
        .unwrap();
        assert_eq!(c.gservers[0].ip, "127.0.0.1");
        assert_eq!(c.gservers[0].hq_password, "lab");
        assert_eq!(c.gservers[1].hq_password, "");
        assert!(
            Config::parse("gservers = [{ ip = \"not-an-address\", hq_password = \"x\" }]").is_err()
        );
        assert!(
            Config::parse("gservers = [{ ip = \"127.0.0.1\", hq_password = \"a\\nb\" }]").is_err()
        );
        assert!(Config::parse("gservers = [{ ip = \"127.0.0.1\" }]").is_err());
    }

    #[test]
    fn empty_file_is_the_defaults() {
        let c = Config::parse("").unwrap();
        assert_eq!(c.bind, "127.0.0.1");
        assert!(c.site_url.is_empty() && c.upgrade_url.is_empty());
        assert_eq!(c.silent_list_after_ms, 0);
        assert_eq!(c.login_fail_limit, default_login_fail_limit());
        assert_eq!(c.login_fail_window_secs, default_login_fail_window_secs());
        assert_eq!(c.status_log_secs, default_status_log_secs());
        assert_eq!(c.gserver_ping_secs, default_gserver_ping_secs());
    }

    #[test]
    fn unknown_keys_and_bad_values_are_refused() {
        assert!(Config::parse("port = 1").is_err());
        assert!(Config::parse("client_ports = []").is_err());
        assert!(Config::parse("site_url = \"a\\nb\"").is_err());
        assert!(Config::parse("gserver_ip = \"sent\"").is_ok());
        assert!(Config::parse("pcid_ignore_hashes = [\"abc\"]").is_err());
        assert!(Config::parse("pcid_match_hashes = 0").is_err());
        assert!(Config::parse("pcid_match_hashes = 4").is_err());
        assert_eq!(Config::parse("").unwrap().pcid_match_hashes, 2);
        let c =
            Config::parse("pcid_ignore_hashes = [\"D41D8CD98F00B204E9800998ECF8427E\"]").unwrap();
        assert_eq!(
            c.pcid_ignore_hashes,
            vec!["d41d8cd98f00b204e9800998ecf8427e"]
        );
    }
}
