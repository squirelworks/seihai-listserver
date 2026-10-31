//! The listserver's settings, read from a TOML file.

use serde::Deserialize;
use std::path::{Path, PathBuf};
use std::time::Duration;

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
    /// The Seihai secure login (`SEI00001`, Seihai's
    /// `documentation/secure-login.md`): the file with this listserver's
    /// Ed25519 key, created on first start. Empty: secure logins are refused.
    pub secure_login_key: PathBuf,
    /// Refuse an account and password sent in the clear (classic id 1).
    /// Off by default, so real clients keep working.
    pub require_secure_login: bool,
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
            secure_login_key: PathBuf::from("seihai-login.key"),
            require_secure_login: false,
        }
    }
}

impl Config {
    /// Read a config file. A relative `accounts`, `log_file` or
    /// `secure_login_key` path is taken from the config file's folder.
    pub fn load(path: &Path) -> Result<Self, String> {
        let text = std::fs::read_to_string(path).map_err(|e| format!("{}: {e}", path.display()))?;
        let mut cfg = Self::parse(&text).map_err(|e| format!("{}: {e}", path.display()))?;
        let dir = path.parent().unwrap_or(Path::new(""));
        for p in [
            &mut cfg.accounts,
            &mut cfg.log_file,
            &mut cfg.secure_login_key,
        ] {
            if !p.as_os_str().is_empty() && p.is_relative() {
                *p = dir.join(&*p);
            }
        }
        Ok(cfg)
    }

    /// Parse config text.
    pub fn parse(text: &str) -> Result<Self, String> {
        let cfg: Self = toml::from_str(text).map_err(|e| e.to_string())?;
        cfg.check()?;
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
        Ok(())
    }

    pub fn client_timeout(&self) -> Duration {
        Duration::from_secs(self.client_timeout_secs.max(1))
    }

    pub fn gserver_timeout(&self) -> Duration {
        Duration::from_secs(self.gserver_timeout_secs.max(1))
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
    }

    #[test]
    fn empty_file_is_the_defaults() {
        let c = Config::parse("").unwrap();
        assert_eq!(c.bind, "127.0.0.1");
        assert!(c.site_url.is_empty() && c.upgrade_url.is_empty());
    }

    #[test]
    fn unknown_keys_and_bad_values_are_refused() {
        assert!(Config::parse("port = 1").is_err());
        assert!(Config::parse("client_ports = []").is_err());
        assert!(Config::parse("site_url = \"a\\nb\"").is_err());
        assert!(Config::parse("gserver_ip = \"sent\"").is_ok());
    }
}
