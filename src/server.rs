//! Listening sockets and one thread per link.

use crate::accounts::{Accounts, FailLimit, GuessKind};
use crate::config::Config;
use crate::state::Servers;
use seihai_core::protocol::seclogin::{self, ServerIdentity};
use std::io;
use std::net::{IpAddr, SocketAddr, TcpListener, TcpStream};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex, RwLock};
use std::time::{Duration, Instant, SystemTime};

/// What every link thread shares.
pub struct Shared {
    settings: RwLock<Config>,
    accounts_cell: RwLock<Arc<Accounts>>,
    pub servers: Servers,
    /// This listserver's secure-login key; `None` when secure logins are off.
    identity_cell: RwLock<Option<ServerIdentity>>,
    fails: FailLimit,
    open: AtomicUsize,
    next_id: AtomicU64,
    /// Config file to read again on reload. `None` when started from defaults.
    config_path: Mutex<Option<PathBuf>>,
    reload_flag: Arc<AtomicBool>,
}

/// A started listserver.
pub struct Running {
    /// Where gservers register.
    pub gserver_addr: SocketAddr,
    /// Where clients ask for the list, in `client_ports` order.
    pub client_addrs: Vec<SocketAddr>,
    pub shared: Arc<Shared>,
}

impl Running {
    /// Read the config file again and apply it. The listeners stay on the
    /// address and ports they already bound.
    pub fn reload(&self) -> Result<(), String> {
        if self
            .shared
            .config_path
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .is_none()
        {
            return Err("no config file to reload".into());
        }
        self.shared.reload_file()
    }
}

impl Shared {
    /// A copy of the settings, so a reload can replace them without holding
    /// the lock across a login check.
    pub fn config(&self) -> Config {
        self.settings
            .read()
            .unwrap_or_else(|e| e.into_inner())
            .clone()
    }

    fn accounts(&self) -> Arc<Accounts> {
        Arc::clone(&self.accounts_cell.read().unwrap_or_else(|e| e.into_inner()))
    }

    pub(crate) fn identity(&self) -> std::sync::RwLockReadGuard<'_, Option<ServerIdentity>> {
        self.identity_cell.read().unwrap_or_else(|e| e.into_inner())
    }

    /// `None` when the login is allowed, else the error text. Over the
    /// failure cap, the password is not checked.
    pub fn check_login(
        &self,
        kind: GuessKind,
        peer: Option<IpAddr>,
        account: &[u8],
        password: &[u8],
    ) -> Option<&'static [u8]> {
        let cfg = self.config();
        let (limit, window) = (cfg.login_fail_limit, cfg.login_fail_window());
        if self.fails.blocked(kind, peer, limit, window) {
            return Some(crate::accounts::TOO_MANY);
        }
        let err = self.accounts().check(account, password);
        if err.is_some() {
            self.fails.record(kind, peer, limit, window);
        }
        err
    }

    fn reload_file(&self) -> Result<(), String> {
        let path = self
            .config_path
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .clone();
        let Some(path) = path else {
            return Ok(());
        };
        let cfg = Config::load(&path)?;
        self.apply(cfg)?;
        log!("reloaded config from {}", path.display());
        Ok(())
    }

    /// Swap in `cfg`. Bind address and ports that differ are kept, because
    /// the listeners are already up. A missing secure-login key is an error
    /// and changes nothing (reload does not mint a key).
    fn apply(&self, mut cfg: Config) -> Result<(), String> {
        let old = self.config();
        if cfg.bind != old.bind
            || cfg.gserver_port != old.gserver_port
            || cfg.client_ports != old.client_ports
        {
            log!(
                "reload: bind and ports stay {} gserver {} clients {:?} until a restart",
                old.bind,
                old.gserver_port,
                old.client_ports
            );
            cfg.bind.clone_from(&old.bind);
            cfg.gserver_port = old.gserver_port;
            cfg.client_ports.clone_from(&old.client_ports);
        }
        let accounts = Accounts::new(&cfg.accounts)?;
        let identity = load_identity_existing(&cfg.secure_login_key)?;
        if cfg.log_file != old.log_file && !cfg.log_file.as_os_str().is_empty() {
            crate::log::open(&cfg.log_file)
                .map_err(|e| format!("{}: {e}", cfg.log_file.display()))?;
        }
        let old_pk = self.identity().as_ref().map(ServerIdentity::public_key);
        let new_pk = identity.as_ref().map(ServerIdentity::public_key);
        *self
            .accounts_cell
            .write()
            .unwrap_or_else(|e| e.into_inner()) = Arc::new(accounts);
        *self
            .identity_cell
            .write()
            .unwrap_or_else(|e| e.into_inner()) = identity;
        if old_pk != new_pk {
            match &new_pk {
                Some(pk) => log!(
                    "secure login key now {}, fingerprint {}",
                    seclogin::encode_key(pk),
                    seclogin::fingerprint(pk)
                ),
                None => log!("secure login (SEI00001): off"),
            }
        }
        if cfg.log_file != old.log_file && cfg.log_file.as_os_str().is_empty() {
            crate::log::close();
        }
        let n = cfg.gservers.len();
        let cap = if cfg.login_fail_limit == 0 || cfg.login_fail_window_secs == 0 {
            "no cap".to_string()
        } else {
            format!(
                "{} per {}s per address",
                cfg.login_fail_limit, cfg.login_fail_window_secs
            )
        };
        *self.settings.write().unwrap_or_else(|e| e.into_inner()) = cfg;
        log!("reload applied: gserver allow-list {n} entries, login failures {cap}");
        Ok(())
    }
}

/// `key-fingerprint`'s answer. `Ok(None)` means the arguments are wrong.
/// A missing key file is an error; it is not created.
pub fn fingerprint_command(args: &[String]) -> Result<Option<String>, String> {
    let path = match args {
        [] => PathBuf::from("seihai-login.key"),
        [flag, file] if flag == "--config" => {
            let cfg = Config::load(Path::new(file))?;
            if cfg.secure_login_key.as_os_str().is_empty() {
                return Err("secure_login_key is empty".into());
            }
            cfg.secure_login_key
        }
        [file] => PathBuf::from(file),
        _ => return Ok(None),
    };
    Ok(Some(login_key_lines(&path)?))
}

/// The public key text and fingerprint of the key file at `path`.
/// The file is not created, and the seed is not printed.
pub fn login_key_lines(path: &Path) -> Result<String, String> {
    let id = read_login_key(path)?;
    let pk = id.public_key();
    Ok(format!(
        "key {}\nfingerprint {}\n",
        seclogin::encode_key(&pk),
        seclogin::fingerprint(&pk)
    ))
}

fn read_login_key(path: &Path) -> Result<ServerIdentity, String> {
    let text = std::fs::read_to_string(path).map_err(|e| format!("{}: {e}", path.display()))?;
    let seed = seclogin::decode_key(&text)
        .ok_or_else(|| format!("{}: not a secure-login key", path.display()))?;
    Ok(ServerIdentity::from_seed(&seed))
}

fn load_identity_existing(path: &Path) -> Result<Option<ServerIdentity>, String> {
    if path.as_os_str().is_empty() {
        Ok(None)
    } else {
        Ok(Some(read_login_key(path)?))
    }
}

/// Bind every port and start accepting links in background threads.
/// A port of 0 picks a free one (for tests).
pub fn start(config: Config) -> Result<Running, String> {
    start_at(config, None)
}

/// [`start`], and remember `config_path` so a later reload reads that file.
/// On Unix, SIGHUP reloads it too. The file is also read again when its
/// modification time changes.
pub fn start_at(config: Config, config_path: Option<PathBuf>) -> Result<Running, String> {
    let accounts = Accounts::new(&config.accounts)?;
    let identity = if config.secure_login_key.as_os_str().is_empty() {
        log!("secure login (SEI00001): off");
        None
    } else {
        let path = &config.secure_login_key;
        let (id, created) = ServerIdentity::load_or_create(path)
            .map_err(|e| format!("secure login key {}: {e}", path.display()))?;
        log!(
            "secure login (SEI00001): {} key {}, fingerprint {}",
            if created { "made a new" } else { "loaded" },
            seclogin::encode_key(&id.public_key()),
            seclogin::fingerprint(&id.public_key())
        );
        Some(id)
    };
    let bind = |port: u16| {
        TcpListener::bind((config.bind.as_str(), port))
            .map_err(|e| format!("cannot listen on {}:{port}: {e}", config.bind))
    };
    let gserver = bind(config.gserver_port)?;
    let clients = config
        .client_ports
        .iter()
        .map(|&p| bind(p))
        .collect::<Result<Vec<_>, _>>()?;
    let addr = |l: &TcpListener| l.local_addr().map_err(|e| e.to_string());
    let gserver_addr = addr(&gserver)?;
    let client_addrs = clients.iter().map(addr).collect::<Result<Vec<_>, _>>()?;

    let reload_flag = Arc::new(AtomicBool::new(false));
    let shared = Arc::new(Shared {
        settings: RwLock::new(config),
        accounts_cell: RwLock::new(Arc::new(accounts)),
        servers: Servers::default(),
        identity_cell: RwLock::new(identity),
        fails: FailLimit::default(),
        open: AtomicUsize::new(0),
        next_id: AtomicU64::new(1),
        config_path: Mutex::new(config_path),
        reload_flag: Arc::clone(&reload_flag),
    });
    log!(
        "listening on {gserver_addr} for gservers and {} for clients; accounts: {}",
        client_addrs
            .iter()
            .map(|a| a.to_string())
            .collect::<Vec<_>>()
            .join(", "),
        shared.accounts().describe()
    );
    let cfg = shared.config();
    if cfg.gservers.is_empty() {
        log!("gserver allow-list: off");
    } else {
        log!("gserver allow-list: {} entries", cfg.gservers.len());
    }
    if cfg.login_fail_limit == 0 || cfg.login_fail_window_secs == 0 {
        log!("login failures: no cap");
    } else {
        log!(
            "login failures: {} per {}s per address",
            cfg.login_fail_limit,
            cfg.login_fail_window_secs
        );
    }
    if cfg.silent_list_after_ms == 0 {
        log!("silent list (shape S): off");
    } else {
        log!(
            "silent list (shape S): after {} ms",
            cfg.silent_list_after_ms
        );
    }

    arm_reload(&reload_flag);
    spawn_housekeeping(Arc::clone(&shared));
    spawn_accept(gserver, Arc::clone(&shared), |s, id, _port, shared| {
        crate::gserver::serve(s, id, shared)
    });
    for l in clients {
        spawn_accept(l, Arc::clone(&shared), crate::client::serve);
    }
    Ok(Running {
        gserver_addr,
        client_addrs,
        shared,
    })
}

fn spawn_housekeeping(shared: Arc<Shared>) {
    std::thread::Builder::new()
        .name("reload".into())
        .spawn(move || {
            let path = shared
                .config_path
                .lock()
                .unwrap_or_else(|e| e.into_inner())
                .clone();
            let mut seen = path.as_deref().and_then(mtime);
            let mut last_status = Instant::now();
            loop {
                std::thread::sleep(Duration::from_millis(200));
                if shared.reload_flag.swap(false, Ordering::AcqRel) {
                    if let Err(e) = shared.reload_file() {
                        log!("reload: {e}");
                    }
                    let path = shared
                        .config_path
                        .lock()
                        .unwrap_or_else(|e| e.into_inner())
                        .clone();
                    seen = path.as_deref().and_then(mtime);
                }
                let path = shared
                    .config_path
                    .lock()
                    .unwrap_or_else(|e| e.into_inner())
                    .clone();
                if let Some(path) = path.as_deref() {
                    if let Some(t) = mtime(path) {
                        if seen != Some(t) {
                            seen = Some(t);
                            if let Err(e) = shared.reload_file() {
                                log!("reload: {e}");
                            }
                        }
                    }
                }
                let secs = shared.config().status_log_secs;
                if secs > 0 && last_status.elapsed() >= Duration::from_secs(secs) {
                    log!("{}", shared.servers.status_line());
                    last_status = Instant::now();
                }
            }
        })
        .ok();
}

fn mtime(path: &Path) -> Option<SystemTime> {
    std::fs::metadata(path).and_then(|m| m.modified()).ok()
}

#[cfg(unix)]
fn arm_reload(flag: &Arc<AtomicBool>) {
    if let Err(e) = signal_hook::flag::register(signal_hook::consts::SIGHUP, Arc::clone(flag)) {
        log!("SIGHUP reload not armed: {e}");
    }
}

#[cfg(not(unix))]
fn arm_reload(_flag: &Arc<AtomicBool>) {}

fn spawn_accept(
    listener: TcpListener,
    shared: Arc<Shared>,
    serve: fn(TcpStream, u64, u16, &Shared),
) {
    let port = listener.local_addr().map_or(0, |a| a.port());
    std::thread::spawn(move || {
        for stream in listener.incoming() {
            let stream = match stream {
                Ok(s) => s,
                Err(e) => {
                    log!("accept on {port}: {e}");
                    if is_fatal(&e) {
                        std::thread::sleep(std::time::Duration::from_millis(100));
                    }
                    continue;
                }
            };
            let max = shared.config().max_connections;
            if shared.open.fetch_add(1, Ordering::SeqCst) >= max {
                shared.open.fetch_sub(1, Ordering::SeqCst);
                log!("refused a link on {port}: {max} links already open");
                continue;
            }
            let id = shared.next_id.fetch_add(1, Ordering::Relaxed);
            let link = Arc::clone(&shared);
            let spawned = std::thread::Builder::new()
                .name(format!("link-{id}"))
                .spawn(move || {
                    let _ = stream.set_nodelay(true);
                    serve(stream, id, port, &link);
                    link.open.fetch_sub(1, Ordering::SeqCst);
                });
            if let Err(e) = spawned {
                shared.open.fetch_sub(1, Ordering::SeqCst);
                log!("cannot start a thread for link {id}: {e}");
            }
        }
    });
}

/// Errors such as running out of file handles, where accepting again at
/// once would spin.
fn is_fatal(e: &io::Error) -> bool {
    !matches!(
        e.kind(),
        io::ErrorKind::ConnectionAborted
            | io::ErrorKind::ConnectionReset
            | io::ErrorKind::Interrupted
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn login_key_lines_print_the_public_key_and_not_the_seed() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("seihai-login.key");
        let (id, created) = ServerIdentity::load_or_create(&path).unwrap();
        assert!(created);
        let text = login_key_lines(&path).unwrap();
        let pk = id.public_key();
        assert!(text.contains(&seclogin::encode_key(&pk)));
        assert!(text.contains(&seclogin::fingerprint(&pk)));
        let seed = std::fs::read_to_string(&path).unwrap();
        let seed = seed.trim();
        assert!(!seed.is_empty());
        assert!(!text.contains(seed), "the seed must not be printed");
        assert!(login_key_lines(dir.path().join("missing").as_path()).is_err());

        let printed = fingerprint_command(&[path.display().to_string()])
            .unwrap()
            .unwrap();
        assert_eq!(printed, text);
        let cfg_path = dir.path().join("list.toml");
        let key = path.display().to_string().replace('\\', "/");
        std::fs::write(&cfg_path, format!("secure_login_key = \"{key}\"\n")).unwrap();
        let via_cfg = fingerprint_command(&["--config".into(), cfg_path.display().to_string()])
            .unwrap()
            .unwrap();
        assert!(via_cfg.contains(&seclogin::fingerprint(&pk)));
        assert!(
            fingerprint_command(&["too".into(), "many".into(), "args".into()])
                .unwrap()
                .is_none()
        );
        let default_key = PathBuf::from("seihai-login.key");
        if !default_key.exists() {
            assert!(fingerprint_command(&[]).is_err());
            assert!(
                !default_key.exists(),
                "key-fingerprint does not create a missing key"
            );
        }
        std::fs::write(dir.path().join("off.toml"), "secure_login_key = \"\"\n").unwrap();
        assert!(fingerprint_command(&[
            "--config".into(),
            dir.path().join("off.toml").display().to_string()
        ])
        .is_err());
    }

    #[test]
    fn reload_without_a_file_is_an_error() {
        let cfg = Config {
            gserver_port: 0,
            client_ports: vec![0],
            secure_login_key: PathBuf::new(),
            status_log_secs: 0,
            ..Config::default()
        };
        let run = start(cfg).unwrap();
        assert!(run.reload().is_err());
    }

    #[cfg(unix)]
    #[test]
    fn sighup_sets_a_reload_flag() {
        let flag = Arc::new(AtomicBool::new(false));
        signal_hook::flag::register(signal_hook::consts::SIGHUP, Arc::clone(&flag)).unwrap();
        // The handler only stores `true`. It does not stop the process.
        signal_hook::low_level::raise(signal_hook::consts::SIGHUP).unwrap();
        assert!(flag.load(Ordering::SeqCst));
    }
}
