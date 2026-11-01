//! Listening sockets and one thread per link.

use crate::accounts::Accounts;
use crate::config::Config;
use crate::state::Servers;
use seihai_core::protocol::seclogin::{self, ServerIdentity};
use std::io;
use std::net::{SocketAddr, TcpListener, TcpStream};
use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
use std::sync::Arc;

/// What every link thread shares.
pub struct Shared {
    pub config: Config,
    pub accounts: Accounts,
    pub servers: Servers,
    /// This listserver's secure-login key; `None` when secure logins are off.
    pub identity: Option<ServerIdentity>,
    open: AtomicUsize,
    next_id: AtomicU64,
}

/// A started listserver.
pub struct Running {
    /// Where gservers register.
    pub gserver_addr: SocketAddr,
    /// Where clients ask for the list, in `client_ports` order.
    pub client_addrs: Vec<SocketAddr>,
    pub shared: Arc<Shared>,
}

/// Bind every port and start accepting links in background threads.
/// A port of 0 picks a free one (for tests).
pub fn start(config: Config) -> Result<Running, String> {
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

    let shared = Arc::new(Shared {
        config,
        accounts,
        servers: Servers::default(),
        identity,
        open: AtomicUsize::new(0),
        next_id: AtomicU64::new(1),
    });
    log!(
        "listening on {gserver_addr} for gservers and {} for clients; accounts: {}",
        client_addrs
            .iter()
            .map(|a| a.to_string())
            .collect::<Vec<_>>()
            .join(", "),
        shared.accounts.describe()
    );
    if shared.config.gservers.is_empty() {
        log!("gserver allow-list: off");
    } else {
        log!(
            "gserver allow-list: {} entries",
            shared.config.gservers.len()
        );
    }

    spawn_accept(gserver, shared.clone(), |s, id, _port, shared| {
        crate::gserver::serve(s, id, shared)
    });
    for l in clients {
        spawn_accept(l, shared.clone(), crate::client::serve);
    }
    Ok(Running {
        gserver_addr,
        client_addrs,
        shared,
    })
}

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
            if shared.open.fetch_add(1, Ordering::SeqCst) >= shared.config.max_connections {
                shared.open.fetch_sub(1, Ordering::SeqCst);
                log!(
                    "refused a link on {port}: {} links already open",
                    shared.config.max_connections
                );
                continue;
            }
            let id = shared.next_id.fetch_add(1, Ordering::Relaxed);
            let link = shared.clone();
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
