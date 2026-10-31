//! seihai-listserver: command line.

use seihai_listserver::{accounts, config, log, Config};
use std::io::BufRead;
use std::path::{Path, PathBuf};
use std::process::exit;

const USAGE: &str = "\
usage:
  seihai-listserver [--config FILE]
      Run the listserver. Without --config, ./seihai-listserver.toml is read
      when it exists; otherwise every setting is at its default
      (127.0.0.1, open accounts).
  seihai-listserver add-account FILE ACCOUNT [--password-env VAR]
      Add ACCOUNT to the accounts file FILE (created when missing), or set a
      new password. The password is read from the environment variable VAR,
      or else as one line from standard input. Only an argon2 hash is stored.
  seihai-listserver sample-config
      Print a config file with every setting at its default.
  seihai-listserver --version";

fn main() {
    let args: Vec<String> = std::env::args().skip(1).collect();
    match args.first().map(String::as_str) {
        Some("--version" | "-V") => println!("seihai-listserver {}", env!("CARGO_PKG_VERSION")),
        Some("--help" | "-h") => println!("{USAGE}"),
        Some("sample-config") => print!("{}", config::SAMPLE),
        Some("add-account") => add_account(&args[1..]),
        Some("--config") if args.len() == 2 => run(Some(Path::new(&args[1]))),
        None => run(None),
        _ => {
            eprintln!("{USAGE}");
            exit(2);
        }
    }
}

fn run(path: Option<&Path>) {
    let default = PathBuf::from("seihai-listserver.toml");
    let path = path.or_else(|| default.exists().then_some(default.as_path()));
    let cfg = match path {
        Some(p) => Config::load(p).unwrap_or_else(|e| fail(&e)),
        None => Config::default(),
    };
    if !cfg.log_file.as_os_str().is_empty() {
        if let Err(e) = log::open(&cfg.log_file) {
            fail(&format!("{}: {e}", cfg.log_file.display()));
        }
    }
    log::line(&format!(
        "seihai-listserver {} starting, config {}",
        env!("CARGO_PKG_VERSION"),
        path.map_or("(defaults)".into(), |p| p.display().to_string())
    ));
    if let Err(e) = seihai_listserver::start(cfg) {
        fail(&e);
    }
    loop {
        std::thread::park();
    }
}

fn add_account(args: &[String]) {
    let (file, account, env) = match args {
        [f, a] => (f, a, None),
        [f, a, flag, v] if flag == "--password-env" => (f, a, Some(v)),
        _ => {
            eprintln!("{USAGE}");
            exit(2);
        }
    };
    let password = match env {
        Some(var) => std::env::var(var).unwrap_or_else(|_| fail(&format!("{var} is not set"))),
        None => {
            eprintln!("password for {account}:");
            let mut line = String::new();
            std::io::stdin()
                .lock()
                .read_line(&mut line)
                .unwrap_or_else(|e| fail(&e.to_string()));
            line.trim_end_matches(['\r', '\n']).to_string()
        }
    };
    match accounts::add_account(Path::new(file), account, password.as_bytes()) {
        Ok(true) => println!("{account}: new password set in {file}"),
        Ok(false) => println!("{account}: added to {file}"),
        Err(e) => fail(&e),
    }
}

fn fail(msg: &str) -> ! {
    eprintln!("seihai-listserver: {msg}");
    exit(1);
}
