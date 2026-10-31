//! seihai-listserver: a Graal listserver for classic clients (2.00 to 2.31,
//! 3.x), Seihai and RCs. Gservers register with it and check accounts.
//!
//! Written from the Seihai protocol notes and the lab listserver v2
//! (`docs/reference/listserver.py`); no code from GServer-v2, gs2lib,
//! gs2-parser or graal-listserver.

#[macro_use]
pub mod log;
pub mod accounts;
pub mod client;
pub mod config;
pub mod gserver;
pub mod server;
pub mod state;
pub mod wire;

pub use config::Config;
pub use server::{start, Running};
