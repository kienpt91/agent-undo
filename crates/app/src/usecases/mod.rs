//! Use cases (command handlers). Each acquires the lock it needs, loads the
//! journal aggregate, orchestrates ports and publishes events.

pub mod checkpoint;
pub mod gc;
pub mod history;
pub mod init;
pub mod record;
pub mod reversal;
pub mod run;
pub mod status;
pub mod verify;
pub mod watch;
