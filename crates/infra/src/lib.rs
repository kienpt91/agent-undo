//! agent-undo: a tool-agnostic flight recorder and undo for what coding agents
//! do to a project directory.
#![forbid(unsafe_code)]
#![cfg_attr(
    not(test),
    deny(
        clippy::unwrap_used,
        clippy::expect_used,
        clippy::indexing_slicing,
        clippy::panic
    )
)]

pub mod entry;
pub mod error;
pub mod fsops;
pub mod json;
pub mod paths;
pub mod store;
pub mod util;
