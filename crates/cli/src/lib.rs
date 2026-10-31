//! Command-line front end of agent-undo (argument parsing, rendering, command
//! handlers). The binary in `main.rs` only forwards `std::env::args_os`.
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

pub mod args;
pub mod json;
pub mod render;
