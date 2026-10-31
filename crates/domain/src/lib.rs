//! Pure domain model of agent-undo.
//!
//! Nothing in this crate performs IO, reads a clock, draws randomness or touches
//! the filesystem, a process or a network. Time and identifiers are passed in by
//! callers (the application layer gets them from ports). The crate has no
//! dependencies beyond `std`.
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

pub mod esc;
pub mod hash;
pub mod ignore;
pub mod secrets;

pub mod change;
pub mod diff;
pub mod entry;
pub mod env;
pub mod error;
pub mod journal;
pub mod path;
pub mod plan;
pub mod policy;
pub mod units;
pub mod watch;
