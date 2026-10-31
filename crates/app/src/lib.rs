//! Application layer: use cases and ports. Depends only on the domain crate.
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

pub mod error;
pub mod events;
pub mod fakes;
pub mod ports;
pub mod usecases;
