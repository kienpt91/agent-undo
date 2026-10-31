//! Infrastructure adapters: filesystem, process and clock implementations of
//! the application ports. Depends on the domain and application crates only.
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

pub mod codec;
pub mod fs_blobs;
pub mod fsutil;
pub mod layout;
pub mod lock;
