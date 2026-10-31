# Development image: the official Rust 1.95 image pinned by digest, plus the
# components the project's checks need. No third-party Rust crates are involved.
FROM rust@sha256:d7482085ff5b415f84dba5647ae71606650bdef00db7aeb69f4b3d170c3e4082
RUN rustup component add clippy rustfmt llvm-tools-preview
