//! Application-level errors and the documented process exit codes.

use agent_undo_domain::error::DomainError;
use std::fmt;

/// Exit codes of the `agent-undo` binary (except `run`, which passes the child's
/// exit status through; see the README).
pub mod exit {
    pub const OK: i32 = 0;
    /// Any other runtime failure.
    pub const FAILURE: i32 = 1;
    /// Command line usage error.
    pub const USAGE: i32 = 2;
    /// `undo`/`restore` refused: conflicts or blocked paths, nothing was changed.
    pub const REFUSED: i32 = 3;
    /// Another agent-undo operation holds the store lock.
    pub const LOCKED: i32 = 4;
    /// `verify`/`doctor` found integrity problems.
    pub const INTEGRITY: i32 = 5;
    /// No store for this project (run `agent-undo init`).
    pub const NOT_INITIALIZED: i32 = 6;
    /// `run` only: agent-undo itself failed (like `timeout`/`env` use 125).
    pub const RUN_INTERNAL: i32 = 125;
    /// `run` only: the command was found but could not be executed.
    pub const RUN_CANNOT_EXEC: i32 = 126;
    /// `run` only: the command was not found.
    pub const RUN_NOT_FOUND: i32 = 127;
}

#[derive(Debug)]
pub enum Error {
    /// An IO failure reported by an adapter.
    Io {
        ctx: String,
        source: std::io::Error,
    },
    /// Store data is malformed.
    Format(String),
    NotInitialized(String),
    AlreadyInitialized(String),
    Locked(String),
    Usage(String),
    Integrity(String),
    /// A plan was refused (conflicts, blocked paths).
    Refused(String),
    /// A path-safety rule was violated (traversal, symlink, outside root).
    Unsafe(String),
    /// A size or count limit was exceeded.
    Limit(String),
    Other(String),
}

pub type Result<T, E = Error> = std::result::Result<T, E>;

impl Error {
    pub fn io(ctx: impl Into<String>, source: std::io::Error) -> Error {
        Error::Io {
            ctx: ctx.into(),
            source,
        }
    }

    pub fn exit_code(&self) -> i32 {
        match self {
            Error::Usage(_) => exit::USAGE,
            Error::Refused(_) => exit::REFUSED,
            Error::Locked(_) => exit::LOCKED,
            Error::Integrity(_) => exit::INTEGRITY,
            Error::NotInitialized(_) => exit::NOT_INITIALIZED,
            _ => exit::FAILURE,
        }
    }

    /// Stable machine-readable error code used in `--json` output.
    pub fn code(&self) -> &'static str {
        match self {
            Error::Io { .. } => "io",
            Error::Format(_) => "format",
            Error::NotInitialized(_) => "not_initialized",
            Error::AlreadyInitialized(_) => "already_initialized",
            Error::Locked(_) => "locked",
            Error::Usage(_) => "usage",
            Error::Integrity(_) => "integrity",
            Error::Refused(_) => "refused",
            Error::Unsafe(_) => "unsafe_path",
            Error::Limit(_) => "limit",
            Error::Other(_) => "error",
        }
    }
}

impl From<DomainError> for Error {
    fn from(e: DomainError) -> Error {
        match e {
            DomainError::Invalid(m) => Error::Format(m),
            DomainError::Integrity(m) => Error::Integrity(m),
            DomainError::Refused(m) => Error::Refused(m),
            DomainError::Usage(m) => Error::Usage(m),
            DomainError::Limit(m) => Error::Limit(m),
            DomainError::Unsafe(m) => Error::Unsafe(m),
        }
    }
}

impl From<std::convert::Infallible> for Error {
    fn from(e: std::convert::Infallible) -> Error {
        match e {}
    }
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Error::Io { ctx, source } => write!(f, "{ctx}: {source}"),
            Error::Format(m)
            | Error::NotInitialized(m)
            | Error::AlreadyInitialized(m)
            | Error::Locked(m)
            | Error::Usage(m)
            | Error::Integrity(m)
            | Error::Refused(m)
            | Error::Unsafe(m)
            | Error::Limit(m)
            | Error::Other(m) => f.write_str(m),
        }
    }
}

impl std::error::Error for Error {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Error::Io { source, .. } => Some(source),
            _ => None,
        }
    }
}

/// Adds context to `io::Result`s (used by adapters).
pub trait Ctx<T> {
    fn ctx(self, what: impl FnOnce() -> String) -> Result<T>;
}

impl<T> Ctx<T> for std::io::Result<T> {
    fn ctx(self, what: impl FnOnce() -> String) -> Result<T> {
        self.map_err(|e| Error::io(what(), e))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn exit_codes_per_class() {
        let cases = [
            (Error::Usage("x".into()), exit::USAGE),
            (Error::Refused("x".into()), exit::REFUSED),
            (Error::Locked("x".into()), exit::LOCKED),
            (Error::Integrity("x".into()), exit::INTEGRITY),
            (Error::NotInitialized("x".into()), exit::NOT_INITIALIZED),
            (Error::Other("x".into()), exit::FAILURE),
            (Error::Limit("x".into()), exit::FAILURE),
        ];
        for (e, c) in cases {
            assert_eq!(e.exit_code(), c);
        }
    }

    #[test]
    fn domain_errors_map_to_matching_classes() {
        assert_eq!(Error::from(DomainError::Usage("u".into())).code(), "usage");
        assert_eq!(
            Error::from(DomainError::Integrity("i".into())).code(),
            "integrity"
        );
        assert_eq!(
            Error::from(DomainError::Refused("r".into())).code(),
            "refused"
        );
        assert_eq!(
            Error::from(DomainError::Unsafe("s".into())).code(),
            "unsafe_path"
        );
        assert_eq!(Error::from(DomainError::Limit("l".into())).code(), "limit");
        assert_eq!(
            Error::from(DomainError::Invalid("v".into())).code(),
            "format"
        );
    }

    #[test]
    fn io_error_display_includes_context_and_codes_are_stable() {
        let e = Error::io("reading x", std::io::Error::other("boom"));
        assert_eq!(e.to_string(), "reading x: boom");
        assert_eq!(e.code(), "io");
        assert!(std::error::Error::source(&e).is_some());
        let codes = [
            Error::Format(String::new()).code(),
            Error::NotInitialized(String::new()).code(),
            Error::AlreadyInitialized(String::new()).code(),
            Error::Other(String::new()).code(),
        ];
        assert_eq!(
            codes,
            ["format", "not_initialized", "already_initialized", "error"]
        );
    }

    #[test]
    fn ctx_wraps_io_errors() {
        let r: std::io::Result<()> = Err(std::io::Error::other("nope"));
        let e = r.ctx(|| "doing a thing".into()).unwrap_err();
        assert_eq!(e.to_string(), "doing a thing: nope");
    }
}
