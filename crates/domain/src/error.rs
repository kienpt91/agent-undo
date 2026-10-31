//! Errors raised by domain rules. They carry no IO details.

use std::fmt;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DomainError {
    /// A value object or aggregate was given data that violates an invariant.
    Invalid(String),
    /// Recorded history is inconsistent (broken hash chain, wrong sequence).
    Integrity(String),
    /// A request is valid but refused by a rule (for example pruning the newest checkpoint).
    Refused(String),
    /// The caller asked for something that does not exist or makes no sense.
    Usage(String),
    /// A size or count limit was exceeded.
    Limit(String),
    /// A path-safety rule was violated.
    Unsafe(String),
}

pub type DomainResult<T, E = DomainError> = Result<T, E>;

impl fmt::Display for DomainError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            DomainError::Invalid(m)
            | DomainError::Integrity(m)
            | DomainError::Refused(m)
            | DomainError::Usage(m)
            | DomainError::Limit(m)
            | DomainError::Unsafe(m) => f.write_str(m),
        }
    }
}

impl std::error::Error for DomainError {}
