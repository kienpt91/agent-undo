//! Environment policy for `run`: what the wrapped command gets to see.
//!
//! * `Inherit` (default): the parent environment unchanged.
//! * `Allow(names)`: only the listed variables, if set in the parent.
//!
//! In both modes the extra variables supplied by the caller (`AGENT_UNDO_*`)
//! are added last and override same-named parent variables.

use crate::error::{DomainError, DomainResult};
use crate::esc::display_str;

pub type EnvVar = (Vec<u8>, Vec<u8>);

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum EnvPolicy {
    Inherit,
    Allow(Vec<String>),
}

fn valid_name(n: &str) -> bool {
    let mut chars = n.chars();
    matches!(chars.next(), Some(c) if c.is_ascii_alphabetic() || c == '_')
        && chars.all(|c| c.is_ascii_alphanumeric() || c == '_')
}

impl EnvPolicy {
    /// Allow-list policy from comma-separated and/or repeated names.
    pub fn allow(names: &[String]) -> DomainResult<EnvPolicy> {
        let mut out: Vec<String> = Vec::new();
        for group in names {
            for n in group.split(',').map(str::trim).filter(|n| !n.is_empty()) {
                if !valid_name(n) {
                    return Err(DomainError::Usage(format!(
                        "invalid environment variable name {:?}",
                        display_str(n)
                    )));
                }
                if !out.iter().any(|x| x == n) {
                    out.push(n.to_string());
                }
            }
        }
        if out.is_empty() {
            return Err(DomainError::Usage(
                "--env-allow needs at least one variable name".into(),
            ));
        }
        Ok(EnvPolicy::Allow(out))
    }

    /// Builds the child environment from the parent's and the extra variables.
    pub fn child_env(&self, parent: &[EnvVar], extra: &[(&str, Vec<u8>)]) -> Vec<EnvVar> {
        let mut env: Vec<EnvVar> = match self {
            EnvPolicy::Inherit => parent.to_vec(),
            EnvPolicy::Allow(names) => parent
                .iter()
                .filter(|(k, _)| names.iter().any(|n| n.as_bytes() == k.as_slice()))
                .cloned()
                .collect(),
        };
        for (k, v) in extra {
            env.retain(|(ek, _)| ek.as_slice() != k.as_bytes());
            env.push((k.as_bytes().to_vec(), v.clone()));
        }
        env
    }
}

#[cfg(test)]
mod tests;
