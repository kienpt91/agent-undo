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
mod tests {
    use super::*;

    fn parent() -> Vec<EnvVar> {
        vec![
            (b"PATH".to_vec(), b"/usr/bin".to_vec()),
            (b"HOME".to_vec(), b"/home/u".to_vec()),
            (b"SECRET_TOKEN".to_vec(), b"hunter2".to_vec()),
        ]
    }

    fn get<'a>(env: &'a [EnvVar], k: &str) -> Option<&'a [u8]> {
        env.iter()
            .find(|(n, _)| n == k.as_bytes())
            .map(|(_, v)| v.as_slice())
    }

    #[test]
    fn inherit_keeps_everything() {
        let env = EnvPolicy::Inherit.child_env(&parent(), &[]);
        assert_eq!(env.len(), 3);
    }

    #[test]
    fn allow_list_filters_and_ignores_missing() {
        let p = EnvPolicy::allow(&["PATH,MISSING".to_string(), "HOME".to_string()]).unwrap();
        let env = p.child_env(&parent(), &[]);
        assert_eq!(get(&env, "PATH"), Some(&b"/usr/bin"[..]));
        assert_eq!(get(&env, "HOME"), Some(&b"/home/u"[..]));
        assert_eq!(
            get(&env, "SECRET_TOKEN"),
            None,
            "unlisted variables are dropped"
        );
        assert_eq!(get(&env, "MISSING"), None);
    }

    #[test]
    fn extras_are_added_and_override() {
        let env = EnvPolicy::Inherit.child_env(
            &parent(),
            &[
                ("HOME", b"/x".to_vec()),
                ("AGENT_UNDO_ACTIVE", b"1".to_vec()),
            ],
        );
        assert_eq!(get(&env, "HOME"), Some(&b"/x"[..]));
        assert_eq!(get(&env, "AGENT_UNDO_ACTIVE"), Some(&b"1"[..]));
        assert_eq!(env.iter().filter(|(k, _)| k == b"HOME").count(), 1);
        let p = EnvPolicy::allow(&["PATH".to_string()]).unwrap();
        let env = p.child_env(&parent(), &[("AGENT_UNDO_ACTIVE", b"1".to_vec())]);
        assert_eq!(env.len(), 2);
    }

    #[test]
    fn allow_rejects_bad_and_empty_names() {
        assert!(EnvPolicy::allow(&[]).is_err());
        assert!(EnvPolicy::allow(&[",,".to_string()]).is_err());
        assert!(EnvPolicy::allow(&["1BAD".to_string()]).is_err());
        assert!(EnvPolicy::allow(&["A=B".to_string()]).is_err());
        assert!(EnvPolicy::allow(&["A B".to_string()]).is_err());
    }

    #[test]
    fn allow_deduplicates_names() {
        let p = EnvPolicy::allow(&["A,B,A".to_string(), "B".to_string()]).unwrap();
        assert_eq!(p, EnvPolicy::Allow(vec!["A".into(), "B".into()]));
    }
}
