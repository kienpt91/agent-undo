//! Redaction of text that is persisted in the journal (command lines, labels).
//!
//! The journal is append-only and printed by `log`, `diff` and `run --json`, so a
//! secret passed as a command-line argument would otherwise live in the store
//! forever. Arguments are checked with the same detectors that protect file
//! content, plus argv-specific shapes (`--password VALUE`, `--token=VALUE`,
//! `NAME=value` environment assignments, HTTP credential headers).
//!
//! This is heuristic like the content detectors: an argument that looks like a
//! plain word is kept. `run --no-log-args` records no arguments at all.

use crate::secrets::scan_bytes;

pub const REDACTED: &str = "[redacted]";

/// Substrings of flag names whose value is a secret.
const SECRET_FLAG_PARTS: &[&str] = &[
    "password",
    "passwd",
    "passphrase",
    "secret",
    "token",
    "api-key",
    "api_key",
    "apikey",
    "auth",
    "credential",
    "private-key",
    "private_key",
    "access-key",
    "access_key",
];

const SECRET_HEADERS: &[&str] = &[
    "authorization:",
    "proxy-authorization:",
    "x-api-key:",
    "x-auth-token:",
    "cookie:",
    "set-cookie:",
];

fn secret_flag(flag: &[u8]) -> bool {
    if !flag.starts_with(b"-") {
        return false;
    }
    let dashes = flag.iter().take_while(|b| **b == b'-').count();
    let name = flag.get(dashes..).unwrap_or(&[]).to_ascii_lowercase();
    !name.is_empty()
        && SECRET_FLAG_PARTS
            .iter()
            .any(|p| name.windows(p.len()).any(|w| w == p.as_bytes()))
}

fn redacted(prefix: &[u8]) -> Vec<u8> {
    let mut v = prefix.to_vec();
    v.extend_from_slice(REDACTED.as_bytes());
    v
}

/// Redacts one argument on its own (without looking at its neighbours).
fn redact_one(arg: &[u8]) -> Vec<u8> {
    let lower = arg.to_ascii_lowercase();
    for h in SECRET_HEADERS {
        if lower.starts_with(h.as_bytes()) {
            let mut keep = arg.get(..h.len()).unwrap_or(&[]).to_vec();
            keep.push(b' ');
            return redacted(&keep);
        }
    }
    if arg.starts_with(b"-")
        && let Some(eq) = arg.iter().position(|b| *b == b'=')
        && secret_flag(arg.get(..eq).unwrap_or(&[]))
    {
        return redacted(arg.get(..=eq).unwrap_or(&[]));
    }
    // NAME=value: a secret value (detectors, or a secret-named variable)
    if let Some(eq) = arg.iter().position(|b| *b == b'=')
        && eq > 0
        && !arg.starts_with(b"-")
        && scan_bytes(arg).is_some()
    {
        return redacted(arg.get(..=eq).unwrap_or(&[]));
    }
    if scan_bytes(arg).is_some() {
        return REDACTED.as_bytes().to_vec();
    }
    arg.to_vec()
}

/// Redacts a command line. The result has the same number of arguments.
pub fn redact_args(args: &[Vec<u8>]) -> Vec<Vec<u8>> {
    let mut out = Vec::with_capacity(args.len());
    let mut redact_next = false;
    for a in args {
        if redact_next {
            redact_next = false;
            if !a.starts_with(b"-") {
                out.push(REDACTED.as_bytes().to_vec());
                continue;
            }
        }
        let has_eq = a.contains(&b'=');
        if a.starts_with(b"-") && !has_eq && secret_flag(a) {
            redact_next = true;
            out.push(a.clone());
            continue;
        }
        out.push(redact_one(a));
    }
    out
}

/// A label that matches the secret detectors is replaced as a whole.
pub fn redact_label(label: &[u8]) -> Vec<u8> {
    if scan_bytes(label).is_some() {
        REDACTED.as_bytes().to_vec()
    } else {
        label.to_vec()
    }
}

#[cfg(test)]
mod tests;
