//! Secret detection: sensitive file names and a streaming content scanner.
//!
//! The store must never become a second copy of the user's secrets, so every
//! file is classified before its bytes are written anywhere:
//!
//! 1. [`sensitive_name`] flags well-known secret-bearing names (`.env*`, `*.pem`,
//!    `id_rsa*`, `.npmrc`, files below `.ssh/` or `.aws/`, ...).
//! 2. [`Scanner`] streams over the content with a fixed-size overlap window and
//!    flags private key blocks, common API key shapes, JWTs, credentials embedded
//!    in URLs, and high-entropy values assigned to secret-like names.
//!
//! These are heuristics. They reduce the chance of copying secrets into the
//! store; they do not guarantee it. Anything they miss is stored like any other
//! file, which is why the default store location is outside the project, with
//! `0700`/`0600` permissions.

/// Bytes of each line tail carried between chunks, so a token split across a
/// chunk boundary is still seen. Tokens longer than this may be missed.
pub const OVERLAP: usize = 4096;
const MAX_VALUE_SCAN: usize = 512;

fn lower(b: u8) -> u8 {
    b.to_ascii_lowercase()
}

fn ends_with_ci(name: &[u8], suffix: &[u8]) -> bool {
    name.len() >= suffix.len()
        && name
            .get(name.len() - suffix.len()..)
            .is_some_and(|t| t.eq_ignore_ascii_case(suffix))
}

fn starts_with_ci(name: &[u8], prefix: &[u8]) -> bool {
    name.get(..prefix.len())
        .is_some_and(|h| h.eq_ignore_ascii_case(prefix))
}

fn eq_ci(a: &[u8], b: &[u8]) -> bool {
    a.eq_ignore_ascii_case(b)
}

const SENSITIVE_DIRS: &[&[u8]] = &[
    b".aws",
    b".ssh",
    b".gnupg",
    b".kube",
    b".azure",
    b".docker",
    b".gcloud",
    b".password-store",
];

const SENSITIVE_EXACT: &[&[u8]] = &[
    b".npmrc",
    b".netrc",
    b"_netrc",
    b".pypirc",
    b".git-credentials",
    b".pgpass",
    b".htpasswd",
    b".dockercfg",
    b".s3cfg",
    b"credentials",
    b"terraform.tfstate",
    b"terraform.tfvars",
    b".vault-token",
    b".boto",
    b"kubeconfig",
    b".bash_history",
    b".zsh_history",
    b".psql_history",
    b".mysql_history",
    b".dockerconfigjson",
    b"wallet.dat",
];

const SENSITIVE_SUFFIXES: &[(&[u8], &str)] = &[
    (b".pem", "PEM file"),
    (b".key", "key file"),
    (b".p12", "PKCS#12 keystore"),
    (b".pfx", "PKCS#12 keystore"),
    (b".jks", "Java keystore"),
    (b".jceks", "Java keystore"),
    (b".keystore", "keystore"),
    (b".kdbx", "password database"),
    (b".ppk", "PuTTY private key"),
    (b".tfstate", "Terraform state"),
    (b".tfvars", "Terraform variables"),
    (b".p8", "private key (PKCS#8)"),
    (b".gpg", "GPG key or encrypted file"),
    (b".pgp", "PGP key or encrypted file"),
    (b".kubeconfig", "Kubernetes credentials"),
    (b".secret", "secret file"),
    (b".secrets", "secret file"),
    (b"_credentials", "credentials file"),
    (b"-credentials", "credentials file"),
];

const SENSITIVE_PREFIXES: &[(&[u8], &str)] = &[
    (b".env", "dotenv file"),
    (b"id_rsa", "SSH private key"),
    (b"id_ed25519", "SSH private key"),
    (b"id_ecdsa", "SSH private key"),
    (b"id_dsa", "SSH private key"),
    (b"credentials.", "credentials file"),
    (b"client_secret", "OAuth client secret file"),
    (b"secrets.", "secrets file"),
    (b"secret.", "secrets file"),
    (b"service-account", "service account file"),
    (b"service_account", "service account file"),
];

/// Returns a short reason if the path (relative, `/`-separated) names a file
/// that is treated as sensitive by name alone. Directory components such as
/// `.ssh` or `.aws` make everything below them sensitive.
pub fn sensitive_name(rel: &[u8]) -> Option<&'static str> {
    let comps: Vec<&[u8]> = rel
        .split(|&b| b == b'/')
        .filter(|c| !c.is_empty())
        .collect();
    let (name, parents) = comps.split_last()?;
    for dir in parents {
        if SENSITIVE_DIRS.iter().any(|d| eq_ci(dir, d)) {
            return Some("inside a credentials directory");
        }
    }
    sensitive_component_name(name)
}

/// The same name rules applied to a single file name (no directory context).
pub fn sensitive_component_name(name: &[u8]) -> Option<&'static str> {
    if SENSITIVE_EXACT.iter().any(|e| eq_ci(name, e)) {
        return Some("well-known credentials file");
    }
    for (p, why) in SENSITIVE_PREFIXES {
        if starts_with_ci(name, p) {
            return Some(why);
        }
    }
    for (s, why) in SENSITIVE_SUFFIXES {
        if ends_with_ci(name, s) {
            return Some(why);
        }
    }
    if starts_with_ci(name, b"service")
        && ends_with_ci(name, b".json")
        && name.windows(7).any(|w| w.eq_ignore_ascii_case(b"account"))
    {
        return Some("service account file");
    }
    None
}

/// Shannon entropy in bits per byte.
pub fn shannon_entropy(data: &[u8]) -> f64 {
    if data.is_empty() {
        return 0.0;
    }
    let mut counts = [0u32; 256];
    for &b in data {
        if let Some(c) = counts.get_mut(usize::from(b)) {
            *c += 1;
        }
    }
    let n = data.len() as f64;
    counts
        .iter()
        .filter(|&&c| c > 0)
        .map(|&c| {
            let p = f64::from(c) / n;
            -p * p.log2()
        })
        .sum()
}

fn find(hay: &[u8], needle: &[u8], from: usize) -> Option<usize> {
    let first = *needle.first()?;
    let mut i = from;
    while i < hay.len() {
        let off = hay.get(i..)?.iter().position(|&b| b == first)?;
        let start = i + off;
        if hay.get(start..start + needle.len()) == Some(needle) {
            return Some(start);
        }
        i = start + 1;
    }
    None
}

fn find_ci(hay: &[u8], needle_lower: &[u8], from: usize) -> Option<usize> {
    let first = *needle_lower.first()?;
    let mut i = from;
    while i < hay.len() {
        let off = hay.get(i..)?.iter().position(|&b| lower(b) == first)?;
        let start = i + off;
        if hay
            .get(start..start + needle_lower.len())
            .is_some_and(|w| w.eq_ignore_ascii_case(needle_lower))
        {
            return Some(start);
        }
        i = start + 1;
    }
    None
}

fn has_private_key_header(buf: &[u8]) -> bool {
    let mut from = 0;
    while let Some(p) = find(buf, b"-----BEGIN ", from) {
        let start = p + 11;
        let window = buf.get(start..(start + 48).min(buf.len())).unwrap_or(&[]);
        if find(window, b"PRIVATE KEY", 0).is_some() {
            return true;
        }
        from = start;
    }
    false
}

fn is_token_byte(b: u8) -> bool {
    b.is_ascii_alphanumeric() || matches!(b, b'_' | b'-' | b'.')
}

fn all_alnum(s: &[u8]) -> bool {
    s.iter().all(u8::is_ascii_alphanumeric)
}

fn all_b64url(s: &[u8]) -> bool {
    s.iter()
        .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'_' | b'-'))
}

fn rest_after<'a>(tok: &'a [u8], prefix: &[u8]) -> Option<&'a [u8]> {
    tok.strip_prefix(prefix)
}

fn token_rule(tok: &[u8]) -> Option<&'static str> {
    if tok.len() < 16 {
        return None;
    }
    // AWS access key ids.
    for p in [
        &b"AKIA"[..],
        b"ASIA",
        b"ABIA",
        b"ACCA",
        b"AGPA",
        b"AIDA",
        b"AIPA",
        b"ANPA",
        b"ANVA",
        b"AROA",
    ] {
        if let Some(r) = rest_after(tok, p)
            && r.len() == 16
            && r.iter()
                .all(|b| b.is_ascii_uppercase() || b.is_ascii_digit())
        {
            return Some("AWS access key id");
        }
    }
    for p in [&b"ghp_"[..], b"gho_", b"ghu_", b"ghs_", b"ghr_"] {
        if let Some(r) = rest_after(tok, p)
            && r.len() >= 36
            && all_alnum(r)
        {
            return Some("GitHub token");
        }
    }
    if let Some(r) = rest_after(tok, b"github_pat_")
        && r.len() >= 22
        && all_b64url(r)
    {
        return Some("GitHub fine-grained token");
    }
    for p in [&b"xoxa-"[..], b"xoxb-", b"xoxp-", b"xoxr-", b"xoxs-"] {
        if let Some(r) = rest_after(tok, p)
            && r.len() >= 10
        {
            return Some("Slack token");
        }
    }
    for p in [&b"sk_live_"[..], b"rk_live_", b"sk_test_", b"rk_test_"] {
        if let Some(r) = rest_after(tok, p)
            && r.len() >= 16
            && all_alnum(r)
        {
            return Some("Stripe key");
        }
    }
    if let Some(r) = rest_after(tok, b"whsec_")
        && r.len() >= 16
        && all_alnum(r)
    {
        return Some("Stripe webhook secret");
    }
    if let Some(r) = rest_after(tok, b"sk-")
        && r.len() >= 32
        && all_b64url(r)
        && r.iter().any(u8::is_ascii_digit)
        && shannon_entropy(r) >= 3.0
    {
        return Some("API secret key (sk-...)");
    }
    if let Some(r) = rest_after(tok, b"AIza")
        && r.len() == 35
        && all_b64url(r)
    {
        return Some("Google API key");
    }
    if let Some(r) = rest_after(tok, b"npm_")
        && r.len() == 36
        && all_alnum(r)
    {
        return Some("npm token");
    }
    if let Some(r) = rest_after(tok, b"glpat-")
        && r.len() >= 20
        && all_b64url(r)
    {
        return Some("GitLab token");
    }
    if let Some(r) = rest_after(tok, b"AGE-SECRET-KEY-1")
        && r.len() >= 58
    {
        return Some("age secret key");
    }
    let mut parts = tok.split(|&b| b == b'.');
    if let (Some(a), Some(b), Some(c), None) =
        (parts.next(), parts.next(), parts.next(), parts.next())
    {
        if a == b"SG" && b.len() == 22 && c.len() == 43 && all_b64url(b) && all_b64url(c) {
            return Some("SendGrid key");
        }
        if a.starts_with(b"eyJ")
            && b.starts_with(b"eyJ")
            && a.len() >= 8
            && b.len() >= 8
            && c.len() >= 8
            && all_b64url(a)
            && all_b64url(b)
            && all_b64url(c)
        {
            return Some("JSON Web Token");
        }
    }
    None
}

const KEYWORDS: &[&[u8]] = &[
    b"secret",
    b"password",
    b"passwd",
    b"token",
    b"apikey",
    b"api_key",
    b"api-key",
    b"private_key",
    b"privatekey",
    b"access_key",
    b"accesskey",
    b"credential",
    b"signing_key",
    b"encryption_key",
    b"master_key",
    b"bearer",
];

fn is_value_byte(b: u8) -> bool {
    b.is_ascii_alphanumeric() || matches!(b, b'+' | b'/' | b'_' | b'-' | b'=' | b'.')
}

fn looks_like_secret_value(v: &[u8]) -> bool {
    let v = {
        let mut end = v.len();
        while end > 0 && matches!(v.get(end - 1), Some(b'.') | Some(b'=')) && end > 20 {
            end -= 1;
        }
        v.get(..end).unwrap_or(v)
    };
    if v.len() < 20 {
        return false;
    }
    let has_lower = v.iter().any(u8::is_ascii_lowercase);
    let has_upper = v.iter().any(u8::is_ascii_uppercase);
    let has_digit = v.iter().any(u8::is_ascii_digit);
    let classes = usize::from(has_lower) + usize::from(has_upper) + usize::from(has_digit);
    has_digit && classes >= 2 && shannon_entropy(v) >= 3.5
}

fn assignment_value_is_secret(line: &[u8], mut i: usize, bearer: bool) -> bool {
    if !bearer {
        while line
            .get(i)
            .is_some_and(|&b| b.is_ascii_alphanumeric() || matches!(b, b'_' | b'-'))
        {
            i += 1;
        }
    }
    let mut skipped_ws = false;
    while let Some(&b) = line.get(i) {
        match b {
            b' ' | b'\t' => skipped_ws = true,
            b'"' | b'\'' | b'`' => {}
            _ => break,
        }
        i += 1;
    }
    if bearer {
        if !skipped_ws {
            return false;
        }
    } else {
        match line.get(i) {
            Some(b'=') | Some(b':') => i += 1,
            _ => return false,
        }
        if matches!(line.get(i), Some(b'=') | Some(b'>')) {
            i += 1;
        }
    }
    while line
        .get(i)
        .is_some_and(|&b| matches!(b, b' ' | b'\t' | b'"' | b'\'' | b'`'))
    {
        i += 1;
    }
    let rest = line.get(i..).unwrap_or(&[]);
    let n = rest
        .iter()
        .take(MAX_VALUE_SCAN)
        .take_while(|&&b| is_value_byte(b))
        .count();
    rest.get(..n).is_some_and(looks_like_secret_value)
}

const DOTENV_NAME_PARTS: &[&[u8]] = &[
    b"SECRET",
    b"PASSWORD",
    b"PASSWD",
    b"TOKEN",
    b"API_KEY",
    b"APIKEY",
    b"PRIVATE_KEY",
    b"ACCESS_KEY",
    b"CREDENTIAL",
    b"SIGNING_KEY",
    b"ENCRYPTION_KEY",
    b"MASTER_KEY",
];

/// Variable-name endings that describe where a secret lives or what it is called,
/// not the secret itself (`PASSWORD_FILE`, `TOKEN_URL`, `ACCESS_KEY_ID`, ...).
const DOTENV_NAME_NON_SECRET_ENDINGS: &[&[u8]] = &[
    b"_FILE", b"_PATH", b"_URL", b"_URI", b"_NAME", b"_HEADER", b"_ENV", b"_FIELD", b"_LABEL",
    b"_TYPE", b"_LENGTH", b"_TTL", b"_EXPIRY", b"_ID", b"_DIR", b"_HOST", b"_PORT",
];

fn contains_sub(hay: &[u8], needle: &[u8]) -> bool {
    hay.windows(needle.len()).any(|w| w == needle)
}

/// Whether `text` (one token of a command line, a config line, ...) is a
/// `NAME=value` assignment of a secret-named variable; see [`dotenv_secret_line`].
pub fn is_secret_assignment(text: &[u8]) -> bool {
    dotenv_secret_line(text)
}

/// `NAME=value` with an UPPER_SNAKE name that names a secret and a plausible
/// literal value (6..=256 bytes, no whitespace, not a variable reference, a path,
/// a URL without credentials or another variable's name). Unlike the entropy rule
/// this also catches typical low-entropy passwords such as `DB_PASSWORD=hunter2`.
fn dotenv_secret_line(line: &[u8]) -> bool {
    let mut l = line.trim_ascii_start();
    if let Some(rest) = l.strip_prefix(b"export ") {
        l = rest.trim_ascii_start();
    }
    let name_len = l
        .iter()
        .take_while(|b| b.is_ascii_uppercase() || b.is_ascii_digit() || **b == b'_')
        .count();
    let (name, rest) = l.split_at(name_len);
    if name.len() < 3
        || !name
            .first()
            .is_some_and(|b| b.is_ascii_uppercase() || *b == b'_')
    {
        return false;
    }
    if !DOTENV_NAME_PARTS.iter().any(|p| contains_sub(name, p)) {
        return false;
    }
    if DOTENV_NAME_NON_SECRET_ENDINGS
        .iter()
        .any(|e| name.ends_with(e))
    {
        return false;
    }
    let rest = rest.trim_ascii_start();
    let Some(value) = rest.strip_prefix(b"=") else {
        return false;
    };
    let mut v = value.trim_ascii();
    if let Some(q) = v
        .first()
        .copied()
        .filter(|b| matches!(b, b'"' | b'\'' | b'`'))
        && v.len() >= 2
        && v.last() == Some(&q)
    {
        v = v.get(1..v.len() - 1).unwrap_or(v);
    }
    if !(6..=256).contains(&v.len()) || v.iter().any(u8::is_ascii_whitespace) {
        return false;
    }
    if matches!(
        v.first(),
        Some(b'$' | b'{' | b'<' | b'%' | b'(' | b'*' | b'/' | b'.' | b'#')
    ) {
        return false;
    }
    let lower = v.to_ascii_lowercase();
    if lower.starts_with(b"http://") || lower.starts_with(b"https://") {
        return false;
    }
    // A redaction marker (redaction is idempotent) or another variable's name.
    v != b"[redacted]" && !v.iter().all(|b| b.is_ascii_uppercase() || *b == b'_')
}

fn assignment_secret(line: &[u8]) -> bool {
    for kw in KEYWORDS {
        let bearer = *kw == b"bearer";
        let mut from = 0;
        while let Some(pos) = find_ci(line, kw, from) {
            if assignment_value_is_secret(line, pos + kw.len(), bearer) {
                return true;
            }
            from = pos + 1;
        }
    }
    false
}

fn url_credentials(line: &[u8]) -> bool {
    let mut from = 0;
    while let Some(p) = find(line, b"://", from) {
        from = p + 3;
        let rest = line.get(from..).unwrap_or(&[]);
        let user_len = rest
            .iter()
            .take(256)
            .take_while(|&&b| !matches!(b, b'/' | b':' | b'@' | b' ' | b'\t' | b'"' | b'\''))
            .count();
        if user_len == 0 || rest.get(user_len) != Some(&b':') {
            continue;
        }
        let after = rest.get(user_len + 1..).unwrap_or(&[]);
        let pass_len = after
            .iter()
            .take(256)
            .take_while(|&&b| !matches!(b, b'/' | b'@' | b' ' | b'\t' | b'"' | b'\''))
            .count();
        if after.get(pass_len) != Some(&b'@') {
            continue;
        }
        let pass = after.get(..pass_len).unwrap_or(&[]);
        let placeholder = pass
            .first()
            .is_some_and(|b| matches!(b, b'$' | b'<' | b'{' | b'%' | b'*'));
        if pass.len() >= 8 && !placeholder && shannon_entropy(pass) >= 2.5 {
            return true;
        }
    }
    false
}

/// Scans one window of bytes; returns a reason on the first detection.
fn scan_window(buf: &[u8]) -> Option<&'static str> {
    if has_private_key_header(buf) {
        return Some("private key block");
    }
    for tok in buf.split(|&b| !is_token_byte(b)) {
        if let Some(r) = token_rule(tok) {
            return Some(r);
        }
    }
    for line in buf.split(|&b| b == b'\n') {
        if line.len() < 8 {
            continue;
        }
        if assignment_secret(line) {
            return Some("high-entropy value assigned to a secret-like name");
        }
        if dotenv_secret_line(line) {
            return Some("value assigned to a secret-named variable");
        }
        if url_credentials(line) {
            return Some("credentials embedded in a URL");
        }
    }
    None
}

/// Streaming content scanner with bounded memory (`chunk + OVERLAP` bytes).
#[derive(Debug, Default)]
pub struct Scanner {
    carry: Vec<u8>,
    work: Vec<u8>,
    found: Option<&'static str>,
}

impl Scanner {
    pub fn new() -> Scanner {
        Scanner::default()
    }

    /// Feeds the next chunk; returns the detection reason once something matched
    /// (and keeps returning it).
    pub fn feed(&mut self, chunk: &[u8]) -> Option<&'static str> {
        if self.found.is_some() {
            return self.found;
        }
        self.work.clear();
        self.work.extend_from_slice(&self.carry);
        self.work.extend_from_slice(chunk);
        if let Some(r) = scan_window(&self.work) {
            self.found = Some(r);
            self.carry.clear();
            return self.found;
        }
        let tail_start = self
            .work
            .iter()
            .rposition(|&b| b == b'\n')
            .map_or(0, |p| p + 1);
        let tail = self.work.get(tail_start..).unwrap_or(&[]);
        let keep_from = tail.len().saturating_sub(OVERLAP);
        let keep = tail.get(keep_from..).unwrap_or(&[]);
        self.carry.clear();
        self.carry.extend_from_slice(keep);
        None
    }

    pub fn result(&self) -> Option<&'static str> {
        self.found
    }
}

/// One-shot scan of an in-memory buffer.
pub fn scan_bytes(data: &[u8]) -> Option<&'static str> {
    let mut s = Scanner::new();
    for chunk in data.chunks(64 * 1024) {
        if let Some(r) = s.feed(chunk) {
            return Some(r);
        }
    }
    None
}

#[cfg(test)]
mod tests;
