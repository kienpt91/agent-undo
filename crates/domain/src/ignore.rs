//! A gitignore-style subset with a backtracking-free matcher (no regex).
//!
//! Supported syntax (`.agent-undoignore`, one pattern per line):
//!
//! * `# comment` and blank lines are skipped; `\#` and `\!` escape the first character.
//! * `!pattern` re-includes something an earlier pattern ignored (last match wins).
//! * a trailing `/` matches directories only.
//! * a leading `/`, or a `/` anywhere else in the pattern, anchors it to the project root;
//!   a pattern without a slash matches the entry name at any depth.
//! * `*` (any run of bytes within one path component), `?` (one byte),
//!   `[abc]` / `[a-z]` / `[!abc]` byte classes, `\x` literal escape,
//!   and `**` as a whole path component (zero or more directories).
//!
//! Not supported: per-directory ignore files, `[:alpha:]` classes, case folding.
//! Patterns match bytes, not Unicode scalar values.
//!
//! Matching cost: one component match is `O(len(name) * len(pattern))` using the
//! classic single-backtrack-point wildcard loop, and path matching is a dynamic
//! program over (pattern segments x path components). There is no exponential
//! backtracking, so a hostile pattern file cannot hang the scanner.

pub const MAX_PATTERNS: usize = 10_000;
pub const MAX_PATTERN_LEN: usize = 4096;
pub const MAX_IGNORE_FILE_BYTES: u64 = 1024 * 1024;

/// Patterns that are always applied first. `.agent-undoignore` can re-include
/// them with `!name`.
pub const DEFAULT_PATTERNS: &[&str] = &[
    ".git",
    ".agent-undo",
    ".DS_Store",
    "node_modules/",
    "target/",
    ".next/",
    ".nuxt/",
    ".svelte-kit/",
    ".turbo/",
    ".parcel-cache/",
    "dist/",
    "__pycache__/",
    ".venv/",
    "venv/",
    ".tox/",
    ".cache/",
    ".mypy_cache/",
    ".pytest_cache/",
    ".ruff_cache/",
    ".gradle/",
];

#[derive(Debug, Clone, PartialEq)]
enum Tok {
    Lit(u8),
    Any,
    Star,
    Class {
        negated: bool,
        ranges: Vec<(u8, u8)>,
    },
}

#[derive(Debug, Clone, PartialEq)]
enum Seg {
    DoubleStar,
    Glob(Vec<Tok>),
}

#[derive(Debug, Clone)]
struct Pattern {
    segs: Vec<Seg>,
    anchored: bool,
    dir_only: bool,
    negate: bool,
}

/// An ordered list of ignore patterns.
#[derive(Debug, Clone, Default)]
pub struct IgnoreSet {
    patterns: Vec<Pattern>,
}

fn parse_glob(seg: &[u8]) -> Vec<Tok> {
    let mut toks = Vec::new();
    let mut i = 0;
    while let Some(&c) = seg.get(i) {
        match c {
            b'*' => {
                if !matches!(toks.last(), Some(Tok::Star)) {
                    toks.push(Tok::Star);
                }
                i += 1;
            }
            b'?' => {
                toks.push(Tok::Any);
                i += 1;
            }
            b'\\' => match seg.get(i + 1) {
                Some(&n) => {
                    toks.push(Tok::Lit(n));
                    i += 2;
                }
                None => {
                    toks.push(Tok::Lit(b'\\'));
                    i += 1;
                }
            },
            b'[' => match parse_class(seg, i) {
                Some((tok, next)) => {
                    toks.push(tok);
                    i = next;
                }
                None => {
                    toks.push(Tok::Lit(b'['));
                    i += 1;
                }
            },
            other => {
                toks.push(Tok::Lit(other));
                i += 1;
            }
        }
    }
    toks
}

/// Parses `[...]` starting at `start` (which points at `[`). Returns the token
/// and the index just past the closing `]`, or `None` if the class is unterminated.
fn parse_class(seg: &[u8], start: usize) -> Option<(Tok, usize)> {
    let mut i = start + 1;
    let negated = matches!(seg.get(i), Some(b'!') | Some(b'^'));
    if negated {
        i += 1;
    }
    let mut ranges = Vec::new();
    let mut first = true;
    loop {
        let c = *seg.get(i)?;
        if c == b']' && !first {
            return Some((Tok::Class { negated, ranges }, i + 1));
        }
        first = false;
        let (lo, adv) = if c == b'\\' {
            (*seg.get(i + 1)?, 2)
        } else {
            (c, 1)
        };
        i += adv;
        if seg.get(i) == Some(&b'-') && seg.get(i + 1).is_some_and(|&n| n != b']') {
            let hi_raw = *seg.get(i + 1)?;
            let (hi, adv2) = if hi_raw == b'\\' {
                (*seg.get(i + 2)?, 3)
            } else {
                (hi_raw, 2)
            };
            i += adv2;
            ranges.push((lo.min(hi), lo.max(hi)));
        } else {
            ranges.push((lo, lo));
        }
    }
}

fn tok_matches(tok: &Tok, b: u8) -> bool {
    match tok {
        Tok::Lit(l) => *l == b,
        Tok::Any => true,
        Tok::Class { negated, ranges } => {
            let hit = ranges.iter().any(|&(lo, hi)| lo <= b && b <= hi);
            hit != *negated
        }
        Tok::Star => false,
    }
}

/// Wildcard match of one path component. Single backtrack point: `O(n*m)` worst
/// case, never exponential.
fn glob_match(pat: &[Tok], text: &[u8]) -> bool {
    let (mut p, mut t) = (0usize, 0usize);
    let mut star: Option<(usize, usize)> = None;
    loop {
        match pat.get(p) {
            Some(Tok::Star) => {
                star = Some((p + 1, t));
                p += 1;
            }
            Some(tok) if t < text.len() && text.get(t).is_some_and(|&b| tok_matches(tok, b)) => {
                p += 1;
                t += 1;
            }
            None if t == text.len() => return true,
            _ => match star {
                Some((sp, st)) if st < text.len() => {
                    star = Some((sp, st + 1));
                    p = sp;
                    t = st + 1;
                }
                _ => return false,
            },
        }
    }
}

impl Pattern {
    fn parse(line: &[u8]) -> Option<Pattern> {
        // Strip trailing unescaped spaces.
        let mut end = line.len();
        while end > 0
            && line.get(end - 1) == Some(&b' ')
            && line.get(end.wrapping_sub(2)) != Some(&b'\\')
        {
            end -= 1;
        }
        let mut line = line.get(..end)?;
        if line.is_empty() || line.first() == Some(&b'#') {
            return None;
        }
        let mut negate = false;
        if line.first() == Some(&b'!') {
            negate = true;
            line = line.get(1..)?;
        } else if line.starts_with(b"\\#") || line.starts_with(b"\\!") {
            line = line.get(1..)?;
        }
        let mut dir_only = false;
        if line.last() == Some(&b'/') {
            dir_only = true;
            line = line.get(..line.len() - 1)?;
        }
        let mut anchored = false;
        if line.first() == Some(&b'/') {
            anchored = true;
            line = line.get(1..)?;
        }
        if line.is_empty() {
            return None;
        }
        let parts: Vec<&[u8]> = line
            .split(|&b| b == b'/')
            .filter(|s| !s.is_empty())
            .collect();
        if parts.is_empty() {
            return None;
        }
        if parts.len() > 1 {
            anchored = true;
        }
        let segs = parts
            .iter()
            .map(|p| {
                if *p == b"**" {
                    Seg::DoubleStar
                } else {
                    Seg::Glob(parse_glob(p))
                }
            })
            .collect();
        Some(Pattern {
            segs,
            anchored,
            dir_only,
            negate,
        })
    }

    fn matches(&self, comps: &[&[u8]], is_dir: bool) -> bool {
        if self.dir_only && !is_dir {
            return false;
        }
        if !self.anchored {
            // Single-segment pattern: match the entry name at any depth.
            return match (self.segs.first(), comps.last()) {
                (Some(Seg::Glob(g)), Some(name)) => glob_match(g, name),
                _ => false,
            };
        }
        match_segments(&self.segs, comps)
    }
}

fn match_segments(segs: &[Seg], comps: &[&[u8]]) -> bool {
    let n = comps.len();
    let mut cur = vec![false; n + 1];
    if let Some(first) = cur.first_mut() {
        *first = true;
    }
    for (si, seg) in segs.iter().enumerate() {
        let mut next = vec![false; n + 1];
        match seg {
            Seg::DoubleStar => {
                let trailing = si + 1 == segs.len();
                for j in 0..=n {
                    let zero = !trailing && cur.get(j).copied().unwrap_or(false);
                    let more = j > 0
                        && (next.get(j - 1).copied().unwrap_or(false)
                            || (trailing && cur.get(j - 1).copied().unwrap_or(false)));
                    if let Some(slot) = next.get_mut(j) {
                        *slot = zero || more;
                    }
                }
            }
            Seg::Glob(g) => {
                for j in 0..n {
                    if cur.get(j).copied().unwrap_or(false)
                        && comps.get(j).is_some_and(|c| glob_match(g, c))
                        && let Some(slot) = next.get_mut(j + 1)
                    {
                        *slot = true;
                    }
                }
            }
        }
        cur = next;
    }
    cur.get(n).copied().unwrap_or(false)
}

impl IgnoreSet {
    /// An empty set (nothing ignored).
    pub fn empty() -> IgnoreSet {
        IgnoreSet::default()
    }

    /// The built-in defaults only.
    pub fn defaults() -> IgnoreSet {
        let mut set = IgnoreSet::empty();
        for p in DEFAULT_PATTERNS {
            if let Some(pat) = Pattern::parse(p.as_bytes()) {
                set.patterns.push(pat);
            }
        }
        set
    }

    /// Defaults followed by the patterns in `text`.
    pub fn with_user_patterns(text: &[u8]) -> Result<IgnoreSet, String> {
        let mut set = IgnoreSet::defaults();
        set.add_text(text)?;
        Ok(set)
    }

    /// Appends the patterns in `text`; fails on oversize input rather than
    /// silently dropping rules.
    pub fn add_text(&mut self, text: &[u8]) -> Result<(), String> {
        for raw in text.split(|&b| b == b'\n') {
            let line = raw.strip_suffix(b"\r").unwrap_or(raw);
            if line.len() > MAX_PATTERN_LEN {
                return Err(format!(
                    "ignore pattern longer than {MAX_PATTERN_LEN} bytes"
                ));
            }
            if let Some(p) = Pattern::parse(line) {
                if self.patterns.len() >= DEFAULT_PATTERNS.len() + MAX_PATTERNS {
                    return Err(format!("more than {MAX_PATTERNS} ignore patterns"));
                }
                self.patterns.push(p);
            }
        }
        Ok(())
    }

    pub fn len(&self) -> usize {
        self.patterns.len()
    }

    pub fn is_empty(&self) -> bool {
        self.patterns.is_empty()
    }

    /// Whether `rel` (a `/`-separated path relative to the project root) is ignored.
    /// The last matching pattern wins; `!` patterns re-include.
    pub fn is_ignored(&self, rel: &[u8], is_dir: bool) -> bool {
        let comps: Vec<&[u8]> = rel
            .split(|&b| b == b'/')
            .filter(|c| !c.is_empty())
            .collect();
        if comps.is_empty() {
            return false;
        }
        for pat in self.patterns.iter().rev() {
            if pat.matches(&comps, is_dir) {
                return !pat.negate;
            }
        }
        false
    }
}

#[cfg(test)]
mod tests;
