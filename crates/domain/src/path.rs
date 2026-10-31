//! `RelPath`: a validated, project-relative path.
//!
//! A `RelPath` can only be constructed from bytes that are safe to join onto a
//! project root: non-empty, no leading or trailing `/`, no empty, `.` or `..`
//! components, no NUL, bounded lengths. Because every path that reaches the
//! restore engine is a `RelPath`, path traversal through a hostile manifest is
//! rejected at the boundary where bytes become domain values.

use crate::error::{DomainError, DomainResult};
use crate::esc;
use std::cmp::Ordering;

pub const MAX_PATH_LEN: usize = 4096;
pub const MAX_COMPONENT_LEN: usize = 255;

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct RelPath(Vec<u8>);

/// Orders relative paths so that a directory's contents sort directly after the
/// directory and siblings sort by name: `/` compares lower than every other
/// byte. This is the order produced by a depth-first walk over sorted names.
pub fn cmp_bytes(a: &[u8], b: &[u8]) -> Ordering {
    let key = |x: &u8| if *x == b'/' { 0u8 } else { *x };
    a.iter().map(key).cmp(b.iter().map(key))
}

impl RelPath {
    /// Validating constructor.
    pub fn new(bytes: impl Into<Vec<u8>>) -> DomainResult<RelPath> {
        let p: Vec<u8> = bytes.into();
        let bad = |why: &str| {
            DomainError::Unsafe(format!(
                "invalid project-relative path {:?}: {why}",
                esc::display(&p)
            ))
        };
        if p.is_empty() {
            return Err(bad("empty"));
        }
        if p.len() > MAX_PATH_LEN {
            return Err(bad("too long"));
        }
        if p.first() == Some(&b'/') {
            return Err(bad("absolute"));
        }
        if p.contains(&0) {
            return Err(bad("contains NUL"));
        }
        for comp in p.split(|&b| b == b'/') {
            if comp.is_empty() {
                return Err(bad("empty component"));
            }
            if comp == b"." || comp == b".." {
                return Err(bad("'.' or '..' component"));
            }
            if comp.len() > MAX_COMPONENT_LEN {
                return Err(bad("component too long"));
            }
        }
        Ok(RelPath(p))
    }

    /// Normalizes user input (`./a//b/`) and validates it. `..` is rejected, not resolved.
    pub fn normalized(bytes: &[u8]) -> DomainResult<RelPath> {
        let comps: Vec<&[u8]> = bytes
            .split(|&b| b == b'/')
            .filter(|c| !c.is_empty() && *c != b".")
            .collect();
        RelPath::new(comps.join(&b'/'))
    }

    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }

    pub fn into_bytes(self) -> Vec<u8> {
        self.0
    }

    /// Number of components.
    pub fn depth(&self) -> usize {
        self.0.split(|&b| b == b'/').count()
    }

    /// Last component.
    pub fn name(&self) -> &[u8] {
        self.0.rsplit(|&b| b == b'/').next().unwrap_or(&self.0)
    }

    /// Parent path (`None` for a top-level name).
    pub fn parent(&self) -> Option<RelPath> {
        let i = self.0.iter().rposition(|&b| b == b'/')?;
        self.0.get(..i).map(|b| RelPath(b.to_vec()))
    }

    /// Appends one name (no `/`, not `.`/`..`).
    pub fn join(&self, name: &[u8]) -> DomainResult<RelPath> {
        if name.contains(&b'/') {
            return Err(DomainError::Unsafe("name contains '/'".into()));
        }
        let mut v = self.0.clone();
        v.push(b'/');
        v.extend_from_slice(name);
        RelPath::new(v)
    }

    /// A top-level path made of a single name.
    pub fn from_name(name: &[u8]) -> DomainResult<RelPath> {
        if name.contains(&b'/') {
            return Err(DomainError::Unsafe("name contains '/'".into()));
        }
        RelPath::new(name)
    }

    /// Whether `self` lies strictly below `ancestor`.
    pub fn is_below(&self, ancestor: &RelPath) -> bool {
        self.0.len() > ancestor.0.len()
            && self.0.starts_with(&ancestor.0)
            && self.0.get(ancestor.0.len()) == Some(&b'/')
    }

    /// Whether `self` equals `other` or lies below it.
    pub fn is_within(&self, other: &RelPath) -> bool {
        self == other || self.is_below(other)
    }

    /// Components in order.
    pub fn components(&self) -> impl Iterator<Item = &[u8]> {
        self.0.split(|&b| b == b'/')
    }

    /// Escaped form for terminals and JSON.
    pub fn display(&self) -> String {
        esc::display(&self.0)
    }

    /// Percent-encoded form used by the on-disk formats.
    pub fn encode(&self) -> String {
        esc::pct_encode(&self.0)
    }
}

impl PartialOrd for RelPath {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for RelPath {
    fn cmp(&self, other: &Self) -> Ordering {
        cmp_bytes(&self.0, &other.0)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn p(s: &str) -> RelPath {
        RelPath::new(s.as_bytes()).unwrap()
    }

    #[test]
    fn accepts_normal_paths() {
        for s in ["a", "a/b/c.txt", ".hidden/x", "with space/ü"] {
            assert!(RelPath::new(s.as_bytes()).is_ok(), "{s}");
        }
    }

    #[test]
    fn rejects_every_unsafe_shape() {
        for s in [
            "", "/abs", "a//b", "a/", "../x", "a/../b", "./a", "a/./b", "a/..",
        ] {
            assert!(RelPath::new(s.as_bytes()).is_err(), "{s}");
        }
        assert!(RelPath::new(b"a\0b".to_vec()).is_err());
        assert!(RelPath::new(vec![b'a'; MAX_PATH_LEN + 1]).is_err());
        let long = format!("{}/x", "a".repeat(MAX_COMPONENT_LEN + 1));
        assert!(RelPath::new(long.into_bytes()).is_err());
        assert!(matches!(
            RelPath::new(b"../x".to_vec()),
            Err(DomainError::Unsafe(_))
        ));
    }

    #[test]
    fn normalization_strips_noise_but_not_dotdot() {
        assert_eq!(RelPath::normalized(b"./a//b/").unwrap(), p("a/b"));
        assert!(RelPath::normalized(b"a/../b").is_err());
        assert!(RelPath::normalized(b"").is_err());
        assert!(RelPath::normalized(b"./").is_err());
    }

    #[test]
    fn order_matches_depth_first_walk() {
        assert!(
            p("a/b") < p("a-b"),
            "dir contents sort before a later sibling"
        );
        assert!(p("a") < p("a/b"));
        assert!(p("a") < p("a-b"));
        assert!(p("a/z") < p("b"));
        assert_eq!(p("x").cmp(&p("x")), Ordering::Equal);
    }

    #[test]
    fn order_is_total_and_consistent_with_eq() {
        let names = ["a", "a/b", "a-b", "a.b", "a/b/c", "b", "a b", "ab"];
        for x in names {
            for y in names {
                let (px, py) = (p(x), p(y));
                assert_eq!(px == py, px.cmp(&py) == Ordering::Equal);
                assert_eq!(px.cmp(&py), py.cmp(&px).reverse());
            }
        }
    }

    #[test]
    fn walk_order_equals_sorted_order() {
        // Simulate a depth-first walk over sorted sibling names and compare
        // with sorting the resulting paths.
        fn walk(prefix: &str, out: &mut Vec<String>, depth: usize) {
            let mut names = vec!["a", "a-b", "b", "a.c"];
            names.sort_unstable();
            for n in names {
                let path = if prefix.is_empty() {
                    n.to_string()
                } else {
                    format!("{prefix}/{n}")
                };
                out.push(path.clone());
                if depth < 2 && (n == "a" || n == "b") {
                    walk(&path, out, depth + 1);
                }
            }
        }
        let mut walked = Vec::new();
        walk("", &mut walked, 0);
        let mut sorted: Vec<RelPath> = walked.iter().map(|s| p(s)).collect();
        sorted.sort();
        let walked: Vec<RelPath> = walked.iter().map(|s| p(s)).collect();
        assert_eq!(walked, sorted);
    }

    #[test]
    fn structure_queries() {
        let x = p("a/b/c");
        assert_eq!(x.depth(), 3);
        assert_eq!(x.name(), b"c");
        assert_eq!(x.parent(), Some(p("a/b")));
        assert_eq!(p("a").parent(), None);
        assert_eq!(p("a").join(b"b").unwrap(), p("a/b"));
        assert!(p("a").join(b"b/c").is_err());
        assert!(p("a").join(b"..").is_err());
        assert!(RelPath::from_name(b"a/b").is_err());
        assert_eq!(
            x.components().collect::<Vec<_>>(),
            vec![&b"a"[..], b"b", b"c"]
        );
    }

    #[test]
    fn containment() {
        assert!(p("a/b").is_below(&p("a")));
        assert!(!p("a").is_below(&p("a")));
        assert!(!p("ab").is_below(&p("a")));
        assert!(p("a").is_within(&p("a")));
        assert!(p("a/b/c").is_within(&p("a")));
        assert!(!p("b").is_within(&p("a")));
    }

    #[test]
    fn display_escapes_and_encode_round_trips() {
        let x = RelPath::new(b"dir/\x1b[31mred\nx".to_vec()).unwrap();
        assert!(!x.display().contains('\x1b'));
        assert!(!x.encode().contains('\n'));
        assert_eq!(crate::esc::pct_decode(&x.encode()).unwrap(), x.as_bytes());
    }
}
