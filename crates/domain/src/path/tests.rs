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
