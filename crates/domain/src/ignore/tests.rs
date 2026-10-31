use super::*;

fn set(text: &str) -> IgnoreSet {
    let mut s = IgnoreSet::empty();
    s.add_text(text.as_bytes()).unwrap();
    s
}

fn ign(s: &IgnoreSet, path: &str, dir: bool) -> bool {
    s.is_ignored(path.as_bytes(), dir)
}

#[test]
fn defaults_ignore_common_dirs() {
    let s = IgnoreSet::defaults();
    for d in [
        ".git",
        "node_modules",
        "target",
        ".next",
        "dist",
        "__pycache__",
        ".venv",
        ".cache",
        "a/b/node_modules",
        "pkg/__pycache__",
    ] {
        assert!(ign(&s, d, true), "{d}");
    }
    assert!(
        ign(&s, ".git", false),
        ".git file (worktree) is ignored too"
    );
    assert!(!ign(&s, "src", true));
    assert!(!ign(&s, "src/main.rs", false));
}

#[test]
fn default_dir_patterns_do_not_ignore_files_with_same_name() {
    let s = IgnoreSet::defaults();
    assert!(!ign(&s, "target", false));
    assert!(!ign(&s, "dist", false));
}

#[test]
fn user_pattern_can_reinclude_a_default() {
    let s = IgnoreSet::with_user_patterns(b"!dist/\n").unwrap();
    assert!(!ign(&s, "dist", true));
    assert!(ign(&s, "node_modules", true));
}

#[test]
fn comments_blank_lines_and_crlf() {
    let s = set("# comment\n\n*.log\r\n");
    assert!(ign(&s, "a.log", false));
    assert!(!ign(&s, "# comment", false));
    assert_eq!(s.len(), 1);
}

#[test]
fn star_matches_within_component_only() {
    let s = set("/docs/*.md");
    assert!(ign(&s, "docs/a.md", false));
    assert!(!ign(&s, "docs/sub/a.md", false));
    assert!(!ign(&s, "other/docs/a.md", false));
}

#[test]
fn question_mark_and_class() {
    let s = set("file?.txt\nlog[0-9].txt\nx[!a].c");
    assert!(ign(&s, "file1.txt", false));
    assert!(!ign(&s, "file.txt", false));
    assert!(!ign(&s, "file12.txt", false));
    assert!(ign(&s, "log7.txt", false));
    assert!(!ign(&s, "logx.txt", false));
    assert!(ign(&s, "xb.c", false));
    assert!(!ign(&s, "xa.c", false));
}

#[test]
fn unterminated_class_is_literal() {
    let s = set("a[b");
    assert!(ign(&s, "a[b", false));
    assert!(!ign(&s, "ab", false));
}

#[test]
fn leading_slash_anchors() {
    let s = set("/build");
    assert!(ign(&s, "build", true));
    assert!(!ign(&s, "src/build", true));
}

#[test]
fn unanchored_matches_at_any_depth() {
    let s = set("*.tmp");
    assert!(ign(&s, "a.tmp", false));
    assert!(ign(&s, "x/y/z/a.tmp", false));
}

#[test]
fn slash_in_middle_anchors() {
    let s = set("src/gen");
    assert!(ign(&s, "src/gen", true));
    assert!(!ign(&s, "a/src/gen", true));
}

#[test]
fn dir_only_trailing_slash() {
    let s = set("out/");
    assert!(ign(&s, "out", true));
    assert!(!ign(&s, "out", false));
    assert!(ign(&s, "a/out", true));
}

#[test]
fn double_star_prefix() {
    let s = set("**/cache");
    assert!(ign(&s, "cache", true));
    assert!(ign(&s, "a/b/cache", false));
    assert!(!ign(&s, "a/b/cachex", false));
}

#[test]
fn double_star_middle() {
    let s = set("a/**/z");
    assert!(ign(&s, "a/z", false));
    assert!(ign(&s, "a/b/z", false));
    assert!(ign(&s, "a/b/c/z", false));
    assert!(!ign(&s, "b/a/z", false));
    assert!(!ign(&s, "a/b/y", false));
}

#[test]
fn double_star_trailing_needs_at_least_one_component() {
    let s = set("a/**");
    assert!(!ign(&s, "a", true));
    assert!(ign(&s, "a/b", false));
    assert!(ign(&s, "a/b/c", false));
}

#[test]
fn negation_last_match_wins() {
    let s = set("*.log\n!keep.log\n");
    assert!(ign(&s, "a.log", false));
    assert!(!ign(&s, "keep.log", false));
    let s = set("!keep.log\n*.log\n");
    assert!(ign(&s, "keep.log", false));
}

#[test]
fn escaped_hash_and_bang() {
    let s = set("\\#file\n\\!bang");
    assert!(ign(&s, "#file", false));
    assert!(ign(&s, "!bang", false));
}

#[test]
fn escaped_star_is_literal() {
    let s = set("a\\*b");
    assert!(ign(&s, "a*b", false));
    assert!(!ign(&s, "aXb", false));
}

#[test]
fn trailing_spaces_are_trimmed() {
    let s = set("name   ");
    assert!(ign(&s, "name", false));
}

#[test]
fn star_alone_matches_everything() {
    let s = set("*");
    assert!(ign(&s, "a", false));
    assert!(ign(&s, "a/b", false));
}

#[test]
fn hostile_pattern_is_not_exponential() {
    // Classic catastrophic-backtracking shape for naive recursive matchers.
    let pat = format!("{}b", "a*".repeat(200));
    let s = set(&pat);
    let name = "a".repeat(5000);
    let start = std::time::Instant::now();
    assert!(!ign(&s, &name, false));
    assert!(start.elapsed().as_secs() < 5, "matcher must be polynomial");
}

#[test]
fn long_path_with_many_double_stars_is_fast() {
    let s = set("**/**/**/**/**/x");
    let path = format!("{}x", "d/".repeat(500));
    let start = std::time::Instant::now();
    assert!(ign(&s, &path, false));
    assert!(start.elapsed().as_secs() < 5);
}

#[test]
fn oversize_pattern_is_rejected() {
    let mut s = IgnoreSet::empty();
    let big = "a".repeat(MAX_PATTERN_LEN + 1);
    assert!(s.add_text(big.as_bytes()).is_err());
}

#[test]
fn too_many_patterns_rejected() {
    let mut s = IgnoreSet::empty();
    let text: String = (0..MAX_PATTERNS + DEFAULT_PATTERNS.len() + 5)
        .map(|i| format!("p{i}\n"))
        .collect();
    assert!(s.add_text(text.as_bytes()).is_err());
}

#[test]
fn non_utf8_names_match_bytewise() {
    let mut s = IgnoreSet::empty();
    s.add_text(b"bad?name").unwrap();
    assert!(s.is_ignored(b"bad\xffname", false));
}

#[test]
fn empty_path_is_never_ignored() {
    assert!(!IgnoreSet::defaults().is_ignored(b"", true));
}

#[test]
fn dot_segments_in_pattern_are_literal() {
    let s = set("a.b");
    assert!(ign(&s, "a.b", false));
    assert!(!ign(&s, "aXb", false));
}
