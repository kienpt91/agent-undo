use super::*;

fn text(o: DiffOutcome) -> String {
    match o {
        DiffOutcome::Text(t) => t,
        other => panic!("expected text, got {other:?}"),
    }
}

#[test]
fn identical_inputs() {
    assert_eq!(unified(b"a\nb\n", b"a\nb\n"), DiffOutcome::Identical);
    assert_eq!(unified(b"", b""), DiffOutcome::Identical);
}

#[test]
fn single_line_change() {
    let d = text(unified(b"one\ntwo\nthree\n", b"one\nTWO\nthree\n"));
    assert_eq!(d, "@@ -1,3 +1,3 @@\n one\n-two\n+TWO\n three\n");
}

#[test]
fn pure_insertion_and_deletion() {
    let d = text(unified(b"a\nc\n", b"a\nb\nc\n"));
    assert_eq!(d, "@@ -1,2 +1,3 @@\n a\n+b\n c\n");
    let d = text(unified(b"a\nb\nc\n", b"a\nc\n"));
    assert_eq!(d, "@@ -1,3 +1,2 @@\n a\n-b\n c\n");
}

#[test]
fn empty_to_content_and_back() {
    assert_eq!(text(unified(b"", b"x\ny\n")), "@@ -0,0 +1,2 @@\n+x\n+y\n");
    assert_eq!(text(unified(b"x\ny\n", b"")), "@@ -1,2 +0,0 @@\n-x\n-y\n");
}

#[test]
fn distant_changes_make_separate_hunks() {
    let old: String = (1..=30).map(|i| format!("line{i}\n")).collect();
    let new = old
        .replace("line2\n", "CHANGED2\n")
        .replace("line28\n", "CHANGED28\n");
    let d = text(unified(old.as_bytes(), new.as_bytes()));
    assert_eq!(d.matches("@@ -").count(), 2, "{d}");
    assert!(d.contains("-line2\n+CHANGED2"));
    assert!(d.contains("-line28\n+CHANGED28"));
    assert!(!d.contains("line15"), "far-away lines are not shown");
}

#[test]
fn nearby_changes_merge_into_one_hunk() {
    let old: String = (1..=12).map(|i| format!("l{i}\n")).collect();
    let new = old.replace("l3\n", "X3\n").replace("l7\n", "X7\n");
    let d = text(unified(old.as_bytes(), new.as_bytes()));
    assert_eq!(d.matches("@@ -").count(), 1, "{d}");
}

#[test]
fn applying_the_diff_reconstructs_the_new_file() {
    // Property-style: for many deterministic pseudo-random edits, applying the
    // hunks to the old text yields the new text.
    let mut seed = 0x1234_5678_u64;
    let mut rnd = |n: u64| {
        seed ^= seed << 13;
        seed ^= seed >> 7;
        seed ^= seed << 17;
        seed % n
    };
    for _ in 0..60 {
        let old_lines: Vec<String> = (0..rnd(25) + 1)
            .map(|i| format!("row {i} {}", rnd(4)))
            .collect();
        let mut new_lines = old_lines.clone();
        for _ in 0..rnd(6) {
            let pos = (rnd(new_lines.len() as u64 + 1)) as usize;
            match rnd(3) {
                0 => new_lines.insert(pos, format!("ins {}", rnd(100))),
                1 if pos < new_lines.len() => {
                    new_lines.remove(pos);
                }
                _ if pos < new_lines.len() => new_lines[pos] = format!("mod {}", rnd(100)),
                _ => {}
            }
        }
        let old = old_lines.join("\n") + "\n";
        let new = new_lines.join("\n") + "\n";
        match unified(old.as_bytes(), new.as_bytes()) {
            DiffOutcome::Identical => assert_eq!(old, new),
            DiffOutcome::Text(d) => assert_eq!(apply(&old, &d), new, "diff:\n{d}"),
            other => panic!("{other:?}"),
        }
    }
}

/// Minimal unified-diff applier used to check the property above.
fn apply(old: &str, diff: &str) -> String {
    let old_lines: Vec<&str> = old.lines().collect();
    let mut out: Vec<String> = Vec::new();
    let mut pos = 0usize;
    for line in diff.lines() {
        if let Some(h) = line.strip_prefix("@@ -") {
            let start: usize = h.split([',', ' ']).next().unwrap().parse().unwrap();
            let a_start = if start == 0 { 0 } else { start - 1 };
            let count_zero = h.split(' ').next().unwrap().ends_with(",0");
            let a_start = if count_zero { start } else { a_start };
            while pos < a_start {
                out.push(old_lines[pos].to_string());
                pos += 1;
            }
        } else if let Some(t) = line.strip_prefix('+') {
            out.push(t.to_string());
        } else if line.starts_with('-') {
            pos += 1;
        } else if let Some(t) = line.strip_prefix(' ') {
            out.push(t.to_string());
            pos += 1;
        }
    }
    while pos < old_lines.len() {
        out.push(old_lines[pos].to_string());
        pos += 1;
    }
    out.join("\n") + "\n"
}

#[test]
fn binary_invalid_utf8_and_large_inputs_are_omitted() {
    assert_eq!(
        unified(b"a\0b", b"a\0c"),
        DiffOutcome::Omitted("binary file")
    );
    assert_eq!(
        unified(&[0xff, 0xfe], b"x"),
        DiffOutcome::Omitted("not valid UTF-8 text")
    );
    let big = vec![b'a'; MAX_DIFF_BYTES + 1];
    assert_eq!(
        unified(&big, b"x"),
        DiffOutcome::Omitted("file too large for a text diff")
    );
    let many: String = "x\n".repeat(MAX_DIFF_LINES + 1);
    assert_eq!(
        unified(many.as_bytes(), b"y\n"),
        DiffOutcome::Omitted("too many lines for a text diff")
    );
}

#[test]
fn too_many_differences_is_omitted_not_slow() {
    let old: String = (0..2000).map(|i| format!("a{i}\n")).collect();
    let new: String = (0..2000).map(|i| format!("b{i}\n")).collect();
    let start = std::time::Instant::now();
    assert_eq!(
        unified(old.as_bytes(), new.as_bytes()),
        DiffOutcome::Omitted("too many differences for a text diff")
    );
    assert!(start.elapsed().as_secs() < 5);
}

#[test]
fn control_sequences_in_content_are_escaped() {
    let d = text(unified(b"safe\n", b"\x1b[31mred\x07\n"));
    assert!(!d.contains('\x1b') && !d.contains('\x07'));
    assert!(d.contains("\\x1b[31mred\\x07"));
}

#[test]
fn bidi_characters_are_escaped() {
    let d = text(unified(b"a\n", "b\u{202E}c\n".as_bytes()));
    assert!(!d.contains('\u{202E}'));
}

#[test]
fn tabs_pass_through() {
    let d = text(unified(b"a\n", b"\tb\n"));
    assert!(d.contains("+\tb"));
}

#[test]
fn trailing_newline_differences_are_reported() {
    let d = text(unified(b"a\nb", b"a\nb\n"));
    assert!(d.contains("trailing newline"), "{d}");
    let d = text(unified(b"a", b"a\n"));
    assert!(
        d.contains("no trailing newline differs") || d.contains("trailing newline"),
        "{d}"
    );
}
