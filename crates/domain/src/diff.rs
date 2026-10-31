//! Unified text diff for small text files (Myers O(ND), bounded).
//!
//! Only valid UTF-8 text without NUL bytes, below fixed size and line limits,
//! is diffed; everything else is reported as omitted with a reason. Every line
//! is escaped with [`crate::esc::display_keep_tab`] so file content cannot inject
//! terminal control sequences.

use crate::esc::display_keep_tab;

pub const MAX_DIFF_BYTES: usize = 64 * 1024;
pub const MAX_DIFF_LINES: usize = 4000;
pub const MAX_EDIT_DISTANCE: usize = 600;
const CONTEXT: usize = 3;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DiffOutcome {
    /// Hunks in unified format, starting at the first `@@` line.
    Text(String),
    /// No diff produced; the reason is human readable.
    Omitted(&'static str),
    /// Identical content.
    Identical,
}

fn as_text(b: &[u8]) -> Result<&str, &'static str> {
    if b.len() > MAX_DIFF_BYTES {
        return Err("file too large for a text diff");
    }
    if b.contains(&0) {
        return Err("binary file");
    }
    std::str::from_utf8(b).map_err(|_| "not valid UTF-8 text")
}

fn split_lines(s: &str) -> (Vec<&str>, bool) {
    if s.is_empty() {
        return (Vec::new(), true);
    }
    let ends_nl = s.ends_with('\n');
    let body = s.strip_suffix('\n').unwrap_or(s);
    (body.split('\n').collect(), ends_nl)
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Tag {
    Equal,
    Delete,
    Insert,
}

fn vget(v: &[isize], off: isize, k: isize) -> isize {
    usize::try_from(off + k)
        .ok()
        .and_then(|i| v.get(i))
        .copied()
        .unwrap_or(-1)
}

fn vset(v: &mut [isize], off: isize, k: isize, val: isize) {
    if let Some(slot) = usize::try_from(off + k).ok().and_then(|i| v.get_mut(i)) {
        *slot = val;
    }
}

/// Myers diff of two line slices; `None` if the edit distance exceeds the cap.
fn myers(a: &[&str], b: &[&str]) -> Option<Vec<(Tag, usize, usize)>> {
    let n = a.len() as isize;
    let m = b.len() as isize;
    let max = (n + m).min(MAX_EDIT_DISTANCE as isize);
    let off = max + 1;
    let mut v = vec![-1isize; (2 * max + 3) as usize];
    vset(&mut v, off, 1, 0);
    let mut trace: Vec<Vec<isize>> = Vec::new();
    let mut found = None;
    'outer: for d in 0..=max {
        trace.push(v.clone());
        let mut k = -d;
        while k <= d {
            let mut x = if k == -d || (k != d && vget(&v, off, k - 1) < vget(&v, off, k + 1)) {
                vget(&v, off, k + 1)
            } else {
                vget(&v, off, k - 1) + 1
            };
            let mut y = x - k;
            while x < n && y < m && a.get(x as usize) == b.get(y as usize) {
                x += 1;
                y += 1;
            }
            vset(&mut v, off, k, x);
            if x >= n && y >= m {
                found = Some(d);
                break 'outer;
            }
            k += 2;
        }
    }
    let d_final = found?;
    // Backtrack.
    let mut edits: Vec<(Tag, usize, usize)> = Vec::new();
    let (mut x, mut y) = (n, m);
    for d in (0..=d_final).rev() {
        let vd = trace.get(d as usize)?;
        let k = x - y;
        let prev_k = if k == -d || (k != d && vget(vd, off, k - 1) < vget(vd, off, k + 1)) {
            k + 1
        } else {
            k - 1
        };
        let prev_x = vget(vd, off, prev_k);
        let prev_y = prev_x - prev_k;
        while x > prev_x && y > prev_y {
            x -= 1;
            y -= 1;
            edits.push((Tag::Equal, x as usize, y as usize));
        }
        if d > 0 {
            if x == prev_x {
                y -= 1;
                edits.push((Tag::Insert, x as usize, y as usize));
            } else {
                x -= 1;
                edits.push((Tag::Delete, x as usize, y as usize));
            }
        }
    }
    edits.reverse();
    Some(edits)
}

struct Line<'a> {
    tag: Tag,
    text: &'a str,
    a_no: usize,
    b_no: usize,
}

/// Produces a unified diff (hunks only) of `old` and `new`.
pub fn unified(old: &[u8], new: &[u8]) -> DiffOutcome {
    if old == new {
        return DiffOutcome::Identical;
    }
    let (old_s, new_s) = match (as_text(old), as_text(new)) {
        (Ok(a), Ok(b)) => (a, b),
        (Err(e), _) | (_, Err(e)) => return DiffOutcome::Omitted(e),
    };
    let (a, a_nl) = split_lines(old_s);
    let (b, b_nl) = split_lines(new_s);
    if a.len() > MAX_DIFF_LINES || b.len() > MAX_DIFF_LINES {
        return DiffOutcome::Omitted("too many lines for a text diff");
    }
    // Trim the common prefix and suffix.
    let prefix = a.iter().zip(&b).take_while(|(x, y)| x == y).count();
    let max_suffix = a.len().min(b.len()) - prefix;
    let suffix = a
        .iter()
        .rev()
        .zip(b.iter().rev())
        .take(max_suffix)
        .take_while(|(x, y)| x == y)
        .count();
    let (Some(a_mid), Some(b_mid)) = (
        a.get(prefix..a.len() - suffix),
        b.get(prefix..b.len() - suffix),
    ) else {
        return DiffOutcome::Omitted("diff failed");
    };
    let Some(edits) = myers(a_mid, b_mid) else {
        return DiffOutcome::Omitted("too many differences for a text diff");
    };
    let mut lines: Vec<Line> = Vec::new();
    for (i, text) in a.iter().take(prefix).enumerate() {
        lines.push(Line {
            tag: Tag::Equal,
            text,
            a_no: i,
            b_no: i,
        });
    }
    for (tag, x, y) in edits {
        let (text, a_no, b_no) = match tag {
            Tag::Equal | Tag::Delete => {
                (a_mid.get(x).copied().unwrap_or(""), prefix + x, prefix + y)
            }
            Tag::Insert => (b_mid.get(y).copied().unwrap_or(""), prefix + x, prefix + y),
        };
        lines.push(Line {
            tag,
            text,
            a_no,
            b_no,
        });
    }
    for i in 0..suffix {
        let ai = a.len() - suffix + i;
        let bi = b.len() - suffix + i;
        lines.push(Line {
            tag: Tag::Equal,
            text: a.get(ai).copied().unwrap_or(""),
            a_no: ai,
            b_no: bi,
        });
    }
    // Group into hunks.
    let changed: Vec<usize> = lines
        .iter()
        .enumerate()
        .filter(|(_, l)| l.tag != Tag::Equal)
        .map(|(i, _)| i)
        .collect();
    if changed.is_empty() {
        // Only the trailing-newline state differs.
        return DiffOutcome::Text(format!(
            "@@ -1,{} +1,{} @@\n\\ no trailing newline differs ({} -> {})\n",
            a.len(),
            b.len(),
            if a_nl { "newline" } else { "none" },
            if b_nl { "newline" } else { "none" }
        ));
    }
    let mut ranges: Vec<(usize, usize)> = Vec::new();
    for &i in &changed {
        let start = i.saturating_sub(CONTEXT);
        let end = (i + CONTEXT + 1).min(lines.len());
        match ranges.last_mut() {
            Some(last) if start <= last.1 => last.1 = end,
            _ => ranges.push((start, end)),
        }
    }
    let mut out = String::new();
    for (start, end) in ranges {
        let slice = lines.get(start..end).unwrap_or(&[]);
        let a_start = slice.first().map_or(0, |l| l.a_no);
        let b_start = slice.first().map_or(0, |l| l.b_no);
        let a_count = slice.iter().filter(|l| l.tag != Tag::Insert).count();
        let b_count = slice.iter().filter(|l| l.tag != Tag::Delete).count();
        let fmt_range = |s: usize, c: usize| {
            if c == 0 {
                format!("{s},0")
            } else {
                format!("{},{c}", s + 1)
            }
        };
        out.push_str(&format!(
            "@@ -{} +{} @@\n",
            fmt_range(a_start, a_count),
            fmt_range(b_start, b_count)
        ));
        for l in slice {
            let sign = match l.tag {
                Tag::Equal => ' ',
                Tag::Delete => '-',
                Tag::Insert => '+',
            };
            out.push(sign);
            out.push_str(&display_keep_tab(l.text.as_bytes()));
            out.push('\n');
        }
    }
    if a_nl != b_nl {
        out.push_str("\\ trailing newline differs between the two versions\n");
    }
    DiffOutcome::Text(out)
}

#[cfg(test)]
mod tests {
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
}
