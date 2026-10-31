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
mod tests;
