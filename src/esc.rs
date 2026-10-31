//! Escaping for terminals (display) and for the on-disk text formats (percent
//! encoding).
//!
//! Anything that originates from the project directory or from a user
//! (paths, symlink targets, labels, command lines) is escaped before it is
//! printed, so a hostile file name cannot inject terminal control sequences
//! (ANSI/OSC), line breaks or bidirectional-override characters into output.

use std::fmt::Write as _;

/// Characters that are not control characters per `char::is_control` but still
/// change how text is laid out or hide content (zero-width, bidi, line/paragraph
/// separators, byte-order mark, interlinear annotation).
fn is_invisible_format(c: char) -> bool {
    matches!(
        c,
        '\u{00AD}'
            | '\u{061C}'
            | '\u{180E}'
            | '\u{200B}'..='\u{200F}'
            | '\u{2028}'..='\u{202E}'
            | '\u{2060}'..='\u{206F}'
            | '\u{FEFF}'
            | '\u{FFF9}'..='\u{FFFB}'
            | '\u{E0000}'..='\u{E007F}'
    )
}

fn push_escaped_char(out: &mut String, c: char, allow_tab: bool) {
    match c {
        '\\' => out.push_str("\\\\"),
        '\n' => out.push_str("\\n"),
        '\r' => out.push_str("\\r"),
        '\t' if allow_tab => out.push('\t'),
        '\t' => out.push_str("\\t"),
        c if c.is_control() || is_invisible_format(c) => {
            let v = u32::from(c);
            if v < 0x80 {
                let _ = write!(out, "\\x{v:02x}");
            } else {
                let _ = write!(out, "\\u{{{v:x}}}");
            }
        }
        c => out.push(c),
    }
}

fn escape_impl(bytes: &[u8], allow_tab: bool) -> String {
    let mut out = String::with_capacity(bytes.len());
    let mut rest = bytes;
    while !rest.is_empty() {
        match std::str::from_utf8(rest) {
            Ok(s) => {
                s.chars().for_each(|c| push_escaped_char(&mut out, c, allow_tab));
                break;
            }
            Err(e) => {
                let (good, bad) = rest.split_at(e.valid_up_to());
                if let Ok(s) = std::str::from_utf8(good) {
                    s.chars().for_each(|c| push_escaped_char(&mut out, c, allow_tab));
                }
                let bad_len = e.error_len().unwrap_or(bad.len()).max(1);
                let (invalid, after) = bad.split_at(bad_len.min(bad.len()));
                for b in invalid {
                    let _ = write!(out, "\\x{b:02x}");
                }
                rest = after;
            }
        }
    }
    out
}

/// Escapes arbitrary bytes for safe display on a terminal or inside a JSON
/// string. Backslash is escaped, so the result is unambiguous. Invalid UTF-8
/// becomes `\xNN`, control characters become `\xNN`/`\u{...}`, and bidi or
/// zero-width format characters become `\u{...}`.
pub fn display(bytes: &[u8]) -> String {
    escape_impl(bytes, false)
}

/// Like [`display`] but lets TAB through unchanged (used for text diff bodies).
pub fn display_keep_tab(bytes: &[u8]) -> String {
    escape_impl(bytes, true)
}

/// Escapes a `str`.
pub fn display_str(s: &str) -> String {
    display(s.as_bytes())
}

fn pct_safe(b: u8) -> bool {
    b.is_ascii_alphanumeric() || matches!(b, b'.' | b'_' | b'-' | b'/' | b'+' | b'@' | b'=' | b'~' | b':')
}

/// Percent-encodes bytes for the on-disk text formats. The output contains only
/// `[A-Za-z0-9._-/+@=~:%]`, never whitespace, commas or control characters.
pub fn pct_encode(bytes: &[u8]) -> String {
    let mut out = String::with_capacity(bytes.len());
    for &b in bytes {
        if pct_safe(b) {
            out.push(char::from(b));
        } else {
            let _ = write!(out, "%{b:02X}");
        }
    }
    out
}

fn hex_val(b: u8) -> Option<u8> {
    match b {
        b'0'..=b'9' => Some(b - b'0'),
        b'A'..=b'F' => Some(b - b'A' + 10),
        b'a'..=b'f' => Some(b - b'a' + 10),
        _ => None,
    }
}

/// Inverse of [`pct_encode`]; `None` on malformed escapes.
pub fn pct_decode(s: &str) -> Option<Vec<u8>> {
    let b = s.as_bytes();
    let mut out = Vec::with_capacity(b.len());
    let mut i = 0;
    while i < b.len() {
        let c = *b.get(i)?;
        if c == b'%' {
            let hi = hex_val(*b.get(i + 1)?)?;
            let lo = hex_val(*b.get(i + 2)?)?;
            out.push(hi << 4 | lo);
            i += 3;
        } else {
            out.push(c);
            i += 1;
        }
    }
    Some(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn plain_text_passes_through() {
        assert_eq!(display(b"src/main.rs"), "src/main.rs");
        assert_eq!(display("héllo/日本".as_bytes()), "héllo/日本");
    }

    #[test]
    fn ansi_escape_is_neutralised() {
        let s = display(b"a\x1b[31mred\x1b[0m");
        assert!(!s.contains('\x1b'));
        assert_eq!(s, "a\\x1b[31mred\\x1b[0m");
    }

    #[test]
    fn osc_and_bell_are_neutralised() {
        let s = display(b"\x1b]0;title\x07x");
        assert!(!s.contains('\x1b') && !s.contains('\x07'));
        assert!(s.contains("\\x07"));
    }

    #[test]
    fn newline_and_cr_are_escaped() {
        assert_eq!(display(b"a\nb\rc"), "a\\nb\\rc");
    }

    #[test]
    fn bidi_overrides_are_escaped() {
        let s = display("evil\u{202E}gpj.exe".as_bytes());
        assert!(!s.contains('\u{202E}'));
        assert!(s.contains("\\u{202e}"));
        let s = display("a\u{2066}b\u{2069}".as_bytes());
        assert!(s.contains("\\u{2066}") && s.contains("\\u{2069}"));
    }

    #[test]
    fn zero_width_and_bom_are_escaped() {
        let s = display("a\u{200B}b\u{FEFF}c".as_bytes());
        assert_eq!(s, "a\\u{200b}b\\u{feff}c");
    }

    #[test]
    fn c1_controls_are_escaped() {
        // U+009B is the single-byte CSI introducer.
        let s = display("x\u{9b}31m".as_bytes());
        assert!(!s.contains('\u{9b}'));
    }

    #[test]
    fn invalid_utf8_becomes_hex_escapes() {
        assert_eq!(display(&[b'a', 0xff, 0xfe, b'b']), "a\\xff\\xfeb");
        // truncated multi-byte sequence at the end
        assert_eq!(display(&[b'a', 0xe2, 0x82]), "a\\xe2\\x82");
    }

    #[test]
    fn backslash_is_escaped_so_output_is_unambiguous() {
        assert_eq!(display(b"a\\nb"), "a\\\\nb");
        assert_ne!(display(b"a\\nb"), display(b"a\nb"));
    }

    #[test]
    fn tab_handling() {
        assert_eq!(display(b"a\tb"), "a\\tb");
        assert_eq!(display_keep_tab(b"a\tb"), "a\tb");
    }

    #[test]
    fn nul_and_del_are_escaped() {
        assert_eq!(display(&[0, 0x7f]), "\\x00\\x7f");
    }

    #[test]
    fn pct_round_trip_arbitrary_bytes() {
        let all: Vec<u8> = (0..=255u8).collect();
        let enc = pct_encode(&all);
        assert!(enc.bytes().all(|b| b.is_ascii_graphic()));
        assert!(!enc.contains(' ') && !enc.contains(',') && !enc.contains('\t'));
        assert_eq!(pct_decode(&enc), Some(all));
    }

    #[test]
    fn pct_decode_rejects_malformed() {
        assert!(pct_decode("%").is_none());
        assert!(pct_decode("%4").is_none());
        assert!(pct_decode("%zz").is_none());
    }

    #[test]
    fn pct_encodes_percent_itself() {
        assert_eq!(pct_encode(b"100%"), "100%25");
        assert_eq!(pct_decode("100%25"), Some(b"100%".to_vec()));
    }
}
