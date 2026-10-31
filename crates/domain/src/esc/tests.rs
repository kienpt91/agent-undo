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
