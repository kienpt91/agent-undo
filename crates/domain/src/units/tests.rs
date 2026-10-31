use super::*;

#[test]
fn utc_formatting_known_points() {
    assert_eq!(format_utc(0), "1970-01-01T00:00:00Z");
    assert_eq!(
        format_utc(951_782_400 * 1_000_000_000),
        "2000-02-29T00:00:00Z"
    );
    assert_eq!(
        format_utc(1_700_000_000 * 1_000_000_000),
        "2023-11-14T22:13:20Z"
    );
    assert_eq!(format_utc(-1_000_000_000), "1969-12-31T23:59:59Z");
}

#[test]
fn duration_parsing() {
    assert_eq!(parse_duration("500ms").unwrap(), Duration::from_millis(500));
    assert_eq!(parse_duration("2s").unwrap(), Duration::from_secs(2));
    assert_eq!(parse_duration("3").unwrap(), Duration::from_secs(3));
    assert_eq!(parse_duration("5m").unwrap(), Duration::from_secs(300));
    assert_eq!(parse_duration("1h").unwrap(), Duration::from_secs(3600));
    assert_eq!(
        parse_duration("7d").unwrap(),
        Duration::from_secs(7 * 86_400)
    );
    assert!(parse_duration("x").is_err());
    assert!(parse_duration("5y").is_err());
    assert!(parse_duration("").is_err());
    assert!(parse_duration("99999999999999999999d").is_err());
    assert!(parse_duration("18446744073709551615d").is_err());
}

#[test]
fn size_parsing() {
    assert_eq!(parse_size("25MiB").unwrap(), 25 << 20);
    assert_eq!(parse_size("64k").unwrap(), 64 << 10);
    assert_eq!(parse_size("1048576").unwrap(), 1 << 20);
    assert_eq!(parse_size("2G").unwrap(), 2 << 30);
    assert!(parse_size("1TB").is_err());
    assert!(parse_size("-1").is_err());
    assert!(parse_size("18446744073709551615GiB").is_err());
}

#[test]
fn human_sizes() {
    assert_eq!(human_size(10), "10 B");
    assert_eq!(human_size(1536), "1.5 KiB");
    assert_eq!(human_size(25 << 20), "25.0 MiB");
}
