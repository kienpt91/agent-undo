//! Pure formatting and parsing of times, durations and sizes.

use crate::error::{DomainError, DomainResult};
use crate::esc::display_str;
use std::time::Duration;

/// Formats nanoseconds since the Unix epoch as `YYYY-MM-DDTHH:MM:SSZ` (UTC).
pub fn format_utc(ns: i64) -> String {
    let secs = ns.div_euclid(1_000_000_000);
    let days = secs.div_euclid(86_400);
    let rem = secs.rem_euclid(86_400);
    let z = days + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z.rem_euclid(146_097);
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let mut y = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    if m <= 2 {
        y += 1;
    }
    format!(
        "{y:04}-{m:02}-{d:02}T{:02}:{:02}:{:02}Z",
        rem / 3600,
        (rem % 3600) / 60,
        rem % 60
    )
}

fn split_number(s: &str) -> (&str, &str) {
    let split = s.find(|c: char| !c.is_ascii_digit()).unwrap_or(s.len());
    s.split_at(split)
}

/// Parses `500ms`, `2s`, `5m`, `1h`, `7d` (a bare number means seconds).
pub fn parse_duration(s: &str) -> DomainResult<Duration> {
    let s = s.trim();
    let (num, unit) = split_number(s);
    let n: u64 = num
        .parse()
        .map_err(|_| DomainError::Usage(format!("invalid duration {:?}", display_str(s))))?;
    let ms_per_unit: u64 = match unit {
        "ms" => 1,
        "" | "s" => 1000,
        "m" => 60_000,
        "h" => 3_600_000,
        "d" => 86_400_000,
        _ => {
            return Err(DomainError::Usage(format!(
                "invalid duration unit in {:?} (use ms, s, m, h, d)",
                display_str(s)
            )));
        }
    };
    let ms = n
        .checked_mul(ms_per_unit)
        .ok_or_else(|| DomainError::Usage("duration too large".into()))?;
    Ok(Duration::from_millis(ms))
}

/// Parses a size such as `25MiB`, `64K`, `1048576` (powers of 1024).
pub fn parse_size(s: &str) -> DomainResult<u64> {
    let s = s.trim();
    let (num, unit) = split_number(s);
    let n: u64 = num
        .parse()
        .map_err(|_| DomainError::Usage(format!("invalid size {:?}", display_str(s))))?;
    let mult: u64 = match unit.to_ascii_lowercase().as_str() {
        "" | "b" => 1,
        "k" | "kb" | "kib" => 1 << 10,
        "m" | "mb" | "mib" => 1 << 20,
        "g" | "gb" | "gib" => 1 << 30,
        _ => {
            return Err(DomainError::Usage(format!(
                "invalid size unit in {:?} (use B, KiB, MiB, GiB)",
                display_str(s)
            )));
        }
    };
    n.checked_mul(mult)
        .ok_or_else(|| DomainError::Usage("size too large".into()))
}

/// Human-readable byte count (`1.5 KiB`).
pub fn human_size(n: u64) -> String {
    const UNITS: [&str; 5] = ["B", "KiB", "MiB", "GiB", "TiB"];
    let mut v = n as f64;
    let mut i = 0;
    while v >= 1024.0 && i + 1 < UNITS.len() {
        v /= 1024.0;
        i += 1;
    }
    if i == 0 {
        format!("{n} B")
    } else {
        format!("{v:.1} {}", UNITS.get(i).copied().unwrap_or("B"))
    }
}

#[cfg(test)]
mod tests {
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
}
