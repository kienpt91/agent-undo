use super::*;

#[test]
fn exit_codes_per_class() {
    let cases = [
        (Error::Usage("x".into()), exit::USAGE),
        (Error::Refused("x".into()), exit::REFUSED),
        (Error::Locked("x".into()), exit::LOCKED),
        (Error::Integrity("x".into()), exit::INTEGRITY),
        (Error::NotInitialized("x".into()), exit::NOT_INITIALIZED),
        (Error::Other("x".into()), exit::FAILURE),
        (Error::Limit("x".into()), exit::FAILURE),
    ];
    for (e, c) in cases {
        assert_eq!(e.exit_code(), c);
    }
}

#[test]
fn domain_errors_map_to_matching_classes() {
    assert_eq!(Error::from(DomainError::Usage("u".into())).code(), "usage");
    assert_eq!(
        Error::from(DomainError::Integrity("i".into())).code(),
        "integrity"
    );
    assert_eq!(
        Error::from(DomainError::Refused("r".into())).code(),
        "refused"
    );
    assert_eq!(
        Error::from(DomainError::Unsafe("s".into())).code(),
        "unsafe_path"
    );
    assert_eq!(Error::from(DomainError::Limit("l".into())).code(), "limit");
    assert_eq!(
        Error::from(DomainError::Invalid("v".into())).code(),
        "format"
    );
}

#[test]
fn io_error_display_includes_context_and_codes_are_stable() {
    let e = Error::io("reading x", std::io::Error::other("boom"));
    assert_eq!(e.to_string(), "reading x: boom");
    assert_eq!(e.code(), "io");
    assert!(std::error::Error::source(&e).is_some());
    let codes = [
        Error::Format(String::new()).code(),
        Error::NotInitialized(String::new()).code(),
        Error::AlreadyInitialized(String::new()).code(),
        Error::Other(String::new()).code(),
    ];
    assert_eq!(
        codes,
        ["format", "not_initialized", "already_initialized", "error"]
    );
}

#[test]
fn ctx_wraps_io_errors() {
    let r: std::io::Result<()> = Err(std::io::Error::other("nope"));
    let e = r.ctx(|| "doing a thing".into()).unwrap_err();
    assert_eq!(e.to_string(), "doing a thing: nope");
}
