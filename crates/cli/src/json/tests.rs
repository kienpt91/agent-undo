use super::*;

#[test]
fn scalars_serialize() {
    assert_eq!(Json::Null.to_compact(), "null");
    assert_eq!(Json::from(true).to_compact(), "true");
    assert_eq!(Json::from(-5i64).to_compact(), "-5");
    assert_eq!(Json::from(7u64).to_compact(), "7");
}

#[test]
fn strings_are_escaped() {
    assert_eq!(
        Json::from("a\"b\\c\n\u{1}").to_compact(),
        "\"a\\\"b\\\\c\\n\\u0001\""
    );
}

#[test]
fn objects_and_arrays_nest() {
    let j = Json::obj()
        .with("a", 1u64)
        .with("b", vec!["x", "y"])
        .with("c", Json::obj().with("d", Option::<u64>::None));
    assert_eq!(j.to_compact(), r#"{"a":1,"b":["x","y"],"c":{"d":null}}"#);
}

#[test]
fn output_is_single_line() {
    let j = Json::obj().with("k", "line1\nline2");
    assert!(!j.to_compact().contains('\n'));
}
