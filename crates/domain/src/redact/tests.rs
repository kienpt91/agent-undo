use super::*;

fn args(a: &[&str]) -> Vec<Vec<u8>> {
    a.iter().map(|s| s.as_bytes().to_vec()).collect()
}

fn text(v: &[Vec<u8>]) -> String {
    v.iter()
        .map(|a| String::from_utf8_lossy(a).into_owned())
        .collect::<Vec<_>>()
        .join(" ")
}

#[test]
fn ordinary_arguments_are_kept() {
    let a = args(&[
        "cargo",
        "test",
        "--workspace",
        "-p",
        "agent-undo",
        "--",
        "--nocapture",
    ]);
    assert_eq!(redact_args(&a), a);
}

#[test]
fn token_shapes_and_url_credentials_are_replaced() {
    let token = format!("{}{}", "gh", "p_") + "A1b2C3d4E5f6G7h8I9j0K1l2M3n4O5p6Q7r8";
    let url = format!("postgres://app:{}@db.internal/app", "Zk3Qx9Lm2Vb8Nc4R");
    let out = redact_args(&args(&["tool", &token, &url]));
    assert_eq!(text(&out), format!("tool {REDACTED} {REDACTED}"));
}

#[test]
fn flag_values_of_secret_flags_are_replaced_in_both_forms() {
    let out = redact_args(&args(&[
        "deploy",
        "--password",
        "hunter2",
        "--token=abc",
        "--region",
        "eu",
    ]));
    assert_eq!(
        text(&out),
        format!("deploy --password {REDACTED} --token={REDACTED} --region eu")
    );
    let out = redact_args(&args(&[
        "x",
        "--api-key",
        "k",
        "--api_key=k2",
        "--client-secret",
        "s",
    ]));
    assert_eq!(
        text(&out),
        format!("x --api-key {REDACTED} --api_key={REDACTED} --client-secret {REDACTED}")
    );
}

#[test]
fn a_secret_flag_without_a_value_does_not_swallow_the_next_flag() {
    let out = redact_args(&args(&["x", "--token", "--verbose"]));
    assert_eq!(text(&out), "x --token --verbose");
    let out = redact_args(&args(&["x", "--password"]));
    assert_eq!(text(&out), "x --password");
}

#[test]
fn environment_style_assignments_are_replaced_by_value() {
    let out = redact_args(&args(&["env", "DB_PASSWORD=hunter2", "PORT=8080", "sh"]));
    assert_eq!(
        text(&out),
        format!("env DB_PASSWORD={REDACTED} PORT=8080 sh")
    );
}

#[test]
fn http_credential_headers_are_replaced_after_the_colon() {
    let out = redact_args(&args(&[
        "curl",
        "-H",
        "Authorization: Bearer abc",
        "-H",
        "X-Api-Key: k",
        "-H",
        "Accept: application/json",
    ]));
    assert_eq!(
        text(&out),
        format!(
            "curl -H Authorization: {REDACTED} -H X-Api-Key: {REDACTED} -H Accept: application/json"
        )
    );
}

#[test]
fn invalid_utf8_and_empty_arguments_are_handled() {
    let a = vec![
        b"x".to_vec(),
        vec![0xff, 0xfe],
        Vec::new(),
        b"--token".to_vec(),
        vec![0xff],
    ];
    let out = redact_args(&a);
    assert_eq!(out.len(), 5);
    assert_eq!(out.get(1), Some(&vec![0xff, 0xfe]));
    assert_eq!(out.get(4), Some(&REDACTED.as_bytes().to_vec()));
}

#[test]
fn redaction_is_idempotent() {
    let a = args(&["x", "--password", "hunter2", "TOKEN=abcdef12"]);
    let once = redact_args(&a);
    assert_eq!(redact_args(&once), once);
}

#[test]
fn labels_that_look_like_secrets_are_replaced() {
    assert_eq!(redact_label(b"fix the build"), b"fix the build");
    assert_eq!(redact_label(b"DB_PASSWORD=hunter2"), REDACTED.as_bytes());
    let token = format!("{}{}", "gh", "p_") + "A1b2C3d4E5f6G7h8I9j0K1l2M3n4O5p6Q7r8";
    assert_eq!(redact_label(token.as_bytes()), REDACTED.as_bytes());
}

#[test]
fn assignments_inside_a_shell_script_argument_are_redacted_in_place() {
    let out = redact_args(&args(&[
        "sh",
        "-c",
        "export DB_PASSWORD=hunter2; printf 'API_TOKEN=abc12345\\nPORT=5432\\n' > .env && ./run",
    ]));
    let joined = text(&out);
    assert!(
        !joined.contains("hunter2") && !joined.contains("abc12345"),
        "{joined}"
    );
    assert!(
        joined.contains("export DB_PASSWORD=[redacted];"),
        "{joined}"
    );
    assert!(
        joined.contains("&& ./run"),
        "the rest of the script stays readable: {joined}"
    );
}

#[test]
fn scripts_without_secret_assignments_are_untouched() {
    let a = args(&[
        "sh",
        "-c",
        "PORT=8080 HOST=localhost cargo run --release && echo done",
    ]);
    assert_eq!(redact_args(&a), a);
}
