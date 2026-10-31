use super::*;

/// Deterministic pseudo-random string over `alphabet`, with one digit forced in.
fn rnd(seed: u64, len: usize, alphabet: &[u8]) -> String {
    let mut x = seed
        .wrapping_mul(6364136223846793005)
        .wrapping_add(1442695040888963407);
    let mut out = Vec::with_capacity(len);
    for _ in 0..len {
        x ^= x << 13;
        x ^= x >> 7;
        x ^= x << 17;
        out.push(alphabet[(x % alphabet.len() as u64) as usize]);
    }
    if len > 4 {
        out[3] = b'7';
    }
    String::from_utf8(out).unwrap()
}

const ALNUM: &[u8] = b"abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";
const UPPER_DIGIT: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";
const B64URL: &[u8] = b"abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789-_";

fn hit(text: &str) -> bool {
    scan_bytes(text.as_bytes()).is_some()
}

#[test]
fn names_dotenv_variants() {
    for n in [
        ".env",
        ".env.local",
        ".env.production",
        "sub/dir/.env",
        ".ENV",
    ] {
        assert!(sensitive_name(n.as_bytes()).is_some(), "{n}");
    }
}

#[test]
fn names_key_material() {
    for n in [
        "a.pem",
        "k.key",
        "id_rsa",
        "id_rsa.pub",
        "id_ed25519",
        "x/id_ecdsa",
        "store.p12",
        "store.pfx",
        "app.jks",
        "release.keystore",
        "vault.kdbx",
        "KEY.PEM",
    ] {
        assert!(sensitive_name(n.as_bytes()).is_some(), "{n}");
    }
}

#[test]
fn names_config_credentials() {
    for n in [
        ".npmrc",
        ".netrc",
        "a/.pypirc",
        ".git-credentials",
        "credentials",
        "credentials.json",
        "aws_credentials",
        "client_secret_123.json",
        "secrets.yml",
        "terraform.tfstate",
        "service-account-prod.json",
    ] {
        assert!(sensitive_name(n.as_bytes()).is_some(), "{n}");
    }
}

#[test]
fn names_credential_directories() {
    for n in [
        ".ssh/config",
        ".aws/config",
        "home/.gnupg/pubring.kbx",
        "a/.kube/x",
        ".ssh/known_hosts",
    ] {
        assert!(sensitive_name(n.as_bytes()).is_some(), "{n}");
    }
}

#[test]
fn names_negative() {
    for n in [
        "src/main.rs",
        "README.md",
        "environment.ts",
        "env.rs",
        "keyboard.rs",
        "monkey.txt",
        "credentials_provider.rs",
        "pem.rs",
        "Cargo.toml",
        ".gitignore",
        "ssh/config",
        "secretary.md",
    ] {
        assert!(sensitive_name(n.as_bytes()).is_none(), "{n}");
    }
}

#[test]
fn dir_itself_named_ssh_is_not_a_file_match() {
    // The directory entry is not sensitive; the files below it are.
    assert!(sensitive_name(b".ssh").is_none());
}

#[test]
fn private_key_headers() {
    for kind in [
        "RSA PRIVATE",
        "EC PRIVATE",
        "OPENSSH PRIVATE",
        "PRIVATE",
        "ENCRYPTED PRIVATE",
        "DSA PRIVATE",
    ] {
        let text = format!("junk\n-----BEGIN {kind} KEY-----\nabc\n");
        assert!(hit(&text), "{kind}");
    }
    assert!(hit(&format!("-----BEGIN {} KEY BLOCK-----", "PGP PRIVATE")));
}

#[test]
fn public_material_is_not_flagged() {
    assert!(!hit(&format!("-----BEGIN {}-----\nMII", "CERTIFICATE")));
    assert!(!hit(&format!("-----BEGIN {} KEY-----", "PUBLIC")));
    assert!(!hit(
        "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIexample user@host"
    ));
}

#[test]
fn aws_key_id() {
    let id = format!("{}{}", "AK", "IA") + &rnd(1, 16, UPPER_DIGIT);
    assert!(hit(&format!("aws_access_key_id = {id}")));
    assert!(hit(&format!("export X={id}")));
    // wrong length / lower case are not key ids
    let short = format!("{}{}", "AK", "IA") + &rnd(1, 10, UPPER_DIGIT);
    assert!(!hit(&format!("x = {short}")));
    let lowercase =
        format!("{}{}", "AK", "IA").to_lowercase() + &rnd(1, 16, UPPER_DIGIT).to_lowercase();
    assert!(!hit(&lowercase));
}

#[test]
fn github_tokens() {
    let t = format!("{}{}", "gh", "p_") + &rnd(2, 36, ALNUM);
    assert!(hit(&format!("token {t}")));
    let pat = format!("{}{}", "github", "_pat_") + &rnd(3, 40, B64URL);
    assert!(hit(&pat));
    let short = format!("{}{}", "gh", "p_") + &rnd(2, 10, ALNUM);
    assert!(!hit(&short));
}

#[test]
fn slack_stripe_google_npm_gitlab() {
    assert!(hit(&(format!("{}{}", "xo", "xb-") + &rnd(4, 24, ALNUM))));
    assert!(hit(&(format!("{}{}", "sk_", "live_") + &rnd(5, 24, ALNUM))));
    assert!(hit(&(format!("{}{}", "whs", "ec_") + &rnd(5, 24, ALNUM))));
    assert!(hit(&(format!("{}{}", "AI", "za") + &rnd(6, 35, B64URL))));
    assert!(hit(&(format!("{}{}", "np", "m_") + &rnd(7, 36, ALNUM))));
    assert!(hit(&(format!("{}{}", "glp", "at-") + &rnd(8, 24, B64URL))));
}

#[test]
fn sk_style_keys_need_mixed_content() {
    let k = format!("{}{}", "s", "k-") + &rnd(9, 40, B64URL);
    assert!(hit(&format!("SERVICE_KEY={k}")));
    // a hyphenated slug is not a key
    assert!(!hit("sk-this-is-just-a-very-long-hyphenated-slug-name"));
    // and a word that merely ends in sk- is not a token start
    assert!(!hit(
        "task-runner-configuration-for-the-build-pipeline-stage"
    ));
}

#[test]
fn jwt_shape() {
    let h = format!("{}{}", "ey", "J") + &rnd(10, 20, B64URL);
    let p = format!("{}{}", "ey", "J") + &rnd(11, 30, B64URL);
    let s = rnd(12, 40, B64URL);
    assert!(hit(&format!("Authorization: {h}.{p}.{s}")));
    assert!(!hit(&format!("{h}.{p}")), "two segments are not a JWT");
    assert!(!hit("version 1.2.3 of the package"));
}

#[test]
fn age_and_sendgrid() {
    let age = format!("{}{}", "AGE-SECRET", "-KEY-1") + &rnd(13, 58, UPPER_DIGIT);
    assert!(hit(&age));
    let sg = format!(
        "{}{}.{}.{}",
        "S",
        "G",
        rnd(14, 22, B64URL),
        rnd(15, 43, B64URL)
    );
    assert!(hit(&sg));
}

#[test]
fn assignment_with_high_entropy_value() {
    let v = rnd(16, 32, ALNUM);
    assert!(hit(&format!("password = \"{v}\"")));
    assert!(hit(&format!("API_KEY: {v}")));
    assert!(hit(&format!("{{\"client_secret\": \"{v}\"}}")));
    assert!(hit(&format!("export SECRET_TOKEN='{v}'")));
    assert!(hit(&format!("auth_token:={v}")));
    assert!(hit(&format!("Authorization: Bearer {v}")));
}

#[test]
fn assignment_negatives() {
    assert!(!hit("password = \"changeme\""));
    assert!(!hit(
        "password = hash_password(user_input_value_that_is_long)"
    ));
    assert!(!hit("token: ${{ secrets.GITHUB_TOKEN }}"));
    assert!(!hit(
        "const secret = process.env.JWT_SECRET_KEY_FOR_SIGNING_TOKENS;"
    ));
    assert!(!hit(
        "let token = tokenizer.next_token_from_the_input_stream();"
    ));
    assert!(!hit(
        "password_field_label = \"Enter your password here please\""
    ));
    assert!(!hit(
        "the word password appears here but nothing is assigned"
    ));
}

#[test]
fn low_entropy_long_values_are_ignored() {
    let v = "a1".repeat(15);
    assert!(!hit(&format!("password = {v}")));
    assert!(!hit(&format!("token = {}", "0".repeat(40))));
}

#[test]
fn url_credentials_detected() {
    let pw = rnd(17, 16, ALNUM);
    assert!(hit(&format!(
        "DATABASE_URL=postgres://app:{pw}@db.internal:5432/app"
    )));
    assert!(
        !hit("https://user:pass@example.com/"),
        "short placeholder password"
    );
    assert!(!hit("postgres://app:${DB_PASSWORD}@db/app"));
    assert!(!hit("https://example.com/path:with:colons@x"));
    assert!(!hit("see https://github.com/org/repo for details"));
}

#[test]
fn ordinary_source_code_is_not_flagged() {
    let code = r#"
        fn main() {
            let key = "abc";
            let names = vec!["alice", "bob"];
            println!("{}", names.join(","));
            // https://example.com/docs#section
        }
    "#;
    assert!(!hit(code));
    assert!(!hit(&"lorem ipsum dolor sit amet ".repeat(2000)));
}

#[test]
fn binary_noise_does_not_panic() {
    let mut x = 12345u64;
    let data: Vec<u8> = (0..200_000)
        .map(|_| {
            x = x.wrapping_mul(6364136223846793005).wrapping_add(1);
            (x >> 33) as u8
        })
        .collect();
    let _ = scan_bytes(&data);
}

#[test]
fn token_split_across_chunk_boundary_is_found() {
    let t = format!("{}{}", "gh", "p_") + &rnd(20, 36, ALNUM);
    let text = format!("{} {t} tail", "x".repeat(100));
    let bytes = text.as_bytes();
    for split in [1, 50, 101, 105, 120, 130] {
        let mut s = Scanner::new();
        assert!(s.feed(&bytes[..split]).is_none() || split > 104);
        let res = s.feed(&bytes[split..]);
        assert!(res.is_some() || s.result().is_some(), "split at {split}");
    }
}

#[test]
fn header_split_across_chunks_is_found() {
    let text = format!("pad\n-----BEGIN {} KEY-----\n", "RSA PRIVATE");
    let b = text.as_bytes();
    for split in 1..b.len() {
        let mut s = Scanner::new();
        let a = s.feed(&b[..split]);
        let c = s.feed(&b[split..]);
        assert!(a.is_some() || c.is_some(), "split {split}");
    }
}

#[test]
fn scanner_memory_is_bounded() {
    let mut s = Scanner::new();
    let chunk = vec![b'x'; 64 * 1024];
    for _ in 0..200 {
        assert!(s.feed(&chunk).is_none());
        assert!(s.carry.len() <= OVERLAP);
    }
}

#[test]
fn found_state_is_sticky() {
    let mut s = Scanner::new();
    assert!(
        s.feed(format!("-----BEGIN {} KEY-----", "PRIVATE").as_bytes())
            .is_some()
    );
    assert!(s.feed(b"clean").is_some());
}

#[test]
fn entropy_values() {
    assert_eq!(shannon_entropy(b""), 0.0);
    assert_eq!(shannon_entropy(b"aaaa"), 0.0);
    assert!((shannon_entropy(b"abcd") - 2.0).abs() < 1e-9);
}
