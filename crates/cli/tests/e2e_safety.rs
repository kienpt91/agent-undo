//! End-to-end safety scenarios for the real `agent-undo` binary: hostile file
//! names, symlinks, secrets, ignore rules, file modes, special files.
//!
//! Secret-shaped fixtures are assembled at runtime so no key-shaped literal
//! appears in this source file.

mod common;

use common::*;
use std::fs;
use std::io::Write;
use std::os::unix::fs::FileTypeExt;
use std::process::Stdio;
use std::time::Duration;

const EVIL_ESC: &str = "evil\u{1b}[31mred.txt";
const EVIL_NL: &str = "line1\nline2.txt";
const EVIL_BIDI: &str = "invoice\u{202e}fdp.exe";

fn github_token() -> String {
    format!("{}{}", "gh", "p_") + "A1b2C3d4E5f6G7h8I9j0K1l2M3n4O5p6Q7r8"
}

/// Deterministic pseudo-random base64-looking text, built at runtime so no key
/// material (not even a well-known sample) appears in the source.
fn pseudo_b64(seed: u64, len: usize) -> String {
    const ALPHABET: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut x = seed
        .wrapping_mul(6364136223846793005)
        .wrapping_add(1442695040888963407);
    (0..len)
        .map(|_| {
            x ^= x << 13;
            x ^= x >> 7;
            x ^= x << 17;
            char::from(ALPHABET[(x % ALPHABET.len() as u64) as usize])
        })
        .collect()
}

fn pem_body_lines() -> Vec<String> {
    (1..=3).map(|i| pseudo_b64(900 + i, 64)).collect()
}

fn private_key_block() -> String {
    let head = format!("-----BEGIN {} KEY-----", "RSA PRIVATE");
    let tail = format!("-----END {} KEY-----", "RSA PRIVATE");
    format!("{head}\n{}\n{tail}\n", pem_body_lines().join("\n"))
}

fn secret_value(tag: &str) -> String {
    // A long mixed-case value that looks like a credential.
    format!("{}{}", tag, "Zk3Qx9Lm2Vb8Nc4Rt7Yw1Hd6Pf5Js0Ga")
}

/// Shell snippet that creates the three hostile file names from printf escapes.
const MAKE_HOSTILE: &str = r#"printf x > "$(printf 'evil\033[31mred.txt')"; printf x > "$(printf 'line1\nline2.txt')"; printf x > "$(printf 'invoice\342\200\256fdp.exe')""#;

fn assert_clean_terminal_text(text: &str) {
    assert!(!text.contains('\u{1b}'), "raw ESC in output: {text:?}");
    assert!(!text.contains('\u{202e}'), "raw RLO in output: {text:?}");
    assert!(!text.contains('\u{7}'), "raw BEL in output: {text:?}");
    assert!(!text.contains('\r'), "raw CR in output: {text:?}");
}

// ------------------------------------------------------------ hostile names

#[test]
fn hostile_file_names_are_escaped_in_human_diff() {
    let p = Proj::inited("hostile-diff");
    p.agent(MAKE_HOSTILE);
    assert!(p.exists(EVIL_ESC) && p.exists(EVIL_NL) && p.exists(EVIL_BIDI));
    let o = p.run(&["diff", "2"]);
    assert_eq!(o.code, 0, "{}", o.all());
    assert_clean_terminal_text(&o.stdout);
    assert!(o.stdout.contains("A  evil\\x1b[31mred.txt"), "{}", o.stdout);
    assert!(o.stdout.contains("A  line1\\nline2.txt"), "{}", o.stdout);
    assert!(
        o.stdout.contains("A  invoice\\u{202e}fdp.exe"),
        "{}",
        o.stdout
    );
    // The newline in a name never starts a new output line.
    assert!(
        !o.stdout.lines().any(|l| l.starts_with("line2.txt")),
        "{}",
        o.stdout
    );
    assert!(o.stdout.contains("+++ b/line1\\nline2.txt"), "{}", o.stdout);
}

#[test]
fn hostile_file_names_are_escaped_in_undo_output() {
    let p = Proj::inited("hostile-undo");
    p.agent(MAKE_HOSTILE);
    let dry = p.run(&["undo", "2"]);
    assert_eq!(dry.code, 0, "{}", dry.all());
    assert_clean_terminal_text(&dry.stdout);
    assert!(
        dry.stdout.contains("evil\\x1b[31mred.txt"),
        "{}",
        dry.stdout
    );
    assert!(dry.stdout.contains("line1\\nline2.txt"), "{}", dry.stdout);
    assert!(!dry.stdout.lines().any(|l| l.starts_with("line2.txt")));
    assert!(p.exists(EVIL_ESC), "dry run");
    let o = p.run(&["undo", "2", "--apply"]);
    assert_eq!(o.code, 0, "{}", o.all());
    assert_clean_terminal_text(&o.stdout);
    assert!(!p.exists(EVIL_ESC) && !p.exists(EVIL_NL) && !p.exists(EVIL_BIDI));
}

#[test]
fn hostile_file_names_are_escaped_in_json_with_a_percent_encoded_twin() {
    let p = Proj::inited("hostile-json");
    p.agent(MAKE_HOSTILE);
    let o = p.run(&["--json", "diff", "2"]);
    assert_eq!(o.code, 0, "{}", o.all());
    assert_clean_terminal_text(&o.stdout);
    assert_eq!(
        o.stdout.matches('\n').count(),
        1,
        "a name must not break the JSON line"
    );
    let j = o.json();
    let by_path = |path: &str| {
        j.p("changes")
            .arr()
            .iter()
            .find(|c| c.p("path").str() == path)
            .unwrap_or_else(|| panic!("no change for {path}: {}", o.stdout))
            .p("path_pct")
            .str()
            .to_string()
    };
    assert_eq!(by_path("evil\\x1b[31mred.txt"), "evil%1B%5B31mred.txt");
    assert_eq!(by_path("line1\\nline2.txt"), "line1%0Aline2.txt");
    assert_eq!(
        by_path("invoice\\u{202e}fdp.exe"),
        "invoice%E2%80%AEfdp.exe"
    );
    // The undo plan uses the same two fields.
    let u = p.run(&["--json", "undo", "2"]);
    assert_clean_terminal_text(&u.stdout);
    let uj = u.json();
    assert!(
        uj.p("items")
            .arr()
            .iter()
            .all(|i| !i.p("path_pct").str().contains('\u{1b}'))
    );
}

#[test]
fn hostile_pending_paths_are_escaped_in_status_json() {
    let p = Proj::inited("hostile-status");
    p.write(EVIL_ESC, "x");
    p.write(EVIL_BIDI, "y");
    let o = p.run(&["--json", "status"]);
    assert_eq!(o.code, 0, "{}", o.all());
    assert_clean_terminal_text(&o.stdout);
    let j = o.json();
    assert_eq!(j.p("pending.counts.created").u64(), 2);
    let paths: Vec<&str> = j
        .p("pending.sample")
        .arr()
        .iter()
        .map(|c| c.p("path").str())
        .collect();
    assert!(paths.contains(&"evil\\x1b[31mred.txt"), "{paths:?}");
    assert!(paths.contains(&"invoice\\u{202e}fdp.exe"), "{paths:?}");
}

#[test]
fn hostile_project_directory_name_is_escaped_in_init_status_and_doctor() {
    let p = Proj::named("hostile-root", "pr\u{1b}[2Jo\nj\u{202e}x");
    p.write("a.txt", "x");
    let init = p.run(&["init"]);
    assert_eq!(init.code, 0, "{}", init.all());
    assert_clean_terminal_text(&init.stdout);
    assert!(
        init.stdout.contains("pr\\x1b[2Jo\\nj\\u{202e}x"),
        "{}",
        init.stdout
    );
    for cmd in ["status", "doctor"] {
        let o = p.run(&[cmd]);
        assert_eq!(o.code, 0, "{cmd}: {}", o.all());
        assert_clean_terminal_text(&o.stdout);
        assert!(
            !o.stdout.lines().any(|l| l.starts_with("j\\u")),
            "{cmd}: {}",
            o.stdout
        );
    }
    let st = p.run(&["status"]);
    assert_eq!(
        st.stdout.lines().next().unwrap().matches("\\n").count(),
        1,
        "{}",
        st.stdout
    );
    // The JSON carries the escaped form too (still a single, parseable line).
    let j = p.run(&["--json", "status"]);
    assert_clean_terminal_text(&j.stdout);
    assert!(
        j.json()
            .p("project")
            .str()
            .contains("pr\\x1b[2Jo\\nj\\u{202e}x")
    );
}

#[test]
fn hostile_labels_and_commands_are_escaped_in_log_diff_and_run_report() {
    let p = Proj::inited("hostile-label");
    let o = p.run(&[
        "run",
        "--label",
        "evil\u{1b}[31mlabel\u{7}",
        "--",
        "sh",
        "-c",
        "echo x > f.txt; : 'a\u{1b}[0m'",
    ]);
    assert_eq!(o.code, 0, "{}", o.all());
    assert_clean_terminal_text(&o.stderr);
    let log = p.run(&["log"]);
    assert_clean_terminal_text(&log.stdout);
    assert!(
        log.stdout.contains("evil\\x1b[31mlabel\\x07"),
        "{}",
        log.stdout
    );
    assert!(log.stdout.contains("a\\x1b[0m"), "{}", log.stdout);
    let diff = p.run(&["diff", "2"]);
    assert_clean_terminal_text(&diff.stdout);
    assert!(
        diff.stdout.contains("label: evil\\x1b[31mlabel\\x07"),
        "{}",
        diff.stdout
    );
    let j = p.run(&["--json", "log"]);
    assert_clean_terminal_text(&j.stdout);
    assert_eq!(
        j.json().p("checkpoints.1.label").str(),
        "evil\\x1b[31mlabel\\x07"
    );
}

#[test]
fn hostile_file_content_is_escaped_in_text_diffs() {
    let p = Proj::inited("hostile-content");
    p.agent("printf 'safe\\n\\033]0;owned\\007\\nbidi \\342\\200\\256 end\\n' > notes.txt");
    let o = p.run(&["diff", "2"]);
    assert_eq!(o.code, 0, "{}", o.all());
    assert_clean_terminal_text(&o.stdout);
    assert!(o.stdout.contains("+safe"), "{}", o.stdout);
    assert!(o.stdout.contains("\\x1b]0;owned\\x07"), "{}", o.stdout);
    let j = p.run(&["--json", "diff", "2"]);
    assert_clean_terminal_text(&j.stdout);
}

#[test]
fn hostile_symlink_targets_are_escaped() {
    let p = Proj::inited("hostile-link");
    p.agent("ln -s \"$(printf 'tgt\\033[0m')\" hostile-link");
    let o = p.run(&["diff", "2"]);
    assert_eq!(o.code, 0, "{}", o.all());
    assert_clean_terminal_text(&o.stdout);
    assert!(o.stdout.contains("symlink -> tgt\\x1b[0m"), "{}", o.stdout);
    let j = p.run(&["--json", "diff", "2"]);
    assert_clean_terminal_text(&j.stdout);
    assert_eq!(j.json().p("changes.0.after.target").str(), "tgt\\x1b[0m");
}

#[test]
fn restore_of_a_hostile_path_works_and_prints_it_escaped() {
    let p = Proj::new("hostile-restore");
    p.write(EVIL_ESC, "original\n");
    p.write(EVIL_NL, "original\n");
    p.run(&["init"]);
    p.agent("echo changed > \"$(printf 'evil\\033[31mred.txt')\"; echo changed > \"$(printf 'line1\\nline2.txt')\"");
    let o = p.run(&["restore", EVIL_ESC, "--from", "1", "--apply"]);
    assert_eq!(o.code, 0, "{}", o.all());
    assert_clean_terminal_text(&o.stdout);
    assert!(o.stdout.contains("evil\\x1b[31mred.txt"), "{}", o.stdout);
    assert_eq!(p.read(EVIL_ESC), "original\n");
    assert_eq!(p.read(EVIL_NL), "changed\n");
    let o = p.run(&["restore", EVIL_NL, "--from", "1", "--apply"]);
    assert_eq!(o.code, 0, "{}", o.all());
    assert_eq!(p.read(EVIL_NL), "original\n");
}

#[test]
fn hostile_names_survive_verify_gc_and_undo_round_trips() {
    let p = Proj::new("hostile-roundtrip");
    p.write(EVIL_BIDI, "payload\n");
    p.run(&["init"]);
    p.agent(r#"rm "$(printf 'invoice\342\200\256fdp.exe')""#);
    assert!(!p.exists(EVIL_BIDI));
    assert_eq!(p.run(&["undo", "2", "--apply"]).code, 0);
    assert_eq!(p.read(EVIL_BIDI), "payload\n");
    assert_eq!(p.run(&["verify"]).code, 0);
    assert_eq!(p.run(&["gc", "--keep", "2", "--apply"]).code, 0);
    assert_eq!(p.run(&["verify"]).code, 0);
}

// ----------------------------------------------------------------- symlinks

#[test]
fn a_symlink_to_etc_is_recorded_as_a_link_and_undo_removes_only_the_link() {
    let p = Proj::inited("symlink-etc");
    p.agent("ln -s /etc etc-link");
    let j = p.json(&["diff", "2"]);
    assert_eq!(
        j.p("changes").arr().len(),
        1,
        "nothing below the link is recorded"
    );
    assert_eq!(j.p("changes.0.path").str(), "etc-link");
    assert_eq!(j.p("changes.0.after.kind").str(), "symlink");
    assert_eq!(j.p("changes.0.after.target").str(), "/etc");
    let human = p.run(&["diff", "2"]);
    assert!(
        human.stdout.contains("A  etc-link  (symlink -> /etc)"),
        "{}",
        human.stdout
    );
    assert_eq!(p.run(&["undo", "2", "--apply"]).code, 0);
    assert!(!p.exists("etc-link"));
    assert!(fs::metadata("/etc").unwrap().is_dir());
    assert!(
        fs::metadata("/etc/passwd").is_ok(),
        "/etc must be untouched"
    );
}

#[test]
fn writes_through_a_symlink_to_an_outside_directory_are_not_tracked_or_undone() {
    let p = Proj::inited("symlink-outside");
    let outside = p.base.join("outside");
    fs::create_dir_all(&outside).unwrap();
    fs::write(outside.join("existing.txt"), "keep\n").unwrap();
    let script = format!(
        "ln -s '{}' link; echo agent > link/new.txt",
        outside.display()
    );
    p.agent(&script);
    assert!(outside.join("new.txt").exists());
    let d = p.json(&["diff", "2"]);
    assert_eq!(d.p("changes").arr().len(), 1, "{d:?}");
    assert_eq!(d.p("changes.0.path").str(), "link");
    assert_eq!(p.run(&["undo", "2", "--apply"]).code, 0);
    assert!(!p.exists("link"));
    assert_eq!(
        fs::read_to_string(outside.join("existing.txt")).unwrap(),
        "keep\n"
    );
    assert!(
        outside.join("new.txt").exists(),
        "files outside the project are never touched"
    );
}

#[test]
fn restore_never_writes_through_a_symlinked_parent() {
    let p = Proj::new("symlink-parent");
    let outside = p.base.join("outside");
    fs::create_dir_all(&outside).unwrap();
    fs::write(outside.join("f.txt"), "outside-original\n").unwrap();
    p.write("d/f.txt", "inside-original\n");
    p.run(&["init"]);
    p.agent("rm -rf d; ln -s ../outside d");
    assert!(
        fs::symlink_metadata(p.path("d"))
            .unwrap()
            .file_type()
            .is_symlink()
    );

    let o = p.run(&["restore", "d/f.txt", "--from", "1", "--apply"]);
    assert_eq!(
        fs::read_to_string(outside.join("f.txt")).unwrap(),
        "outside-original\n",
        "restore followed a symlink out of the project: {}",
        o.all()
    );
    assert!(
        fs::symlink_metadata(p.path("d"))
            .unwrap()
            .file_type()
            .is_symlink()
    );

    let o = p.run(&["undo", "2", "--apply"]);
    assert_eq!(
        fs::read_to_string(outside.join("f.txt")).unwrap(),
        "outside-original\n",
        "undo followed a symlink out of the project: {}",
        o.all()
    );
    assert_eq!(fs::read_dir(&outside).unwrap().count(), 1);
}

#[test]
fn a_replaced_file_symlink_is_restored_as_a_real_file() {
    let p = Proj::new("symlink-replaced");
    p.write("config.txt", "real content\n");
    p.run(&["init"]);
    p.agent("rm config.txt; ln -s /etc/hostname config.txt");
    assert_eq!(p.run(&["undo", "2", "--apply"]).code, 0);
    assert!(
        fs::symlink_metadata(p.path("config.txt"))
            .unwrap()
            .file_type()
            .is_file()
    );
    assert_eq!(p.read("config.txt"), "real content\n");
}

#[test]
fn a_symlink_created_by_an_agent_survives_checkpoint_and_verify() {
    let p = Proj::inited("symlink-dangling");
    p.agent("ln -s does-not-exist dangling");
    assert_eq!(p.run(&["verify"]).code, 0);
    assert_eq!(p.json(&["status"]).p("pending.counts.total").u64(), 0);
    assert_eq!(p.run(&["undo", "2", "--apply"]).code, 0);
    assert!(!p.exists("dangling"));
}

// -------------------------------------------------- modes, renames, dirs

#[test]
fn a_chmod_by_the_agent_is_a_mode_change_and_is_undone() {
    let p = Proj::new("mode-chmod");
    p.write("tool.sh", "#!/bin/sh\necho tool\n");
    p.chmod("tool.sh", 0o644);
    p.run(&["init"]);
    p.agent("chmod +x tool.sh");
    assert_eq!(p.mode("tool.sh") & 0o111, 0o111);
    let d = p.run(&["diff", "2"]);
    assert!(d.stdout.contains("1 mode-changed"), "{}", d.stdout);
    assert!(
        d.stdout.contains("T  tool.sh  (mode 0644 -> 0755)"),
        "{}",
        d.stdout
    );
    let o = p.run(&["undo", "2", "--apply"]);
    assert_eq!(o.code, 0, "{}", o.all());
    assert_eq!(p.mode("tool.sh"), 0o644);
    assert_eq!(p.read("tool.sh"), "#!/bin/sh\necho tool\n");
}

#[test]
fn the_executable_bit_is_preserved_when_a_deleted_file_is_restored() {
    let p = Proj::new("mode-exec");
    p.write("run.sh", "#!/bin/sh\necho hi\n");
    p.chmod("run.sh", 0o755);
    p.write("private.key.txt", "k\n");
    p.chmod("private.key.txt", 0o600);
    p.run(&["init"]);
    p.agent("rm run.sh private.key.txt");
    assert_eq!(p.run(&["undo", "2", "--apply"]).code, 0);
    assert_eq!(p.mode("run.sh"), 0o755);
    assert_eq!(p.mode("private.key.txt"), 0o600);
    // And the restored script really runs.
    let o = p.run(&["run", "--", "./run.sh"]);
    assert_eq!(o.code, 0, "{}", o.all());
    assert_eq!(o.stdout, "hi\n");
}

#[test]
fn restore_from_a_checkpoint_resets_both_content_and_mode() {
    let p = Proj::new("mode-restore");
    p.write("script.sh", "echo one\n");
    p.chmod("script.sh", 0o755);
    p.run(&["init"]);
    p.agent("echo two > script.sh; chmod 600 script.sh");
    assert_eq!(p.mode("script.sh"), 0o600);
    let o = p.run(&["restore", "script.sh", "--from", "1", "--apply"]);
    assert_eq!(o.code, 0, "{}", o.all());
    assert_eq!(p.mode("script.sh"), 0o755);
    assert_eq!(p.read("script.sh"), "echo one\n");
}

#[test]
fn a_file_renamed_by_the_agent_is_renamed_back_by_undo() {
    let p = Proj::new("rename-undo");
    p.write("old-name.txt", "important\n");
    p.write("other.txt", "other\n");
    p.run(&["init"]);
    p.agent("mv old-name.txt new-name.txt");
    let o = p.run(&["undo", "2", "--apply"]);
    assert_eq!(o.code, 0, "{}", o.all());
    assert!(!p.exists("new-name.txt"));
    assert_eq!(p.read("old-name.txt"), "important\n");
    assert_eq!(p.read("other.txt"), "other\n");
}

#[test]
fn a_directory_deleted_by_the_agent_comes_back_with_its_contents_and_modes() {
    let p = Proj::new("dir-deleted");
    p.write("keep.txt", "k\n");
    p.write("tree/a.txt", "a\n");
    p.write("tree/sub/b.txt", "b\n");
    p.write("tree/sub/deeper/c.sh", "#!/bin/sh\n");
    p.chmod("tree/sub/deeper/c.sh", 0o755);
    fs::create_dir_all(p.path("tree/empty")).unwrap();
    p.chmod("tree/sub", 0o750);
    p.run(&["init"]);
    p.agent("rm -rf tree");
    assert!(!p.exists("tree"));
    let o = p.run(&["undo", "2", "--apply"]);
    assert_eq!(o.code, 0, "{}", o.all());
    assert_eq!(p.read("tree/a.txt"), "a\n");
    assert_eq!(p.read("tree/sub/b.txt"), "b\n");
    assert_eq!(p.read("tree/sub/deeper/c.sh"), "#!/bin/sh\n");
    assert_eq!(p.mode("tree/sub/deeper/c.sh"), 0o755);
    assert!(
        fs::metadata(p.path("tree/empty")).unwrap().is_dir(),
        "empty dirs are recorded"
    );
    assert_eq!(p.mode("tree/sub"), 0o750);
    assert_eq!(p.read("keep.txt"), "k\n");
    assert_eq!(p.run(&["verify"]).code, 0);
}

#[test]
fn a_directory_created_by_the_agent_is_removed_by_undo() {
    let p = Proj::inited("dir-created");
    p.agent("mkdir -p gen/a/b; echo 1 > gen/a/b/f.txt; echo 2 > gen/g.txt");
    let o = p.run(&["undo", "2", "--apply"]);
    assert_eq!(o.code, 0, "{}", o.all());
    assert!(!p.exists("gen"));
}

#[test]
fn undo_keeps_a_directory_that_gained_files_after_the_agent_created_it() {
    let p = Proj::inited("dir-hand-file");
    p.agent("mkdir gen; echo 1 > gen/f.txt");
    p.write("gen/mine.txt", "added by a human afterwards\n");
    let (code, j) = p.json_code(&["undo", "2", "--apply"]);
    // Removing `gen` would destroy the human's file: the plan must refuse or skip it.
    assert!(
        code == 3 || p.exists("gen/mine.txt"),
        "the human's file was destroyed: exit {code}: {j:?}"
    );
    assert_eq!(p.read("gen/mine.txt"), "added by a human afterwards\n");
}

#[test]
fn a_file_replaced_by_a_directory_is_undone() {
    let p = Proj::new("file-to-dir");
    p.write("thing", "was a file\n");
    p.run(&["init"]);
    p.agent("rm thing; mkdir thing; echo inner > thing/inner.txt");
    let o = p.run(&["undo", "2", "--apply"]);
    assert_eq!(o.code, 0, "{}", o.all());
    assert!(
        fs::symlink_metadata(p.path("thing"))
            .unwrap()
            .file_type()
            .is_file()
    );
    assert_eq!(p.read("thing"), "was a file\n");
}

// ------------------------------------------------------------------ secrets

#[test]
fn a_rewritten_env_file_is_not_restorable_and_is_left_alone() {
    let p = Proj::new("secret-env");
    let old = secret_value("old");
    let new = secret_value("new");
    p.write(".env", &format!("{}={}\n", "TOKEN", old));
    p.write("app.txt", "v1\n");
    p.run(&["init"]);
    let o = p.run_env(
        &[
            "--json",
            "run",
            "--",
            "sh",
            "-c",
            "printf 'TOKEN=%s\\n' \"$NEWVAL\" > .env; echo v2 > app.txt",
        ],
        &[("NEWVAL", &new)],
    );
    assert_eq!(o.code, 0, "{}", o.all());
    let env_after = p.read(".env");

    let dry = p.run(&["undo", "2"]);
    assert_eq!(dry.code, 0, "{}", dry.all());
    assert!(dry.stdout.contains("not restorable"), "{}", dry.stdout);
    assert!(
        dry.stdout
            .contains("summary: 1 ready, 0 conflicts, 0 already done, 1 not restorable"),
        "{}",
        dry.stdout
    );
    assert!(!dry.all().contains(&old) && !dry.all().contains(&new));

    let j = p.json(&["undo", "2", "--apply"]);
    let env_item = j
        .p("items")
        .arr()
        .iter()
        .find(|i| i.p("path").str() == ".env")
        .unwrap();
    assert_eq!(env_item.p("status").str(), "not-restorable");
    assert_eq!(env_item.p("outcome").str(), "skipped");
    assert_eq!(j.p("counts.not_restorable").u64(), 1);
    assert_eq!(
        p.read(".env"),
        env_after,
        "the secret file must be left exactly as it is"
    );
    assert_eq!(p.read("app.txt"), "v1\n", "other files are still undone");
    assert_eq!(p.run(&["verify"]).code, 0);
}

#[test]
fn undoing_only_a_secret_change_does_nothing_and_succeeds() {
    let p = Proj::new("secret-only");
    p.write(".env", &format!("{}={}\n", "API_TOKEN", secret_value("a")));
    p.run(&["init"]);
    let b = secret_value("b");
    let o = p.run_env(
        &[
            "run",
            "--",
            "sh",
            "-c",
            "printf 'API_TOKEN=%s\\n' \"$NEWVAL\" > .env",
        ],
        &[("NEWVAL", &b)],
    );
    assert_eq!(o.code, 0, "{}", o.all());
    let before = p.count();
    let o = p.run(&["undo", "2", "--apply"]);
    assert_eq!(o.code, 0, "{}", o.all());
    assert!(o.stdout.contains("not restorable"), "{}", o.stdout);
    assert!(o.stdout.contains("nothing to do"), "{}", o.stdout);
    assert!(p.read(".env").contains(&b));
    assert_eq!(p.count(), before);
    assert_eq!(p.run(&["verify"]).code, 0);
}

#[test]
fn a_new_env_file_created_by_the_agent_is_not_deleted_by_undo() {
    let p = Proj::inited("secret-new-env");
    let v = secret_value("fresh");
    let o = p.run_env(
        &[
            "run",
            "--",
            "sh",
            "-c",
            "printf 'SECRET=%s\\n' \"$NEWVAL\" > .env.local",
        ],
        &[("NEWVAL", &v)],
    );
    assert_eq!(o.code, 0, "{}", o.all());
    let o = p.run(&["undo", "2", "--apply"]);
    assert_eq!(o.code, 0, "{}", o.all());
    assert!(
        p.exists(".env.local"),
        "undo must not delete a file it could never restore"
    );
}

#[test]
fn secret_contents_never_reach_the_store_or_any_output() {
    let p = Proj::new("secret-store");
    let old = secret_value("o");
    let new = secret_value("n");
    let token = github_token();
    let key = private_key_block();
    p.write(".env", &format!("{}={}\n", "TOKEN", old));
    p.write("plain.txt", "nothing secret here\n");
    p.run(&["init"]);
    let o = p.run_env(
        &[
            "--json", "run", "--", "sh", "-c",
            "printf 'TOKEN=%s\\n' \"$NEWVAL\" > .env; printf '%s\\n' \"$GHTOKEN\" > notes.txt; printf '%s' \"$PEM\" > deploy.txt; echo more > plain.txt",
        ],
        &[("NEWVAL", &new), ("GHTOKEN", &token), ("PEM", &key)],
    );
    assert_eq!(o.code, 0, "{}", o.all());
    let store = p.store();
    for secret in [&old, &new, &token, &pem_body_lines()[0]] {
        assert!(
            !any_file_contains(&store, secret.as_bytes()),
            "a secret was copied into the store"
        );
    }
    assert!(
        any_file_contains(&store, b"nothing secret here"),
        "ordinary files are stored"
    );
    let diff = p.run(&["diff", "2"]);
    assert_eq!(diff.code, 0, "{}", diff.all());
    assert!(!diff.stdout.contains(&new) && !diff.stdout.contains(&token));
    assert!(
        diff.stdout
            .contains("sensitive file: content is never stored or shown"),
        "{}",
        diff.stdout
    );
    let dj = p.json(&["diff", "2"]);
    let withheld = dj
        .p("changes")
        .arr()
        .iter()
        .filter(|c| c.try_p("withheld").is_some())
        .count();
    assert_eq!(withheld, 3, ".env, notes.txt, deploy.txt: {dj:?}");
    for c in dj.p("changes").arr() {
        if c.p("path").str() == "plain.txt" {
            assert!(c.p("text_diff").str().contains("+more"));
        } else {
            assert!(c.p("text_diff").is_null());
            assert!(c.p("after.sensitive").bool());
            assert!(
                c.try_p("after.sha256").is_none(),
                "sensitive entries never expose a hash"
            );
        }
    }
    // The journal's command line never contained the secrets (they came from the environment).
    let log = p.run(&["log"]);
    assert!(!log.stdout.contains(&new) && !log.stdout.contains(&token));
    assert_eq!(p.run(&["verify"]).code, 0);
    assert_eq!(p.run(&["gc", "--keep", "1", "--apply"]).code, 0);
    assert!(!any_file_contains(&store, new.as_bytes()));
}

#[test]
fn secrets_are_also_kept_out_of_checkpoints_made_by_hand() {
    let p = Proj::inited("secret-manual");
    let token = github_token();
    p.write("config.json", &format!("{{\"auth\": \"{token}\"}}\n"));
    let j = p.json(&["checkpoint"]);
    assert_eq!(j.p("checkpoint.changes.created").u64(), 1);
    assert!(!any_file_contains(&p.store(), token.as_bytes()));
    let d = p.json(&["diff", "2"]);
    assert!(d.p("changes.0.after.sensitive").bool());
}

// ------------------------------------------------------------ ignore rules

#[test]
fn default_ignores_are_not_recorded() {
    let p = Proj::inited("ignore-default");
    fs::create_dir_all(p.path(".git")).unwrap();
    p.agent(
        "mkdir -p node_modules/pkg target/debug dist .git/objects; \
         echo x > node_modules/pkg/index.js; echo x > target/debug/app; echo x > dist/out.js; \
         echo x > .git/objects/o; echo x > .DS_Store; echo real > real.txt",
    );
    let d = p.json(&["diff", "2"]);
    let paths: Vec<&str> = d
        .p("changes")
        .arr()
        .iter()
        .map(|c| c.p("path").str())
        .collect();
    assert_eq!(paths, vec!["real.txt"]);
    assert_eq!(p.json(&["status"]).p("pending.counts.total").u64(), 0);
    // Changes inside ignored directories are never seen, and so never undone.
    p.agent("echo changed > node_modules/pkg/index.js");
    assert_eq!(p.log().p("checkpoints.2.changes.total").u64(), 0);
    assert_eq!(p.run(&["undo", "2", "--apply"]).code, 0);
    assert!(p.exists("node_modules/pkg/index.js"));
    assert_eq!(p.read("node_modules/pkg/index.js"), "changed\n");
}

#[test]
fn agent_undoignore_adds_patterns() {
    let p = Proj::new("ignore-custom");
    p.write(".agent-undoignore", "*.log\nbuild/\n/scratch.txt\n");
    p.run(&["init"]);
    p.agent("mkdir build logs; echo x > build/o; echo x > debug.log; echo x > logs/app.log; echo x > scratch.txt; echo x > sub.txt; mkdir -p deep; echo x > deep/scratch.txt");
    let d = p.json(&["diff", "2"]);
    let mut paths: Vec<&str> = d
        .p("changes")
        .arr()
        .iter()
        .map(|c| c.p("path").str())
        .collect();
    paths.sort_unstable();
    assert_eq!(paths, vec!["deep", "deep/scratch.txt", "logs", "sub.txt"]);
}

#[test]
fn agent_undoignore_can_reinclude_a_default_ignored_directory() {
    let p = Proj::new("ignore-negate");
    p.write(".agent-undoignore", "!dist/\n");
    p.run(&["init"]);
    p.agent("mkdir dist; echo built > dist/out.js; mkdir node_modules; echo y > node_modules/m.js");
    let d = p.json(&["diff", "2"]);
    let paths: Vec<&str> = d
        .p("changes")
        .arr()
        .iter()
        .map(|c| c.p("path").str())
        .collect();
    assert!(paths.contains(&"dist/out.js"), "{paths:?}");
    assert!(
        !paths.iter().any(|p| p.starts_with("node_modules")),
        "{paths:?}"
    );
}

#[test]
fn editing_agent_undoignore_is_itself_a_recorded_change() {
    let p = Proj::inited("ignore-edit");
    p.agent("echo '*.tmp' > .agent-undoignore; echo x > a.tmp; echo y > a.txt");
    let d = p.json(&["diff", "2"]);
    let paths: Vec<&str> = d
        .p("changes")
        .arr()
        .iter()
        .map(|c| c.p("path").str())
        .collect();
    assert_eq!(paths, vec![".agent-undoignore", "a.txt"]);
}

// ------------------------------------------------------------ special files

#[test]
fn a_fifo_in_the_project_never_blocks_any_command() {
    if !have_command("mkfifo") {
        eprintln!("skipped: no mkfifo");
        return;
    }
    let p = Proj::new("fifo");
    p.write("a.txt", "x\n");
    let st = std::process::Command::new("mkfifo")
        .arg(p.path("pipe"))
        .status()
        .unwrap();
    assert!(st.success());
    let limit = Duration::from_secs(30);
    assert_eq!(p.run_limited(&["init"], limit).code, 0);
    p.write("a.txt", "y\n");
    let o = p.run_limited(&["checkpoint"], limit);
    assert_eq!(o.code, 0, "{}", o.all());
    assert!(o.stdout.contains("1 modified"), "{}", o.stdout);
    assert_eq!(p.run_limited(&["status"], limit).code, 0);
    assert_eq!(p.run_limited(&["verify"], limit).code, 0);
    let o = p.run_limited(&["run", "--", "sh", "-c", "echo z > a.txt"], limit);
    assert_eq!(o.code, 0, "{}", o.all());
    let o = p.run_limited(&["undo", "3", "--apply"], limit);
    assert_eq!(o.code, 0, "{}", o.all());
    assert_eq!(p.read("a.txt"), "y\n");
    assert!(
        fs::symlink_metadata(p.path("pipe"))
            .unwrap()
            .file_type()
            .is_fifo()
    );
}

#[test]
fn a_fifo_created_by_the_agent_is_recorded_as_special_and_never_touched() {
    if !have_command("mkfifo") {
        eprintln!("skipped: no mkfifo");
        return;
    }
    let p = Proj::inited("fifo-agent");
    let limit = Duration::from_secs(30);
    let o = p.run_limited(&["run", "--", "mkfifo", "pipe"], limit);
    assert_eq!(o.code, 0, "{}", o.all());
    let d = p.run_limited(&["diff", "2"], limit);
    assert!(d.stdout.contains("A  pipe"), "{}", d.stdout);
    assert!(d.stdout.contains("special"), "{}", d.stdout);
    let u = p.run_limited(&["undo", "2", "--apply"], limit);
    assert!(
        u.stdout.contains("a special file is in the way"),
        "{}",
        u.stdout
    );
    assert!(
        fs::symlink_metadata(p.path("pipe"))
            .unwrap()
            .file_type()
            .is_fifo(),
        "the fifo must be left alone"
    );
    assert_eq!(p.run_limited(&["verify"], limit).code, 0);
}

#[test]
fn an_unreadable_file_is_reported_but_does_not_break_recording() {
    if is_root() {
        eprintln!("skipped: permission checks are bypassed for root");
        return;
    }
    let p = Proj::new("unreadable");
    p.write("locked.txt", "secret-ish\n");
    p.chmod("locked.txt", 0o000);
    p.write("ok.txt", "fine\n");
    let init = p.run(&["init"]);
    assert_eq!(init.code, 0, "{}", init.all());
    p.agent("echo more > ok.txt");
    assert_eq!(p.run(&["verify"]).code, 0);
    let j = p.json(&["status"]);
    let warnings: Vec<&str> = j.p("pending.warnings").arr().iter().map(J::str).collect();
    assert!(
        warnings.iter().any(|w| w.contains("locked.txt")),
        "{warnings:?}"
    );
    p.chmod("locked.txt", 0o600);
}

// -------------------------------------------------------------- misc safety

#[test]
fn run_passes_stdin_through_to_the_command() {
    let p = Proj::inited("run-stdin");
    let mut child = p
        .command_in(
            &p.root,
            &["run", "--", "sh", "-c", "cat > from-stdin.txt"],
            &[],
        )
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    child
        .stdin
        .take()
        .unwrap()
        .write_all(b"piped input\n")
        .unwrap();
    let o = Out::from_output(child.wait_with_output().unwrap());
    assert_eq!(o.code, 0, "{}", o.all());
    assert_eq!(p.read("from-stdin.txt"), "piped input\n");
}

#[test]
fn run_arguments_are_passed_verbatim_without_a_shell() {
    let p = Proj::inited("run-argv");
    let o = p.run(&[
        "run",
        "--",
        "sh",
        "-c",
        "printf '%s|' \"$@\" > args.txt",
        "sh",
        "a b",
        "$HOME",
        "*",
        "",
    ]);
    assert_eq!(o.code, 0, "{}", o.all());
    assert_eq!(p.read("args.txt"), "a b|$HOME|*||");
    let j = p.log();
    assert_eq!(j.p("checkpoints.1.command.4").str(), "a b");
    assert_eq!(j.p("checkpoints.1.command.5").str(), "$HOME");
}

#[test]
fn many_files_round_trip_through_undo() {
    let p = Proj::inited("many-files");
    p.agent("mkdir -p m; i=0; while [ $i -lt 150 ]; do echo $i > m/f$i.txt; i=$((i+1)); done");
    let j = p.json(&["checkpoint"]);
    assert_eq!(j.p("checkpoint.changes.total").u64(), 0);
    assert_eq!(
        p.log().p("checkpoints.1.changes.created").u64(),
        151,
        "150 files and the directory"
    );
    let o = p.run(&["undo", "2", "--apply"]);
    assert_eq!(o.code, 0, "{}", o.all());
    assert!(!p.exists("m"));
    assert_eq!(p.run(&["undo", "5", "--apply"]).code, 0, "undo of the undo");
    assert_eq!(p.read("m/f149.txt"), "149\n");
    assert_eq!(p.run(&["verify"]).code, 0);
}

#[test]
fn the_store_files_stay_private_after_heavy_use() {
    let p = Proj::new("store-perms-after");
    p.write("a.txt", "a\n");
    p.run(&["init"]);
    p.agent("echo b > a.txt; echo c > c.txt");
    p.run(&["undo", "2", "--apply"]);
    p.run(&["gc", "--keep", "2", "--apply"]);
    let store = p.store();
    assert_eq!(mode_of(&store) & 0o077, 0);
    for f in files_below(&store) {
        assert_eq!(
            mode_of(&f) & 0o077,
            0,
            "{} is accessible to others",
            f.display()
        );
    }
    let o = p.run(&["doctor"]);
    assert_eq!(o.code, 0, "{}", o.all());
}

fn copy_tree(from: &std::path::Path, to: &std::path::Path) {
    fs::create_dir_all(to).unwrap();
    for e in fs::read_dir(from).unwrap().flatten() {
        let (src, dst) = (e.path(), to.join(e.file_name()));
        if e.file_type().unwrap().is_dir() {
            copy_tree(&src, &dst);
        } else {
            fs::copy(&src, &dst).unwrap();
        }
    }
}

#[test]
fn a_store_that_belongs_to_a_different_project_root_is_refused() {
    let p = Proj::inited("wrong-root");
    p.agent("echo x > x.txt");
    let q = Proj::inited("wrong-root-other");
    // Put p's store (which records p's root) where q's store lives.
    let qstore = q.store();
    fs::remove_dir_all(&qstore).unwrap();
    copy_tree(&p.store(), &qstore);
    let j = q.json_err(&["status"], 1, "unsafe_path");
    assert!(
        j.p("error.message")
            .str()
            .contains("different project root"),
        "{j:?}"
    );
    q.json_err(&["checkpoint"], 1, "unsafe_path");
    assert_eq!(q.run(&["run", "--", "true"]).code, 125);
}

#[test]
fn human_and_json_text_diffs_escape_content_exactly_once() {
    let p = Proj::inited("diff-escape-once");
    // One real backslash, one real ESC, one tab.
    p.agent("printf 'C:\\\\dir\\n\\033[1mbold\\n\\ttabbed\\n' > win.txt");
    assert_eq!(p.read("win.txt"), "C:\\dir\n\u{1b}[1mbold\n\ttabbed\n");
    let human = p.run(&["diff", "2"]);
    assert_eq!(human.code, 0, "{}", human.all());
    assert_clean_terminal_text(&human.stdout);
    // `display` escapes a backslash as two backslashes and ESC as `\x1b`, applied once.
    assert!(
        human.stdout.lines().any(|l| l == "+C:\\\\dir"),
        "{}",
        human.stdout
    );
    assert!(
        human.stdout.lines().any(|l| l == "+\\x1b[1mbold"),
        "{}",
        human.stdout
    );
    assert!(
        human.stdout.lines().any(|l| l == "+\ttabbed"),
        "tabs pass through: {}",
        human.stdout
    );
    // The JSON body is the same text, so tools and humans see the same escaping.
    let j = p.json(&["diff", "2"]);
    let body = j.p("changes.0.text_diff").str();
    for line in ["+C:\\\\dir", "+\\x1b[1mbold"] {
        assert!(
            body.lines().any(|l| l == line),
            "JSON lacks {line:?}: {body:?}"
        );
    }
}
