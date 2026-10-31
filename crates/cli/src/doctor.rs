//! `doctor`: environment and store health checks.

use crate::json::Json;
use crate::render::envelope;
use agent_undo_app::error::Error;
use agent_undo_app::ports::{JournalRepository, Locker};
use agent_undo_domain::esc::display;
use agent_undo_domain::hash::{sha256, to_hex};
use agent_undo_domain::units::human_size;
use agent_undo_infra::fs_journal::FsJournal;
use agent_undo_infra::fsutil::display_path;
use agent_undo_infra::layout::{IN_PROJECT_DIR, StoreDir, state_base};
use agent_undo_infra::lock::FsLocker;
use std::fs;
use std::os::unix::fs::{MetadataExt, PermissionsExt};
use std::path::Path;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Status {
    Ok,
    Warn,
    Fail,
}

impl Status {
    pub fn as_str(self) -> &'static str {
        match self {
            Status::Ok => "ok",
            Status::Warn => "warn",
            Status::Fail => "fail",
        }
    }
}

#[derive(Debug, Clone)]
pub struct Check {
    pub name: &'static str,
    pub status: Status,
    pub detail: String,
}

fn check(name: &'static str, status: Status, detail: impl Into<String>) -> Check {
    Check {
        name,
        status,
        detail: detail.into(),
    }
}

fn mode_of(p: &Path) -> Option<u32> {
    fs::symlink_metadata(p)
        .ok()
        .map(|m| m.permissions().mode() & 0o777)
}

fn permission_check(store: &StoreDir) -> Check {
    let mut bad: Vec<String> = Vec::new();
    for (p, want) in [
        (store.dir.clone(), 0o700),
        (store.blobs_dir(), 0o700),
        (store.checkpoints_dir(), 0o700),
        (store.tmp_dir(), 0o700),
        (store.dir.join("meta"), 0o600),
        (store.dir.join("key"), 0o600),
        (store.log_path(), 0o600),
    ] {
        match mode_of(&p) {
            Some(m) if m & !want == 0 => {}
            Some(m) => bad.push(format!(
                "{} is {m:04o} (want {want:04o} or stricter)",
                display_path(&p)
            )),
            None => bad.push(format!("{} is missing", display_path(&p))),
        }
    }
    if bad.is_empty() {
        check(
            "store permissions",
            Status::Ok,
            "directories 0700, files 0600",
        )
    } else {
        check("store permissions", Status::Fail, bad.join("; "))
    }
}

fn git_exclude_has_store(root: &Path) -> Option<bool> {
    let exclude = root.join(".git").join("info").join("exclude");
    if !root.join(".git").is_dir() {
        return None;
    }
    let text = fs::read_to_string(exclude).unwrap_or_default();
    Some(text.lines().any(|l| {
        matches!(
            l.trim(),
            ".agent-undo" | "/.agent-undo" | ".agent-undo/" | "/.agent-undo/"
        )
    }))
}

/// Runs all checks. `store` is `None` when the project is not initialized.
pub fn run_checks(root: &Path, store: Option<&StoreDir>) -> Vec<Check> {
    let mut out = Vec::new();
    // Hash self-test.
    let abc = to_hex(&sha256(b"abc"));
    if abc == "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad" {
        out.push(check(
            "sha-256 self-test",
            Status::Ok,
            "known-answer test passed",
        ));
    } else {
        out.push(check(
            "sha-256 self-test",
            Status::Fail,
            "known-answer test failed",
        ));
    }
    // Environment.
    let euid_root = fs::metadata("/proc/self")
        .map(|m| m.uid() == 0)
        .unwrap_or(false);
    if euid_root {
        out.push(check(
            "user",
            Status::Warn,
            "running as root; undo will restore files as root",
        ));
    } else {
        out.push(check("user", Status::Ok, "not running as root"));
    }
    match state_base() {
        Ok(b) => out.push(check("state directory", Status::Ok, display_path(&b))),
        Err(e) => out.push(check("state directory", Status::Warn, e.to_string())),
    }
    // Project root sanity.
    let home = std::env::var_os("HOME").and_then(|h| fs::canonicalize(h).ok());
    if root == Path::new("/") || home.as_deref() == Some(root) {
        out.push(check(
            "project root",
            Status::Warn,
            "the project root is / or your home directory; every snapshot would walk it",
        ));
    } else {
        out.push(check("project root", Status::Ok, display_path(root)));
    }
    if root.join(".git").exists() {
        out.push(check(
            "git metadata",
            Status::Ok,
            ".git is ignored by snapshots; git operations are not recorded or undone",
        ));
    }
    match root.join(".agent-undoignore").exists() {
        true => match agent_undo_infra::layout::read_file_capped(
            &root.join(".agent-undoignore"),
            1024 * 1024,
        )
        .map_err(|e| e.to_string())
        .and_then(|t| {
            agent_undo_domain::ignore::IgnoreSet::with_user_patterns(&t.unwrap_or_default())
        }) {
            Ok(set) => out.push(check(
                ".agent-undoignore",
                Status::Ok,
                format!("{} patterns active (including defaults)", set.len()),
            )),
            Err(e) => out.push(check(".agent-undoignore", Status::Fail, e)),
        },
        false => out.push(check(
            ".agent-undoignore",
            Status::Ok,
            "not present (defaults only)",
        )),
    }
    let Some(store) = store else {
        out.push(check(
            "store",
            Status::Warn,
            "not initialized; run `agent-undo init`",
        ));
        return out;
    };
    out.push(check(
        "store",
        Status::Ok,
        format!(
            "{} ({}; size cap {})",
            display_path(&store.dir),
            if store.meta.in_project {
                "inside the project"
            } else {
                "outside the project"
            },
            human_size(store.meta.max_file_size)
        ),
    ));
    out.push(permission_check(store));
    if store.meta.in_project {
        match git_exclude_has_store(root) {
            Some(true) => out.push(check("git exclude", Status::Ok, format!("{IN_PROJECT_DIR} is listed in .git/info/exclude"))),
            Some(false) => out.push(check("git exclude", Status::Warn, format!("{IN_PROJECT_DIR} is not in .git/info/exclude; it could be committed by accident"))),
            None => out.push(check("git exclude", Status::Warn, "no .git directory; make sure the store is never committed")),
        }
    } else if store.dir.starts_with(root) {
        out.push(check(
            "store location",
            Status::Warn,
            "the external store lies inside the project",
        ));
    }
    // Lock availability.
    let locker = FsLocker::new(store.lock_path());
    match locker.exclusive() {
        Ok(_) => out.push(check("lock", Status::Ok, "free")),
        Err(Error::Locked(_)) => out.push(check(
            "lock",
            Status::Warn,
            "held by another operation right now",
        )),
        Err(e) => out.push(check("lock", Status::Fail, e.to_string())),
    }
    // Journal.
    match FsJournal::new(store.log_path(), store.pruned_path()).load() {
        Ok(j) => out.push(check(
            "journal",
            Status::Ok,
            format!("{} checkpoints, hash chain intact", j.records().len()),
        )),
        Err(e) => out.push(check(
            "journal",
            Status::Fail,
            display(e.to_string().as_bytes()),
        )),
    }
    // Timestamp precision.
    let probe = store
        .tmp_dir()
        .join(format!("doctor-{}", std::process::id()));
    let precise = fs::write(&probe, b"x").is_ok() && {
        let t = std::time::UNIX_EPOCH + std::time::Duration::new(1_700_000_000, 123_456_789);
        let ok = fs::File::options()
            .write(true)
            .open(&probe)
            .and_then(|f| f.set_modified(t))
            .is_ok()
            && fs::metadata(&probe)
                .map(|m| m.mtime_nsec() == 123_456_789)
                .unwrap_or(false);
        let _ = fs::remove_file(&probe);
        ok
    };
    if precise {
        out.push(check(
            "timestamps",
            Status::Ok,
            "nanosecond mtime supported",
        ));
    } else {
        out.push(check("timestamps", Status::Warn, "filesystem timestamps are coarse; the stat cache margin protects correctness, but scans re-hash more"));
    }
    // Stale temp files.
    let stale = fs::read_dir(store.tmp_dir())
        .map(|rd| rd.count())
        .unwrap_or(0);
    if stale > 0 {
        out.push(check("temp files", Status::Warn, format!("{stale} leftover files in tmp/ (from an interrupted run; `gc --apply` removes them)")));
    } else {
        out.push(check("temp files", Status::Ok, "none"));
    }
    out
}

pub fn doctor_text(checks: &[Check]) -> String {
    let mut out = String::new();
    for c in checks {
        let tag = match c.status {
            Status::Ok => " ok ",
            Status::Warn => "warn",
            Status::Fail => "FAIL",
        };
        out.push_str(&format!(
            "[{tag}] {}: {}\n",
            c.name,
            display(c.detail.as_bytes())
        ));
    }
    let fails = checks.iter().filter(|c| c.status == Status::Fail).count();
    let warns = checks.iter().filter(|c| c.status == Status::Warn).count();
    out.push_str(&format!("doctor: {fails} failed, {warns} warnings\n"));
    out
}

pub fn doctor_json(checks: &[Check]) -> Json {
    let items: Vec<Json> = checks
        .iter()
        .map(|c| {
            Json::obj()
                .with("name", c.name)
                .with("status", c.status.as_str())
                .with("detail", display(c.detail.as_bytes()))
        })
        .collect();
    envelope("doctor")
        .with("healthy", checks.iter().all(|c| c.status != Status::Fail))
        .with("checks", Json::Arr(items))
}

#[cfg(test)]
mod tests;
