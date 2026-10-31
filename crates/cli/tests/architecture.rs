//! Architecture tests: the dependency rule domain <- app <- infra <- cli is
//! enforced by the compiler through crate dependencies; these tests additionally
//! check the manifests and scan the source for IO in the pure layers.

use std::fs;
use std::path::{Path, PathBuf};

fn crates_dir() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .expect("crates dir")
        .to_path_buf()
}

fn dependencies(manifest: &Path) -> Vec<String> {
    let text = fs::read_to_string(manifest).expect("read Cargo.toml");
    let mut in_deps = false;
    let mut deps = Vec::new();
    for line in text.lines() {
        let t = line.trim();
        if t.starts_with('[') {
            in_deps = t == "[dependencies]";
            continue;
        }
        if in_deps && !t.is_empty() && !t.starts_with('#') {
            if let Some((name, _)) = t.split_once('=') {
                deps.push(name.trim().to_string());
            }
        }
    }
    deps.sort();
    deps
}

fn rust_sources(dir: &Path, out: &mut Vec<PathBuf>) {
    for entry in fs::read_dir(dir).expect("read_dir") {
        let p = entry.expect("entry").path();
        let name = p.file_name().and_then(|n| n.to_str()).unwrap_or("");
        if p.is_dir() {
            rust_sources(&p, out);
        } else if name.ends_with(".rs") && name != "tests.rs" {
            out.push(p);
        }
    }
}

fn production_source(crate_name: &str) -> Vec<(PathBuf, String)> {
    let mut files = Vec::new();
    rust_sources(&crates_dir().join(crate_name).join("src"), &mut files);
    files.sort();
    files
        .into_iter()
        .map(|f| {
            let text = fs::read_to_string(&f).expect("read source");
            (f, text)
        })
        .collect()
}

#[test]
fn domain_has_no_dependencies_at_all() {
    assert_eq!(
        dependencies(&crates_dir().join("domain/Cargo.toml")),
        Vec::<String>::new()
    );
}

#[test]
fn app_depends_only_on_domain() {
    assert_eq!(
        dependencies(&crates_dir().join("app/Cargo.toml")),
        vec!["agent-undo-domain"]
    );
}

#[test]
fn infra_depends_only_inward() {
    assert_eq!(
        dependencies(&crates_dir().join("infra/Cargo.toml")),
        vec!["agent-undo-app", "agent-undo-domain"]
    );
}

#[test]
fn no_third_party_crates_anywhere() {
    for c in ["domain", "app", "infra", "cli"] {
        for d in dependencies(&crates_dir().join(c).join("Cargo.toml")) {
            assert!(d.starts_with("agent-undo-"), "{c} depends on {d}");
        }
    }
}

const PURE_FORBIDDEN: &[&str] = &[
    "std::fs",
    "std::net",
    "std::process",
    "std::env",
    "std::thread",
    "std::os",
    "SystemTime",
    "Instant",
    "/dev/urandom",
    "unsafe ",
];

fn offenders(layer: &str) -> Vec<String> {
    let mut found = Vec::new();
    for (file, text) in production_source(layer) {
        for (n, line) in text.lines().enumerate() {
            let code = line.split("//").next().unwrap_or("");
            for pat in PURE_FORBIDDEN {
                if code.contains(pat) {
                    found.push(format!("{}:{}: {pat}", file.display(), n + 1));
                }
            }
            // std::io is allowed in the application layer only as a type used to
            // wrap adapter errors, never for operations.
            if code.contains("std::io") && layer == "domain" {
                found.push(format!("{}:{}: std::io in the domain", file.display(), n + 1));
            }
            if code.contains("std::io::") && layer == "app" {
                let ok = ["std::io::Error", "std::io::Result", "std::io::ErrorKind"]
                    .iter()
                    .any(|a| code.contains(a));
                if !ok {
                    found.push(format!(
                        "{}:{}: std::io operation in the application layer",
                        file.display(),
                        n + 1
                    ));
                }
            }
        }
    }
    found
}

#[test]
fn domain_source_performs_no_io_clock_randomness_or_process_access() {
    let bad = offenders("domain");
    assert!(bad.is_empty(), "{bad:#?}");
}

#[test]
fn application_source_performs_no_io_clock_or_process_access() {
    let bad = offenders("app");
    assert!(bad.is_empty(), "{bad:#?}");
}

#[test]
fn inner_layers_never_name_outer_crates() {
    for (layer, outer) in [
        (
            "domain",
            &["agent_undo_app", "agent_undo_infra", "agent_undo_cli"][..],
        ),
        ("app", &["agent_undo_infra", "agent_undo_cli"][..]),
        ("infra", &["agent_undo_cli"][..]),
    ] {
        for (file, text) in production_source(layer) {
            for o in outer {
                assert!(!text.contains(o), "{} references {o}", file.display());
            }
        }
    }
}

#[test]
fn every_crate_forbids_unsafe_code() {
    for c in ["domain", "app", "infra", "cli"] {
        let lib = crates_dir().join(c).join("src/lib.rs");
        let text = fs::read_to_string(&lib).expect("lib.rs");
        assert!(text.contains("#![forbid(unsafe_code)]"), "{c}");
    }
    let main = fs::read_to_string(crates_dir().join("cli/src/main.rs")).expect("main.rs");
    assert!(main.contains("#![forbid(unsafe_code)]"));
}

#[test]
fn every_layer_denies_panicking_shortcuts_outside_tests() {
    for c in ["domain", "app", "infra", "cli"] {
        let text = fs::read_to_string(crates_dir().join(c).join("src/lib.rs")).expect("lib.rs");
        for lint in [
            "clippy::unwrap_used",
            "clippy::expect_used",
            "clippy::indexing_slicing",
        ] {
            assert!(text.contains(lint), "{c} lib.rs must deny {lint}");
        }
    }
}

#[test]
fn no_crate_has_a_build_script() {
    for c in ["domain", "app", "infra", "cli"] {
        assert!(
            !crates_dir().join(c).join("build.rs").exists(),
            "{c} has a build script"
        );
    }
}
