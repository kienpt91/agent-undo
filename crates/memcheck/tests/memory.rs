//! Bounded-memory proof for the real filesystem adapters.
//!
//! The project holds 3000 small files and three 12 MiB files (36 MiB of file
//! data). Snapshots, `verify` and `undo` must stream that data: the extra heap
//! they allocate at any moment stays far below the size of the data, and nothing
//! is retained between operations.
//!
//! The library crates of this repository forbid `unsafe`; this integration-test
//! crate is the one place that needs it, because a counting `#[global_allocator]`
//! requires `unsafe impl GlobalAlloc`. The crate is test-only and never linked
//! into the released binary.
//!
//! There is deliberately ONE `#[test]` in this file: the allocator counters are
//! process-global, so a second test running in parallel would add noise.
#![allow(unsafe_code)]

use agent_undo_app::usecases::checkpoint::manual_checkpoint;
use agent_undo_app::usecases::init::record_baseline;
use agent_undo_app::usecases::reversal::{apply_undo, plan_undo};
use agent_undo_app::usecases::verify::verify;
use agent_undo_domain::journal::Selector;
use agent_undo_infra::layout::{DEFAULT_MAX_FILE_SIZE, StoreDir};
use agent_undo_infra::project::Project;
use agent_undo_infra::support::NullSink;
use std::alloc::{GlobalAlloc, Layout, System};
use std::fs::{self, File};
use std::io::{Seek, SeekFrom, Write};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicUsize, Ordering::Relaxed};

// ---------------------------------------------------------------- allocator

static LIVE: AtomicUsize = AtomicUsize::new(0);
static PEAK: AtomicUsize = AtomicUsize::new(0);

struct Counting;

fn grew(by: usize) {
    let now = LIVE.fetch_add(by, Relaxed) + by;
    PEAK.fetch_max(now, Relaxed);
}

// SAFETY: every method delegates to `System` with the arguments it was given
// and only adds bookkeeping on atomics; layout contracts are passed through.
unsafe impl GlobalAlloc for Counting {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        // SAFETY: forwarded unchanged to the system allocator.
        let p = unsafe { System.alloc(layout) };
        if !p.is_null() {
            grew(layout.size());
        }
        p
    }

    unsafe fn alloc_zeroed(&self, layout: Layout) -> *mut u8 {
        // SAFETY: forwarded unchanged to the system allocator.
        let p = unsafe { System.alloc_zeroed(layout) };
        if !p.is_null() {
            grew(layout.size());
        }
        p
    }

    unsafe fn dealloc(&self, ptr: *mut u8, layout: Layout) {
        // SAFETY: `ptr`/`layout` come from a previous allocation by this allocator.
        unsafe { System.dealloc(ptr, layout) };
        LIVE.fetch_sub(layout.size(), Relaxed);
    }

    unsafe fn realloc(&self, ptr: *mut u8, layout: Layout, new_size: usize) -> *mut u8 {
        // SAFETY: `ptr`/`layout` come from a previous allocation by this allocator.
        let p = unsafe { System.realloc(ptr, layout, new_size) };
        if !p.is_null() {
            if new_size >= layout.size() {
                grew(new_size - layout.size());
            } else {
                LIVE.fetch_sub(layout.size() - new_size, Relaxed);
            }
        }
        p
    }
}

#[global_allocator]
static ALLOC: Counting = Counting;

fn live() -> usize {
    LIVE.load(Relaxed)
}

/// Runs `f`; returns its result and the high-water mark of live bytes above the
/// live bytes at entry (measured while the result is still alive).
fn measure<T>(f: impl FnOnce() -> T) -> (T, usize) {
    let before = live();
    PEAK.store(before, Relaxed);
    let out = f();
    let peak = PEAK.load(Relaxed);
    (out, peak.saturating_sub(before))
}

// ------------------------------------------------------------------ fixture

const SMALL_DIRS: usize = 30;
const SMALL_PER_DIR: usize = 100; // 3000 small files
const BIG_FILES: usize = 3;
const BIG_SIZE: u64 = 12 * 1024 * 1024;
const ITERATIONS: usize = 5;
const PEAK_LIMIT: usize = 8 * 1024 * 1024;
const GROWTH_LIMIT: usize = 256 * 1024;

struct TempBase(PathBuf);

impl Drop for TempBase {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

fn small_path(root: &Path, d: usize, f: usize) -> PathBuf {
    root.join(format!("dir{d:02}"))
        .join(format!("file{f:03}.txt"))
}

fn big_path(root: &Path, n: usize) -> PathBuf {
    root.join("big").join(format!("blob{n}.bin"))
}

fn write_big(path: &Path, tag: &str) {
    let mut f = File::create(path).unwrap();
    f.set_len(BIG_SIZE).unwrap(); // sparse: zero-filled
    f.seek(SeekFrom::Start(0)).unwrap();
    f.write_all(tag.as_bytes()).unwrap();
    f.sync_all().unwrap();
}

fn build_project(root: &Path) {
    for d in 0..SMALL_DIRS {
        fs::create_dir_all(root.join(format!("dir{d:02}"))).unwrap();
        for f in 0..SMALL_PER_DIR {
            let text = format!(
                "small file {d}/{f}: {}\n",
                "payload text ".repeat(4 + (d + f) % 7)
            );
            fs::write(small_path(root, d, f), text).unwrap();
        }
    }
    fs::create_dir_all(root.join("big")).unwrap();
    for n in 0..BIG_FILES {
        write_big(&big_path(root, n), &format!("big file {n} generation 0"));
    }
}

/// The agent's work in iteration `it`: edit a few small files, change one large
/// file in place, add a new file.
fn agent_edits(root: &Path, it: usize) {
    for k in 0..5 {
        let (d, f) = ((it * 5 + k) % SMALL_DIRS, (it * 7 + k * 13) % SMALL_PER_DIR);
        let text = format!(
            "edited in iteration {it}: {}\n",
            "changed ".repeat(10 + it + k)
        );
        fs::write(small_path(root, d, f), text).unwrap();
    }
    let mut big = fs::OpenOptions::new()
        .write(true)
        .open(big_path(root, it % BIG_FILES))
        .unwrap();
    big.write_all(format!("big file edited in iteration {it}").as_bytes())
        .unwrap();
    big.sync_all().unwrap();
    fs::create_dir_all(root.join("new")).unwrap();
    fs::write(
        root.join("new").join(format!("it{it}.txt")),
        format!("new in {it}\n"),
    )
    .unwrap();
}

fn check_peak(what: &str, extra: usize) {
    assert!(
        extra < PEAK_LIMIT,
        "{what}: peak extra allocation {extra} bytes >= {PEAK_LIMIT} (36 MiB of file data must be streamed)"
    );
}

fn check_flat(what: &str, live_after: &[usize]) {
    let first = live_after.first().copied().unwrap();
    for (i, &l) in live_after.iter().enumerate().skip(1) {
        assert!(
            l <= first + GROWTH_LIMIT,
            "{what}: live bytes after iteration {i} = {l}, iteration 0 = {first} (grew by more than {GROWTH_LIMIT}): {live_after:?}"
        );
    }
}

#[test]
fn snapshot_verify_and_undo_use_bounded_memory() {
    // The counters work: a 2 MiB buffer is seen as roughly 2 MiB of extra peak.
    let (buf, seen) = measure(|| vec![1u8; 2 * 1024 * 1024]);
    assert!(
        seen >= 2 * 1024 * 1024,
        "allocator counted only {seen} bytes"
    );
    drop(buf);
    let base = std::env::temp_dir().join(format!("au-memcheck-{}", std::process::id()));
    let _ = fs::remove_dir_all(&base);
    fs::create_dir_all(base.join("proj")).unwrap();
    let base = fs::canonicalize(&base).unwrap();
    let _cleanup = TempBase(base.clone());
    let root = base.join("proj");
    build_project(&root);

    let store = StoreDir::create(
        &base.join("state").join("store"),
        &root,
        false,
        DEFAULT_MAX_FILE_SIZE,
    )
    .unwrap();
    let project = Project::new(store, Box::new(NullSink));
    let ports = project.ports();

    let (baseline, baseline_peak) = measure(|| record_baseline(&ports).unwrap());
    assert_eq!(
        baseline.stats.entries as usize,
        SMALL_DIRS * (1 + SMALL_PER_DIR) + 1 + BIG_FILES
    );
    drop(baseline);
    check_peak("baseline", baseline_peak);

    let mut ck_peaks = Vec::with_capacity(ITERATIONS);
    let mut verify_peaks = Vec::with_capacity(ITERATIONS);
    let mut undo_peaks = Vec::with_capacity(ITERATIONS);
    let mut ck_live = Vec::with_capacity(ITERATIONS);
    let mut verify_live = Vec::with_capacity(ITERATIONS);
    let mut undo_live = Vec::with_capacity(ITERATIONS);

    for it in 0..ITERATIONS {
        agent_edits(&root, it);

        let (rec, peak) = measure(|| manual_checkpoint(&ports, None, false).unwrap());
        assert!(
            rec.record.counts.total() >= 7,
            "edits were recorded: {:?}",
            rec.record.counts
        );
        drop(rec);
        ck_peaks.push(peak);
        ck_live.push(live());

        let (report, peak) = measure(|| verify(&ports).unwrap());
        assert!(report.ok(), "verify problems: {:?}", report.problems);
        assert!(report.blobs_checked > 3000);
        drop(report);
        verify_peaks.push(peak);
        verify_live.push(live());

        let (applied, peak) = measure(|| {
            let plan = plan_undo(&ports, &Selector::Last).unwrap();
            assert!(plan.has_work() && !plan.has_conflicts());
            drop(plan);
            let report = apply_undo(&ports, &Selector::Last, false).unwrap();
            assert!(
                report.error.is_none() && report.refused.is_none(),
                "{:?}",
                report.error
            );
            report.applied()
        });
        assert!(applied >= 7, "undo reverted the edits ({applied} applied)");
        undo_peaks.push(peak);
        undo_live.push(live());
    }

    for (what, peaks) in [
        ("checkpoint", &ck_peaks),
        ("verify", &verify_peaks),
        ("plan_undo+apply_undo", &undo_peaks),
    ] {
        for (i, &p) in peaks.iter().enumerate() {
            check_peak(&format!("{what} (iteration {i})"), p);
        }
    }
    check_flat("checkpoint", &ck_live);
    check_flat("verify", &verify_live);
    check_flat("plan_undo+apply_undo", &undo_live);
}
