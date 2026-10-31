//! Shared helpers for the end-to-end tests: a temp project with an isolated
//! state directory and HOME, a runner for the real binary, and a tiny JSON reader.
#![allow(dead_code)]

use std::fs;
use std::io::Read;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, Instant};

pub const BIN: &str = env!("CARGO_BIN_EXE_agent-undo");

static COUNTER: AtomicU64 = AtomicU64::new(0);

// ------------------------------------------------------------------ JSON

/// A parsed JSON value. Numbers keep their source text.
#[derive(Debug, Clone, PartialEq)]
pub enum J {
    Null,
    Bool(bool),
    Num(String),
    Str(String),
    Arr(Vec<J>),
    Obj(Vec<(String, J)>),
}

impl J {
    /// Looks up a dotted path (`"checkpoint.changes.created"`, `"items.0.path"`).
    /// Panics with a helpful message if a step is missing.
    pub fn p(&self, path: &str) -> &J {
        self.try_p(path)
            .unwrap_or_else(|| panic!("no `{path}` in {self:?}"))
    }

    pub fn try_p(&self, path: &str) -> Option<&J> {
        let mut cur = self;
        for step in path.split('.') {
            cur = match cur {
                J::Obj(fields) => fields.iter().find(|(k, _)| k == step).map(|(_, v)| v)?,
                J::Arr(items) => items.get(step.parse::<usize>().ok()?)?,
                _ => return None,
            };
        }
        Some(cur)
    }

    pub fn str(&self) -> &str {
        match self {
            J::Str(s) => s,
            other => panic!("not a string: {other:?}"),
        }
    }

    pub fn u64(&self) -> u64 {
        match self {
            J::Num(n) => n.parse().unwrap_or_else(|_| panic!("not a u64: {n}")),
            other => panic!("not a number: {other:?}"),
        }
    }

    pub fn bool(&self) -> bool {
        match self {
            J::Bool(b) => *b,
            other => panic!("not a bool: {other:?}"),
        }
    }

    pub fn arr(&self) -> &[J] {
        match self {
            J::Arr(a) => a,
            other => panic!("not an array: {other:?}"),
        }
    }

    pub fn is_null(&self) -> bool {
        matches!(self, J::Null)
    }

    pub fn keys(&self) -> Vec<&str> {
        match self {
            J::Obj(f) => f.iter().map(|(k, _)| k.as_str()).collect(),
            other => panic!("not an object: {other:?}"),
        }
    }
}

struct Reader<'a> {
    b: &'a [u8],
    i: usize,
}

impl Reader<'_> {
    fn ws(&mut self) {
        while matches!(self.b.get(self.i), Some(b' ' | b'\t' | b'\n' | b'\r')) {
            self.i += 1;
        }
    }

    fn eat(&mut self, c: u8) -> Result<(), String> {
        if self.b.get(self.i) == Some(&c) {
            self.i += 1;
            Ok(())
        } else {
            Err(format!("expected `{}` at byte {}", c as char, self.i))
        }
    }

    fn lit(&mut self, word: &str, v: J) -> Result<J, String> {
        if self.b.get(self.i..self.i + word.len()) == Some(word.as_bytes()) {
            self.i += word.len();
            Ok(v)
        } else {
            Err(format!("bad literal at byte {}", self.i))
        }
    }

    fn value(&mut self) -> Result<J, String> {
        self.ws();
        match self.b.get(self.i) {
            None => Err("unexpected end of input".into()),
            Some(b'{') => {
                self.i += 1;
                let mut fields = Vec::new();
                self.ws();
                if self.b.get(self.i) == Some(&b'}') {
                    self.i += 1;
                    return Ok(J::Obj(fields));
                }
                loop {
                    self.ws();
                    let k = self.string()?;
                    self.ws();
                    self.eat(b':')?;
                    let v = self.value()?;
                    fields.push((k, v));
                    self.ws();
                    match self.b.get(self.i) {
                        Some(b',') => self.i += 1,
                        Some(b'}') => {
                            self.i += 1;
                            return Ok(J::Obj(fields));
                        }
                        _ => return Err(format!("expected `,` or `}}` at byte {}", self.i)),
                    }
                }
            }
            Some(b'[') => {
                self.i += 1;
                let mut items = Vec::new();
                self.ws();
                if self.b.get(self.i) == Some(&b']') {
                    self.i += 1;
                    return Ok(J::Arr(items));
                }
                loop {
                    items.push(self.value()?);
                    self.ws();
                    match self.b.get(self.i) {
                        Some(b',') => self.i += 1,
                        Some(b']') => {
                            self.i += 1;
                            return Ok(J::Arr(items));
                        }
                        _ => return Err(format!("expected `,` or `]` at byte {}", self.i)),
                    }
                }
            }
            Some(b'"') => Ok(J::Str(self.string()?)),
            Some(b't') => self.lit("true", J::Bool(true)),
            Some(b'f') => self.lit("false", J::Bool(false)),
            Some(b'n') => self.lit("null", J::Null),
            Some(b'-' | b'0'..=b'9') => {
                let start = self.i;
                while matches!(
                    self.b.get(self.i),
                    Some(b'-' | b'+' | b'.' | b'e' | b'E' | b'0'..=b'9')
                ) {
                    self.i += 1;
                }
                let text = std::str::from_utf8(&self.b[start..self.i]).unwrap();
                if text.parse::<f64>().is_err() {
                    return Err(format!("bad number `{text}`"));
                }
                Ok(J::Num(text.to_string()))
            }
            Some(c) => Err(format!("unexpected `{}` at byte {}", *c as char, self.i)),
        }
    }

    fn hex4(&mut self) -> Result<u32, String> {
        let h = self
            .b
            .get(self.i..self.i + 4)
            .and_then(|s| std::str::from_utf8(s).ok())
            .and_then(|s| u32::from_str_radix(s, 16).ok())
            .ok_or_else(|| format!("bad \\u escape at byte {}", self.i))?;
        self.i += 4;
        Ok(h)
    }

    fn string(&mut self) -> Result<String, String> {
        self.eat(b'"')?;
        let mut out: Vec<u8> = Vec::new();
        loop {
            let c = *self.b.get(self.i).ok_or("unterminated string")?;
            self.i += 1;
            match c {
                b'"' => break,
                b'\\' => {
                    let e = *self.b.get(self.i).ok_or("unterminated escape")?;
                    self.i += 1;
                    let ch = match e {
                        b'"' => '"',
                        b'\\' => '\\',
                        b'/' => '/',
                        b'b' => '\u{8}',
                        b'f' => '\u{c}',
                        b'n' => '\n',
                        b'r' => '\r',
                        b't' => '\t',
                        b'u' => {
                            let hi = self.hex4()?;
                            let cp = if (0xD800..0xDC00).contains(&hi) {
                                self.eat(b'\\')?;
                                self.eat(b'u')?;
                                let lo = self.hex4()?;
                                if !(0xDC00..0xE000).contains(&lo) {
                                    return Err("bad low surrogate".into());
                                }
                                0x10000 + ((hi - 0xD800) << 10) + (lo - 0xDC00)
                            } else {
                                hi
                            };
                            char::from_u32(cp).ok_or("bad code point")?
                        }
                        other => return Err(format!("bad escape `\\{}`", other as char)),
                    };
                    let mut buf = [0u8; 4];
                    out.extend_from_slice(ch.encode_utf8(&mut buf).as_bytes());
                }
                c if c < 0x20 => return Err(format!("raw control byte {c:#x} in string")),
                c => out.push(c),
            }
        }
        String::from_utf8(out).map_err(|_| "invalid UTF-8 in string".to_string())
    }
}

/// Parses one complete JSON document (surrounding whitespace allowed).
pub fn parse_json(text: &str) -> Result<J, String> {
    let mut r = Reader {
        b: text.as_bytes(),
        i: 0,
    };
    let v = r.value()?;
    r.ws();
    if r.i != r.b.len() {
        return Err(format!("trailing data at byte {}", r.i));
    }
    Ok(v)
}

// ---------------------------------------------------------------- running

#[derive(Debug, Clone)]
pub struct Out {
    /// Exit code; `-1` if the process was killed by a signal.
    pub code: i32,
    pub stdout: String,
    pub stderr: String,
}

impl Out {
    pub fn from_output(o: std::process::Output) -> Out {
        Out {
            code: o.status.code().unwrap_or(-1),
            stdout: String::from_utf8_lossy(&o.stdout).into_owned(),
            stderr: String::from_utf8_lossy(&o.stderr).into_owned(),
        }
    }

    /// Parses stdout as one JSON document.
    pub fn json(&self) -> J {
        parse_json(self.stdout.trim_end_matches('\n'))
            .unwrap_or_else(|e| panic!("stdout is not JSON ({e}): {:?}", self.stdout))
    }

    /// Parses the last line of stderr as JSON (used by `run --json`).
    pub fn stderr_last_json(&self) -> J {
        let line = self.stderr.lines().last().unwrap_or("");
        parse_json(line).unwrap_or_else(|e| panic!("last stderr line is not JSON ({e}): {line:?}"))
    }

    pub fn all(&self) -> String {
        format!("{}{}", self.stdout, self.stderr)
    }
}

pub fn is_root() -> bool {
    use std::os::unix::fs::MetadataExt;
    fs::metadata("/proc/self").is_ok_and(|m| m.uid() == 0)
}

/// A temp project with its own `XDG_STATE_HOME` and `HOME`, all under one base dir.
pub struct Proj {
    pub base: PathBuf,
    pub root: PathBuf,
    pub state: PathBuf,
    pub home: PathBuf,
}

impl Proj {
    pub fn new(name: &str) -> Proj {
        Proj::build(name, "proj", false)
    }

    /// A project whose directory name is `dir_name` (for hostile-name tests).
    pub fn named(name: &str, dir_name: &str) -> Proj {
        Proj::build(name, dir_name, false)
    }

    /// A project whose root *is* `$HOME`.
    pub fn at_home(name: &str) -> Proj {
        Proj::build(name, "home", true)
    }

    fn build(name: &str, dir_name: &str, root_is_home: bool) -> Proj {
        let n = COUNTER.fetch_add(1, Ordering::SeqCst);
        let base = std::env::temp_dir().join(format!("au-e2e-{}-{name}-{n}", std::process::id()));
        let _ = fs::remove_dir_all(&base);
        fs::create_dir_all(&base).unwrap();
        let base = fs::canonicalize(&base).unwrap();
        let root = base.join(dir_name);
        let state = base.join("state");
        let home = if root_is_home {
            root.clone()
        } else {
            base.join("home")
        };
        for d in [&root, &state, &home] {
            fs::create_dir_all(d).unwrap();
        }
        Proj {
            base,
            root,
            state,
            home,
        }
    }

    /// A plain project that is already initialized (external store).
    pub fn inited(name: &str) -> Proj {
        let p = Proj::new(name);
        let o = p.run(&["init"]);
        assert_eq!(o.code, 0, "init failed: {}", o.all());
        p
    }

    pub fn path(&self, rel: &str) -> PathBuf {
        self.root.join(rel)
    }

    pub fn command_in(&self, dir: &Path, args: &[&str], extra_env: &[(&str, &str)]) -> Command {
        let mut c = Command::new(BIN);
        c.env_clear()
            .env(
                "PATH",
                std::env::var_os("PATH").unwrap_or_else(|| "/usr/local/bin:/usr/bin:/bin".into()),
            )
            .env("HOME", &self.home)
            .env("XDG_STATE_HOME", &self.state)
            .current_dir(dir)
            .args(args);
        // When the suite runs under coverage instrumentation, let the spawned binary
        // write its profile next to the test binaries' (never into the project dir).
        if let Some(p) = std::env::var_os("LLVM_PROFILE_FILE") {
            c.env("LLVM_PROFILE_FILE", p);
        }
        for (k, v) in extra_env {
            c.env(k, v);
        }
        c.stdin(Stdio::null());
        c
    }

    /// Runs the binary with the project root as the working directory.
    pub fn run(&self, args: &[&str]) -> Out {
        self.run_in(&self.root, args)
    }

    pub fn run_in(&self, dir: &Path, args: &[&str]) -> Out {
        Out::from_output(self.command_in(dir, args, &[]).output().unwrap())
    }

    pub fn run_env(&self, args: &[&str], env: &[(&str, &str)]) -> Out {
        Out::from_output(self.command_in(&self.root, args, env).output().unwrap())
    }

    /// Spawns with piped output (for background processes).
    pub fn spawn(&self, args: &[&str], env: &[(&str, &str)]) -> Child {
        self.command_in(&self.root, args, env)
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .unwrap()
    }

    /// Runs with a watchdog: panics (after killing the child) if it takes longer than `limit`.
    pub fn run_limited(&self, args: &[&str], limit: Duration) -> Out {
        let mut child = self.spawn(args, &[]);
        let start = Instant::now();
        loop {
            if child.try_wait().unwrap().is_some() {
                break;
            }
            if start.elapsed() > limit {
                let _ = child.kill();
                let _ = child.wait();
                panic!("`{}` did not finish within {limit:?}", args.join(" "));
            }
            std::thread::sleep(Duration::from_millis(20));
        }
        Out::from_output(child.wait_with_output().unwrap())
    }

    /// Runs `args` with `--json` in front and returns the parsed stdout and exit code.
    pub fn json_code(&self, args: &[&str]) -> (i32, J) {
        let mut a = vec!["--json"];
        a.extend_from_slice(args);
        let o = self.run(&a);
        (o.code, o.json())
    }

    /// `--json` run that must exit 0 with `"ok":true`.
    pub fn json(&self, args: &[&str]) -> J {
        let mut a = vec!["--json"];
        a.extend_from_slice(args);
        let o = self.run(&a);
        assert_eq!(o.code, 0, "`{}` failed: {}", args.join(" "), o.all());
        let j = o.json();
        assert!(j.p("ok").bool(), "not ok: {}", o.stdout);
        j
    }

    /// `--json` run that must fail with exit code `code` and `error.code == err`.
    pub fn json_err(&self, args: &[&str], code: i32, err: &str) -> J {
        let (c, j) = self.json_code(args);
        assert_eq!(c, code, "`{}` exit code; json: {j:?}", args.join(" "));
        assert!(!j.p("ok").bool(), "expected ok=false: {j:?}");
        assert_eq!(j.p("error.code").str(), err, "{j:?}");
        j
    }

    /// `run -- sh -c <script>` in the project; asserts exit 0 and returns the checkpoint id.
    pub fn agent(&self, script: &str) -> u64 {
        let o = self.run(&["--json", "run", "--", "sh", "-c", script]);
        assert_eq!(o.code, 0, "agent script failed: {}", o.all());
        o.stderr_last_json().p("checkpoint.id").u64()
    }

    /// Like [`Proj::agent`] with extra `run` options before `--`.
    pub fn agent_with(&self, opts: &[&str], script: &str) -> u64 {
        let mut a = vec!["--json", "run"];
        a.extend_from_slice(opts);
        a.extend_from_slice(&["--", "sh", "-c", script]);
        let o = self.run(&a);
        assert_eq!(o.code, 0, "agent script failed: {}", o.all());
        o.stderr_last_json().p("checkpoint.id").u64()
    }

    /// Number of checkpoints in the journal.
    pub fn count(&self) -> usize {
        self.json(&["log"]).p("checkpoints").arr().len()
    }

    pub fn log(&self) -> J {
        self.json(&["log"])
    }

    /// The single external store directory under `$XDG_STATE_HOME/agent-undo`.
    pub fn store(&self) -> PathBuf {
        let base = self.state.join("agent-undo");
        let dirs: Vec<PathBuf> = fs::read_dir(&base)
            .unwrap_or_else(|e| panic!("no {}: {e}", base.display()))
            .map(|e| e.unwrap().path())
            .collect();
        assert_eq!(dirs.len(), 1, "expected exactly one store: {dirs:?}");
        dirs.into_iter().next().unwrap()
    }

    // ---- project file helpers

    pub fn write(&self, rel: &str, content: &str) {
        self.write_bytes(rel, content.as_bytes());
    }

    pub fn write_bytes(&self, rel: &str, content: &[u8]) {
        let p = self.path(rel);
        if let Some(parent) = p.parent() {
            fs::create_dir_all(parent).unwrap();
        }
        fs::write(p, content).unwrap();
    }

    pub fn read(&self, rel: &str) -> String {
        fs::read_to_string(self.path(rel)).unwrap_or_else(|e| panic!("cannot read {rel}: {e}"))
    }

    pub fn exists(&self, rel: &str) -> bool {
        fs::symlink_metadata(self.path(rel)).is_ok()
    }

    pub fn chmod(&self, rel: &str, mode: u32) {
        fs::set_permissions(self.path(rel), fs::Permissions::from_mode(mode)).unwrap();
    }

    pub fn mode(&self, rel: &str) -> u32 {
        fs::symlink_metadata(self.path(rel))
            .unwrap()
            .permissions()
            .mode()
            & 0o7777
    }
}

impl Drop for Proj {
    fn drop(&mut self) {
        // Make sure nothing we chmod'ed stays undeletable, then remove everything.
        fn open_up(p: &Path) {
            if let Ok(md) = fs::symlink_metadata(p)
                && md.is_dir()
            {
                let _ = fs::set_permissions(p, fs::Permissions::from_mode(0o700));
                if let Ok(rd) = fs::read_dir(p) {
                    for e in rd.flatten() {
                        open_up(&e.path());
                    }
                }
            }
        }
        open_up(&self.base);
        let _ = fs::remove_dir_all(&self.base);
    }
}

/// Mode bits (`& 0o777`) of a path, not following symlinks.
pub fn mode_of(p: &Path) -> u32 {
    fs::symlink_metadata(p).unwrap().permissions().mode() & 0o777
}

/// Recursively lists regular files below `dir`.
pub fn files_below(dir: &Path) -> Vec<PathBuf> {
    let mut out = Vec::new();
    for e in fs::read_dir(dir).unwrap().flatten() {
        let p = e.path();
        let ft = e.file_type().unwrap();
        if ft.is_dir() {
            out.extend(files_below(&p));
        } else if ft.is_file() {
            out.push(p);
        }
    }
    out.sort();
    out
}

/// Whether `needle` occurs in any file below `dir` (file names are not searched).
pub fn any_file_contains(dir: &Path, needle: &[u8]) -> bool {
    files_below(dir).iter().any(|f| {
        let mut data = Vec::new();
        fs::File::open(f)
            .and_then(|mut h| h.read_to_end(&mut data))
            .is_ok()
            && data.windows(needle.len()).any(|w| w == needle)
    })
}

/// Whether the external command `name` exists on PATH.
pub fn have_command(name: &str) -> bool {
    Command::new(name)
        .arg("--help")
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .is_ok()
}

/// Waits (up to `limit`) until `path` exists.
pub fn wait_for(path: &Path, limit: Duration) -> bool {
    let start = Instant::now();
    while start.elapsed() < limit {
        if path.exists() {
            return true;
        }
        std::thread::sleep(Duration::from_millis(20));
    }
    false
}
