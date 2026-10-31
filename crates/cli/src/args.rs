//! Command-line parsing (hand-written; no argument-parsing dependency).

use agent_undo_app::error::{Error, Result};
use agent_undo_domain::esc::display;
use agent_undo_domain::units::{parse_duration, parse_size};
use std::ffi::{OsStr, OsString};
use std::os::unix::ffi::{OsStrExt, OsStringExt};
use std::path::PathBuf;
use std::time::Duration;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum UndoTarget {
    Checkpoint(u64),
    Last,
    /// `None` = the current session.
    Session(Option<u64>),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum GcPolicy {
    Keep(usize),
    OlderThan(Duration),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WatchOpts {
    pub interval: Duration,
    pub quiet: Duration,
    pub label: Option<Vec<u8>>,
    /// Stop after this many checkpoints were recorded.
    pub exit_after: Option<u64>,
    /// Stop after this long.
    pub timeout: Option<Duration>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Command {
    Init {
        in_project: bool,
        max_file_size: Option<u64>,
        allow_broad_root: bool,
    },
    Run {
        label: Option<Vec<u8>>,
        new_session: bool,
        env_allow: Vec<String>,
        args: Vec<Vec<u8>>,
    },
    Checkpoint {
        label: Option<Vec<u8>>,
        new_session: bool,
    },
    Log {
        session: Option<u64>,
    },
    Diff {
        checkpoint: u64,
    },
    Undo {
        target: UndoTarget,
        apply: bool,
        force: bool,
    },
    Restore {
        path: OsString,
        from: u64,
        apply: bool,
        force: bool,
    },
    Status,
    Verify,
    Gc {
        policy: GcPolicy,
        apply: bool,
    },
    Watch(WatchOpts),
    Doctor,
    Help(Option<String>),
    Version,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Cli {
    pub project: Option<PathBuf>,
    pub json: bool,
    pub command: Command,
}

fn usage(msg: impl Into<String>) -> Error {
    Error::Usage(msg.into())
}

struct Args {
    items: std::vec::IntoIter<OsString>,
    peeked: Option<OsString>,
}

impl Args {
    fn next(&mut self) -> Option<OsString> {
        self.peeked.take().or_else(|| self.items.next())
    }

    fn peek(&mut self) -> Option<&OsString> {
        if self.peeked.is_none() {
            self.peeked = self.items.next();
        }
        self.peeked.as_ref()
    }

    fn value(&mut self, flag: &str) -> Result<OsString> {
        self.next()
            .ok_or_else(|| usage(format!("{flag} needs a value")))
    }

    fn text(&mut self, flag: &str) -> Result<String> {
        let v = self.value(flag)?;
        v.into_string().map_err(|v| {
            usage(format!(
                "{flag} value is not valid UTF-8: {:?}",
                display(v.as_bytes())
            ))
        })
    }
}

fn parse_id(s: &str) -> Result<u64> {
    s.strip_prefix('#')
        .unwrap_or(s)
        .parse::<u64>()
        .ok()
        .filter(|n| *n > 0)
        .ok_or_else(|| {
            usage(format!(
                "invalid checkpoint {:?} (use a number such as 3 or #3)",
                agent_undo_domain::esc::display_str(s)
            ))
        })
}

fn parse_label(v: OsString) -> Vec<u8> {
    v.into_vec()
}

/// Parses the full argument list (without the program name).
pub fn parse(args: Vec<OsString>) -> Result<Cli> {
    let mut a = Args {
        items: args.into_iter(),
        peeked: None,
    };
    let mut project = None;
    let mut json = false;
    let mut name: Option<String> = None;
    let mut rest: Vec<OsString> = Vec::new();
    // Global options may appear before or after the command name.
    while let Some(arg) = a.next() {
        let s = arg.to_str().map(str::to_string);
        match s.as_deref() {
            Some("-C" | "--project") => project = Some(PathBuf::from(a.value("--project")?)),
            Some("--json") => json = true,
            Some("-h" | "--help") => {
                return Ok(Cli {
                    project,
                    json,
                    command: Command::Help(name),
                });
            }
            Some("-V" | "--version") => {
                return Ok(Cli {
                    project,
                    json,
                    command: Command::Version,
                });
            }
            Some("--") if name.is_some() => {
                rest.push(arg);
                rest.extend(a.items.by_ref());
                if let Some(p) = a.peeked.take() {
                    rest.push(p);
                }
                break;
            }
            Some(x) if name.is_none() && !x.starts_with('-') => name = Some(x.to_string()),
            _ if name.is_none() => {
                return Err(usage(format!(
                    "unknown option {:?}; try --help",
                    display(arg.as_bytes())
                )));
            }
            _ => rest.push(arg),
        }
    }
    let Some(name) = name else {
        return Ok(Cli {
            project,
            json,
            command: Command::Help(None),
        });
    };
    let command = parse_command(&name, rest)?;
    Ok(Cli {
        project,
        json,
        command,
    })
}

fn no_extra(a: &mut Args, cmd: &str) -> Result<()> {
    match a.next() {
        None => Ok(()),
        Some(x) => Err(usage(format!(
            "{cmd}: unexpected argument {:?}",
            display(x.as_bytes())
        ))),
    }
}

fn parse_command(name: &str, rest: Vec<OsString>) -> Result<Command> {
    let mut a = Args {
        items: rest.into_iter(),
        peeked: None,
    };
    match name {
        "init" => {
            let (mut in_project, mut max, mut broad) = (false, None, false);
            while let Some(x) = a.next() {
                match x.to_str() {
                    Some("--in-project") => in_project = true,
                    Some("--max-file-size") => max = Some(parse_size(&a.text("--max-file-size")?)?),
                    Some("--allow-broad-root") => broad = true,
                    _ => {
                        return Err(usage(format!(
                            "init: unexpected argument {:?}",
                            display(x.as_bytes())
                        )));
                    }
                }
            }
            Ok(Command::Init {
                in_project,
                max_file_size: max,
                allow_broad_root: broad,
            })
        }
        "run" => {
            let (mut label, mut new_session, mut env_allow) = (None, false, Vec::new());
            let mut cmd: Option<Vec<Vec<u8>>> = None;
            while let Some(x) = a.next() {
                match x.to_str() {
                    Some("--label") => label = Some(parse_label(a.value("--label")?)),
                    Some("--new-session") => new_session = true,
                    Some("--env-allow") => env_allow.push(a.text("--env-allow")?),
                    Some("--") => {
                        cmd = Some(a.items.by_ref().map(OsString::into_vec).collect());
                        if let Some(p) = a.peeked.take() {
                            cmd.get_or_insert_with(Vec::new).insert(0, p.into_vec());
                        }
                    }
                    _ => {
                        return Err(usage(format!(
                            "run: unexpected argument {:?} (put the command after `--`)",
                            display(x.as_bytes())
                        )));
                    }
                }
            }
            let args = cmd.filter(|c| !c.is_empty()).ok_or_else(|| {
                usage("run needs a command: agent-undo run [--label L] -- <command> [args...]")
            })?;
            Ok(Command::Run {
                label,
                new_session,
                env_allow,
                args,
            })
        }
        "checkpoint" => {
            let (mut label, mut new_session) = (None, false);
            while let Some(x) = a.next() {
                match x.to_str() {
                    Some("--label") => label = Some(parse_label(a.value("--label")?)),
                    Some("--new-session") => new_session = true,
                    _ => {
                        return Err(usage(format!(
                            "checkpoint: unexpected argument {:?}",
                            display(x.as_bytes())
                        )));
                    }
                }
            }
            Ok(Command::Checkpoint { label, new_session })
        }
        "log" => {
            let mut session = None;
            while let Some(x) = a.next() {
                match x.to_str() {
                    Some("--session") => session = Some(parse_id(&a.text("--session")?)?),
                    _ => {
                        return Err(usage(format!(
                            "log: unexpected argument {:?}",
                            display(x.as_bytes())
                        )));
                    }
                }
            }
            Ok(Command::Log { session })
        }
        "diff" => {
            let id = a
                .next()
                .ok_or_else(|| usage("diff needs a checkpoint number"))?;
            let id = parse_id(id.to_str().unwrap_or(""))?;
            no_extra(&mut a, "diff")?;
            Ok(Command::Diff { checkpoint: id })
        }
        "undo" => {
            let (mut target, mut apply, mut dry, mut force) =
                (None::<UndoTarget>, false, false, false);
            let set = |t: UndoTarget, target: &mut Option<UndoTarget>| -> Result<()> {
                if target.is_some() {
                    return Err(usage(
                        "undo takes exactly one of <checkpoint>, --last or --session",
                    ));
                }
                *target = Some(t);
                Ok(())
            };
            while let Some(x) = a.next() {
                match x.to_str() {
                    Some("--last") => set(UndoTarget::Last, &mut target)?,
                    Some("--session") => {
                        let n = match a.peek().and_then(|p| p.to_str()) {
                            Some(p)
                                if p.strip_prefix('#')
                                    .unwrap_or(p)
                                    .chars()
                                    .all(|c| c.is_ascii_digit())
                                    && !p.is_empty() =>
                            {
                                let v = parse_id(p)?;
                                a.next();
                                Some(v)
                            }
                            _ => None,
                        };
                        set(UndoTarget::Session(n), &mut target)?;
                    }
                    Some("--apply") => apply = true,
                    Some("--dry-run") => dry = true,
                    Some("--force") => force = true,
                    Some(p) if !p.starts_with('-') => {
                        set(UndoTarget::Checkpoint(parse_id(p)?), &mut target)?
                    }
                    _ => {
                        return Err(usage(format!(
                            "undo: unexpected argument {:?}",
                            display(x.as_bytes())
                        )));
                    }
                }
            }
            if apply && dry {
                return Err(usage("--apply and --dry-run cannot be combined"));
            }
            let target =
                target.ok_or_else(|| usage("undo needs <checkpoint>, --last or --session"))?;
            Ok(Command::Undo {
                target,
                apply,
                force,
            })
        }
        "restore" => {
            let (mut path, mut from, mut apply, mut dry, mut force) =
                (None::<OsString>, None, false, false, false);
            while let Some(x) = a.next() {
                match x.to_str() {
                    Some("--from") => from = Some(parse_id(&a.text("--from")?)?),
                    Some("--apply") => apply = true,
                    Some("--dry-run") => dry = true,
                    Some("--force") => force = true,
                    Some(p) if p.starts_with('-') && p != "-" => {
                        return Err(usage(format!(
                            "restore: unexpected option {:?}",
                            agent_undo_domain::esc::display_str(p)
                        )));
                    }
                    _ => {
                        if path.is_some() {
                            return Err(usage("restore takes a single path"));
                        }
                        path = Some(x);
                    }
                }
            }
            if apply && dry {
                return Err(usage("--apply and --dry-run cannot be combined"));
            }
            Ok(Command::Restore {
                path: path.ok_or_else(|| usage("restore needs a path"))?,
                from: from.ok_or_else(|| usage("restore needs --from <checkpoint>"))?,
                apply,
                force,
            })
        }
        "status" | "verify" | "doctor" => {
            no_extra(&mut a, name)?;
            Ok(match name {
                "status" => Command::Status,
                "verify" => Command::Verify,
                _ => Command::Doctor,
            })
        }
        "gc" => {
            let (mut policy, mut apply, mut dry) = (None::<GcPolicy>, false, false);
            while let Some(x) = a.next() {
                let mut set = |p: GcPolicy| -> Result<()> {
                    if policy.is_some() {
                        return Err(usage("gc takes exactly one of --keep N or --older-than D"));
                    }
                    policy = Some(p);
                    Ok(())
                };
                match x.to_str() {
                    Some("--keep") => {
                        let n: usize = a
                            .text("--keep")?
                            .parse()
                            .map_err(|_| usage("--keep needs a positive number"))?;
                        if n == 0 {
                            return Err(usage("--keep must be at least 1"));
                        }
                        set(GcPolicy::Keep(n))?;
                    }
                    Some("--older-than") => set(GcPolicy::OlderThan(parse_duration(
                        &a.text("--older-than")?,
                    )?))?,
                    Some("--apply") => apply = true,
                    Some("--dry-run") => dry = true,
                    _ => {
                        return Err(usage(format!(
                            "gc: unexpected argument {:?}",
                            display(x.as_bytes())
                        )));
                    }
                }
            }
            if apply && dry {
                return Err(usage("--apply and --dry-run cannot be combined"));
            }
            Ok(Command::Gc {
                policy: policy.ok_or_else(|| usage("gc needs --keep N or --older-than D"))?,
                apply,
            })
        }
        "watch" => {
            let mut w = WatchOpts {
                interval: Duration::from_secs(1),
                quiet: Duration::from_secs(2),
                label: None,
                exit_after: None,
                timeout: None,
            };
            while let Some(x) = a.next() {
                match x.to_str() {
                    Some("--interval") => w.interval = parse_duration(&a.text("--interval")?)?,
                    Some("--quiet") => w.quiet = parse_duration(&a.text("--quiet")?)?,
                    Some("--label") => w.label = Some(parse_label(a.value("--label")?)),
                    Some("--exit-after") => {
                        w.exit_after = Some(
                            a.text("--exit-after")?
                                .parse()
                                .map_err(|_| usage("--exit-after needs a number"))?,
                        );
                    }
                    Some("--timeout") => w.timeout = Some(parse_duration(&a.text("--timeout")?)?),
                    _ => {
                        return Err(usage(format!(
                            "watch: unexpected argument {:?}",
                            display(x.as_bytes())
                        )));
                    }
                }
            }
            if w.interval.is_zero() {
                return Err(usage("--interval must be greater than zero"));
            }
            Ok(Command::Watch(w))
        }
        "help" => Ok(Command::Help(a.next().and_then(|s| s.into_string().ok()))),
        other => Err(usage(format!(
            "unknown command {:?}; try --help",
            agent_undo_domain::esc::display_str(other)
        ))),
    }
}

/// Whether an `OsStr` is exactly `s` (helper for tests).
pub fn is(arg: &OsStr, s: &str) -> bool {
    arg.to_str() == Some(s)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn p(args: &[&str]) -> Result<Cli> {
        parse(args.iter().map(OsString::from).collect())
    }

    fn cmd(args: &[&str]) -> Command {
        p(args).unwrap().command
    }

    #[test]
    fn no_args_and_help_flags() {
        assert_eq!(cmd(&[]), Command::Help(None));
        assert_eq!(cmd(&["--help"]), Command::Help(None));
        assert_eq!(cmd(&["undo", "--help"]), Command::Help(Some("undo".into())));
        assert_eq!(cmd(&["help", "gc"]), Command::Help(Some("gc".into())));
        assert_eq!(cmd(&["--version"]), Command::Version);
    }

    #[test]
    fn global_options_before_and_after_command() {
        let c = p(&["-C", "/proj", "--json", "status"]).unwrap();
        assert_eq!(
            (c.project.as_deref(), c.json),
            (Some(std::path::Path::new("/proj")), true)
        );
        let c = p(&["status", "--json", "--project", "/p"]).unwrap();
        assert!(c.json && c.project.is_some());
        assert!(p(&["-C"]).is_err());
    }

    #[test]
    fn unknown_command_and_option() {
        assert!(matches!(p(&["frobnicate"]), Err(Error::Usage(_))));
        assert!(matches!(p(&["--frobnicate"]), Err(Error::Usage(_))));
        assert!(p(&["status", "extra"]).is_err());
    }

    #[test]
    fn init_options() {
        assert_eq!(
            cmd(&[
                "init",
                "--in-project",
                "--max-file-size",
                "1MiB",
                "--allow-broad-root"
            ]),
            Command::Init {
                in_project: true,
                max_file_size: Some(1 << 20),
                allow_broad_root: true
            }
        );
        assert!(p(&["init", "--max-file-size", "lots"]).is_err());
        assert!(p(&["init", "--bogus"]).is_err());
        assert!(p(&["init", "--max-file-size"]).is_err());
    }

    #[test]
    fn run_collects_command_after_double_dash() {
        let c = cmd(&[
            "run",
            "--label",
            "fix",
            "--new-session",
            "--env-allow",
            "A,B",
            "--",
            "sh",
            "-c",
            "echo hi",
            "--json",
        ]);
        assert_eq!(
            c,
            Command::Run {
                label: Some(b"fix".to_vec()),
                new_session: true,
                env_allow: vec!["A,B".into()],
                args: vec![
                    b"sh".to_vec(),
                    b"-c".to_vec(),
                    b"echo hi".to_vec(),
                    b"--json".to_vec()
                ],
            }
        );
    }

    #[test]
    fn run_requires_a_command() {
        assert!(p(&["run"]).is_err());
        assert!(p(&["run", "--"]).is_err());
        assert!(p(&["run", "sh"]).is_err(), "command must follow --");
        assert!(p(&["run", "--label"]).is_err());
    }

    #[test]
    fn global_flags_after_double_dash_belong_to_the_command() {
        let c = p(&["run", "--", "echo", "--json", "-C", "x"]).unwrap();
        assert!(!c.json);
        assert!(c.project.is_none());
    }

    #[test]
    fn checkpoint_and_log() {
        assert_eq!(
            cmd(&["checkpoint", "--label", "x", "--new-session"]),
            Command::Checkpoint {
                label: Some(b"x".to_vec()),
                new_session: true
            }
        );
        assert_eq!(cmd(&["log"]), Command::Log { session: None });
        assert_eq!(
            cmd(&["log", "--session", "2"]),
            Command::Log { session: Some(2) }
        );
        assert!(p(&["log", "--session", "zero"]).is_err());
        assert!(p(&["checkpoint", "x"]).is_err());
    }

    #[test]
    fn diff_needs_a_valid_checkpoint() {
        assert_eq!(cmd(&["diff", "3"]), Command::Diff { checkpoint: 3 });
        assert_eq!(cmd(&["diff", "#7"]), Command::Diff { checkpoint: 7 });
        assert!(p(&["diff"]).is_err());
        assert!(p(&["diff", "0"]).is_err());
        assert!(p(&["diff", "x"]).is_err());
        assert!(p(&["diff", "1", "2"]).is_err());
    }

    #[test]
    fn undo_targets_and_flags() {
        assert_eq!(
            cmd(&["undo", "4"]),
            Command::Undo {
                target: UndoTarget::Checkpoint(4),
                apply: false,
                force: false
            }
        );
        assert_eq!(
            cmd(&["undo", "--last", "--apply", "--force"]),
            Command::Undo {
                target: UndoTarget::Last,
                apply: true,
                force: true
            }
        );
        assert!(matches!(
            cmd(&["undo", "--session"]),
            Command::Undo {
                target: UndoTarget::Session(None),
                ..
            }
        ));
        assert!(matches!(
            cmd(&["undo", "--session", "3"]),
            Command::Undo {
                target: UndoTarget::Session(Some(3)),
                ..
            }
        ));
        assert!(matches!(
            cmd(&["undo", "--session", "--apply"]),
            Command::Undo {
                target: UndoTarget::Session(None),
                apply: true,
                ..
            }
        ));
    }

    #[test]
    fn undo_rejects_bad_combinations() {
        assert!(p(&["undo"]).is_err());
        assert!(p(&["undo", "1", "--last"]).is_err());
        assert!(p(&["undo", "--last", "--session"]).is_err());
        assert!(p(&["undo", "--last", "--apply", "--dry-run"]).is_err());
        assert!(p(&["undo", "--bogus"]).is_err());
        assert!(p(&["undo", "abc"]).is_err());
    }

    #[test]
    fn restore_parsing() {
        assert_eq!(
            cmd(&["restore", "src/a.rs", "--from", "#2", "--apply"]),
            Command::Restore {
                path: "src/a.rs".into(),
                from: 2,
                apply: true,
                force: false
            }
        );
        assert!(p(&["restore", "a"]).is_err(), "needs --from");
        assert!(p(&["restore", "--from", "1"]).is_err(), "needs a path");
        assert!(p(&["restore", "a", "b", "--from", "1"]).is_err());
        assert!(p(&["restore", "a", "--from", "1", "--apply", "--dry-run"]).is_err());
        assert!(p(&["restore", "a", "--from", "1", "--weird"]).is_err());
    }

    #[test]
    fn gc_parsing() {
        assert_eq!(
            cmd(&["gc", "--keep", "5"]),
            Command::Gc {
                policy: GcPolicy::Keep(5),
                apply: false
            }
        );
        assert_eq!(
            cmd(&["gc", "--older-than", "7d", "--apply"]),
            Command::Gc {
                policy: GcPolicy::OlderThan(Duration::from_secs(7 * 86_400)),
                apply: true
            }
        );
        assert!(p(&["gc"]).is_err());
        assert!(p(&["gc", "--keep", "0"]).is_err());
        assert!(p(&["gc", "--keep", "x"]).is_err());
        assert!(p(&["gc", "--keep", "1", "--older-than", "1d"]).is_err());
        assert!(p(&["gc", "--keep", "1", "--apply", "--dry-run"]).is_err());
        assert!(p(&["gc", "--older-than", "soon"]).is_err());
    }

    #[test]
    fn watch_parsing() {
        let c = cmd(&[
            "watch",
            "--interval",
            "250ms",
            "--quiet",
            "1s",
            "--label",
            "w",
            "--exit-after",
            "2",
            "--timeout",
            "1m",
        ]);
        assert_eq!(
            c,
            Command::Watch(WatchOpts {
                interval: Duration::from_millis(250),
                quiet: Duration::from_secs(1),
                label: Some(b"w".to_vec()),
                exit_after: Some(2),
                timeout: Some(Duration::from_secs(60)),
            })
        );
        assert!(matches!(cmd(&["watch"]), Command::Watch(_)));
        assert!(p(&["watch", "--interval", "0"]).is_err());
        assert!(p(&["watch", "--exit-after", "x"]).is_err());
        assert!(p(&["watch", "--bogus"]).is_err());
    }

    #[test]
    fn simple_commands_reject_extras() {
        assert_eq!(cmd(&["status"]), Command::Status);
        assert_eq!(cmd(&["verify"]), Command::Verify);
        assert_eq!(cmd(&["doctor"]), Command::Doctor);
        assert!(p(&["verify", "x"]).is_err());
        assert!(p(&["doctor", "--fix"]).is_err());
    }

    #[test]
    fn non_utf8_paths_and_labels_are_accepted() {
        let weird = OsString::from_vec(vec![b'a', 0xff, b'b']);
        let c = parse(vec![
            "restore".into(),
            weird.clone(),
            "--from".into(),
            "1".into(),
        ])
        .unwrap();
        assert!(matches!(c.command, Command::Restore { ref path, .. } if *path == weird));
        let c = parse(vec!["checkpoint".into(), "--label".into(), weird]).unwrap();
        assert!(
            matches!(c.command, Command::Checkpoint { label: Some(ref l), .. } if l == &[b'a', 0xff, b'b'])
        );
    }

    #[test]
    fn error_messages_escape_hostile_arguments() {
        let hostile = OsString::from_vec(b"\x1b[31mbad".to_vec());
        let e = parse(vec!["status".into(), hostile]).unwrap_err();
        assert!(!e.to_string().contains('\x1b'));
    }

    #[test]
    fn is_helper() {
        assert!(is(OsStr::new("x"), "x"));
        assert!(!is(OsStr::new("x"), "y"));
    }
}
