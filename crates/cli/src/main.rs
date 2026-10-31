#![forbid(unsafe_code)]

fn main() {
    let args: Vec<std::ffi::OsString> = std::env::args_os().skip(1).collect();
    let stdout = std::io::stdout();
    let stderr = std::io::stderr();
    let code = agent_undo_cli::commands::main_with(args, &mut stdout.lock(), &mut stderr.lock());
    std::process::exit(code);
}
