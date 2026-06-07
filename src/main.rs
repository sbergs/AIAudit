//! AIHound: AI credential & secrets scanner.

mod cli;
mod mcp;
mod output;
mod permissions;
mod platform;
mod redactor;
mod remediation;
mod remote;
mod scanner;
mod scanners;

fn main() {
    let code = match cli::run() {
        Ok(code) => code,
        Err(e) => {
            eprintln!("ERROR: {:#}", e);
            1
        }
    };
    std::process::exit(code);
}
