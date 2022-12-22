mod cli;

use clap::Parser;
use cli::Cli;
use env_logger::{Builder, Env};
use std::io::Write;

const FILTER_ENV: &str = "ADBORC_LOG_LEVEL";
const STYLE_ENV: &str = "ADBORC_LOG_STYLE";

fn main() {
    // Initialize the logger.
    let env = Env::default()
        .filter_or(FILTER_ENV, "info")
        .write_style_or(STYLE_ENV, "auto");

    Builder::from_env(env)
        .format(|buf, record| {
            let ts = buf.timestamp();
            writeln!(
                buf,
                "[{} {} {}::{}] {}",
                ts,
                record.level(),
                record.module_path().unwrap(),
                record.line().unwrap(),
                record.args()
            )
        })
        .init();

    let cli = Cli::parse();
    cli.process();
}
