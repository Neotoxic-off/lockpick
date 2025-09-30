use clap::Parser;
use std::path::PathBuf;

#[derive(Parser, Debug)]
#[command(author, version, about, long_about = None)]
pub struct Args {
    #[arg(short, long)]
    pub file: PathBuf,

    #[arg(short, long, default_value_t = 3.3)]
    pub entropy: f64,
}
