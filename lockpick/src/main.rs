mod arguments;
mod aes_candidate;
mod aes_dumpster;
mod output;

use clap::Parser;
use log::{error, info};
use std::io::Result as IoResult;
use std::path::PathBuf;

use aes_dumpster::AesDumpster;
use arguments::Args;

fn load_file(path: &PathBuf) -> IoResult<Vec<u8>> {
    use std::fs::File;
    use std::io::Read;

    info!("Loading file: {:?}", path);
    let mut file = File::open(path)?;
    let mut buffer = Vec::new();
    file.read_to_end(&mut buffer)?;
    info!("Loaded {} bytes", buffer.len());
    Ok(buffer)
}

fn setup() -> () {
    env_logger::Builder::new()
        .filter_level(log::LevelFilter::Debug)
        .format_timestamp_secs()
        .init();
}

fn main() -> IoResult<()> {
    setup();

    let args: Args = Args::parse();

    info!("Target: {:?}", args.file);

    if !args.file.exists() {
        error!("File not found: {:?}", args.file);
        std::process::exit(1);
    }

    let buffer: Vec<u8> = match load_file(&args.file) {
        Ok(buf) => buf,
        Err(e) => {
            error!("Failed to load file: {}", e);
            std::process::exit(1);
        }
    };

    let dumpster: AesDumpster = AesDumpster::new(buffer, args.entropy);
    dumpster.scan();

    Ok(())
}
