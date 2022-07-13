use std::fs;

use clap::Parser;

mod crypto;

#[derive(Parser, Debug)]
#[clap(author, version, about, long_about = None)]
struct Args {
    /// Encrypt
    #[clap(short, long, value_parser)]
    encrypt: bool,

    /// Decrypt
    #[clap(short, long, value_parser)]
    decrypt: bool,

    /// Input file path
    #[clap(short, long, value_parser)]
    input: String,

    /// Output file path
    #[clap(short, long, value_parser, default_value = "")]
    output: String,

    /// Path to the key
    #[clap(short, long, value_parser)]
    key: String,
}

fn main() {
    let args = Args::parse();

    match fs::read_to_string(args.key) {
        Ok(key) => {
            if args.encrypt {
                match crypto::encrypt_file(&args.input, &key) {
                    Ok(_) => {}
                    Err(e) => { println!("Cannot encrypt file: {}", e) }
                };
            }

            if args.decrypt {
                match crypto::decrypt_file(&args.input, &args.output, &key) {
                    Ok(_) => {}
                    Err(e) => { println!("Cannot decrypt file: {}", e) }
                };
            }
        }
        Err(e) => { println!("Cannot open key: {}", e) }
    }
}
