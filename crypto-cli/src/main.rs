use std::error::Error;
use std::fs;

use clap::Parser;

use crypto_lib;

#[derive(Parser, Debug)]
#[clap(author, version, about, long_about = None)]
struct Args {
    /// File path to be encrypted
    #[clap(short, long, value_parser, default_value = "")]
    encrypt: String,

    /// File path to be decrypted
    #[clap(short, long, value_parser, default_value = "")]
    decrypt: String,

    /// Key path
    #[clap(short, long, value_parser)]
    key: String,
}

fn main() -> Result<(), Box<dyn Error>> {
    let args = Args::parse();

    if args.encrypt != "" || args.decrypt != "" {
        match fs::read_to_string(args.key) {
            Ok(key) => {
                if args.encrypt != "" {
                    match crypto_lib::encrypt_file(&args.encrypt, &key) {
                        Ok(_) => { println!("Encrypting {} ...", &args.encrypt); }
                        Err(e) => { return Err(format!("Cannot encrypt file: {}", e).into()); }
                    };
                }

                if args.decrypt != "" {
                    match crypto_lib::decrypt_file(&args.decrypt, &key) {
                        Ok(_) => {
                            println!("Decrypting {} ...", &args.decrypt);
                        }
                        Err(e) => { return Err(format!("Cannot decrypt file: {}", e).into()); }
                    };
                }
            }
            Err(e) => { return Err(format!("Cannot open key: {}", e).into()); }
        }
    } else {
        return Err(format!("No path provided!").into());
    }

    Ok(())
}
