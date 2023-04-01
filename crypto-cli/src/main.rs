use std::error::Error;
use clap::Parser;
use crypto_lib;

#[derive(Parser, Debug)]
#[clap(author, version, about, long_about = None)]
struct Args {
    /// File or directory path to be encrypted
    #[clap(short, long, value_parser, default_value = "")]
    encrypt: String,

    /// File path to be decrypted
    #[clap(short, long, value_parser, default_value = "")]
    decrypt: String,

    /// Destination path
    #[clap(short, long, value_parser, default_value = "")]
    out: String,

    /// Key path: public key for encryption or private key for decryption
    #[clap(short, long, value_parser)]
    key: String,

    /// Passphrase for decrypting the private key
    #[clap(short, long, value_parser, default_value = "")]
    passphrase: String,
}

fn main() -> Result<(), Box<dyn Error>> {
    let args = Args::parse();
    if args.encrypt == "" && args.decrypt == "" {
        return Err(format!("Encrypt or decrypt path should be provided!").into());
    } else if args.encrypt != "" && args.decrypt != "" {
        return Err(format!("Only encrypt or only decrypt path should be provided!").into());
    } else {
        if args.encrypt != "" {
            // Error propagation intentionally not simplified with the question mark (?) operator
            match crypto_lib::encrypt_file_hybrid(&args.encrypt, &args.out, &args.key) {
                Ok(_) => {
                    println!("Encrypting {} ...", &args.encrypt);
                }
                Err(e) => {
                    return Err(format!("Cannot encrypt file: {:?}", e).into());
                }
            };
        }

        if args.decrypt != "" {
            // Error propagation intentionally not simplified with the question mark (?) operator
            match crypto_lib::decrypt_file_hybrid(&args.decrypt, &args.out, &args.key, &args.passphrase) {
                Ok(_) => {
                    println!("Decrypting {} ...", &args.decrypt);
                }
                Err(e) => { return Err(format!("Cannot decrypt file: {:?}", e).into()); }
            };
        }
    }

    Ok(())
}
