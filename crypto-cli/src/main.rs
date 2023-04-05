use clap::Parser;
use crypto_lib::{
    CryptoError,
    decrypt_file_hybrid,
    encrypt_file_hybrid,
    generate_asymmetric_key_pair,
    encrypt_file_symmetric,
    decrypt_file_symmetric,
    encrypt_large_file_symmetric,
    decrypt_large_file_symmetric,
};

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
    #[clap(short, long, value_parser, default_value = "")]
    key: String,

    /// Passphrase for decrypting the private key or for symmetric key derivation
    #[clap(short, long, value_parser, default_value = "")]
    passphrase: String,

    /// Generate private and public key pair
    #[clap(short, long)]
    generate: bool,

    /// Generate private and public key pair directory path
    #[clap(short, long, default_value_t = 4096)]
    bit_size: u32,

    /// For large input file that doesn't fit to RAM. Much slower
    #[clap(short, long)]
    large: bool,
}

fn main() -> Result<(), CryptoError> {
    let mut args = Args::parse();

    if args.generate {
        generate_asymmetric_key_pair(args.bit_size, &args.passphrase, &args.out)?;
    } else if args.encrypt.is_empty() && args.decrypt.is_empty() {
        eprintln!("No sufficient arguments supplied!");
    } else if !args.encrypt.is_empty() && !args.decrypt.is_empty() {
        eprintln!("Only encrypt or only decrypt path should be provided!");
    } else if !args.key.is_empty() {
        if !args.encrypt.is_empty() {
            encrypt_file_hybrid(&args.encrypt, &args.out, &args.key)?;
        }

        if !args.decrypt.is_empty() {
            decrypt_file_hybrid(&args.decrypt, &args.out, &mut args.key, &mut args.passphrase)?;
        }
    } else if !args.passphrase.is_empty() {
        if args.large {
            if !args.encrypt.is_empty() {
                encrypt_large_file_symmetric(&args.encrypt, &args.out, &mut args.passphrase)?;
            }

            if !args.decrypt.is_empty() {
                decrypt_large_file_symmetric(&args.decrypt, &args.out, &mut args.passphrase)?;
            }
        } else {
            if !args.encrypt.is_empty() {
                encrypt_file_symmetric(&args.encrypt, &args.out, &mut args.passphrase)?;
            }

            if !args.decrypt.is_empty() {
                decrypt_file_symmetric(&args.decrypt, &args.out, &mut args.passphrase)?;
            }
        }
    } else {
        eprintln!("Error: No sufficient arguments supplied!");
    }

    Ok(())
}
