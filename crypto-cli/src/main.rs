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
    /// File path to be decrypted
    #[clap(short, long, value_parser, default_value = "")]
    inpath: String,

    /// Destination path
    #[clap(short, long, value_parser, default_value = "")]
    outpath: String,

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
        generate_asymmetric_key_pair(args.bit_size, &args.passphrase, &args.outpath)?;
    } else if args.inpath.is_empty() {
        eprintln!("Source path missing!");
    } else if !args.key.is_empty() {
        if args.inpath.ends_with(".rch") {
            decrypt_file_hybrid(&args.inpath, &args.outpath, &mut args.key, &mut args.passphrase)?;
        } else {
            encrypt_file_hybrid(&args.inpath, &args.outpath, &args.key)?;
        }
    } else if !args.passphrase.is_empty() {
        if args.large || args.inpath.ends_with(".rcls") {
            if args.inpath.ends_with(".rcls") {
                decrypt_large_file_symmetric(&args.inpath, &args.outpath, &mut args.passphrase)?;
            } else {
                encrypt_large_file_symmetric(&args.inpath, &args.outpath, &mut args.passphrase)?;
            }
        } else if args.inpath.ends_with(".rcs") {
            decrypt_file_symmetric(&args.inpath, &args.outpath, &mut args.passphrase)?;
        } else {
            encrypt_file_symmetric(&args.inpath, &args.outpath, &mut args.passphrase)?;
        }
    } else {
        eprintln!("Error: No sufficient arguments supplied!");
    }

    Ok(())
}
