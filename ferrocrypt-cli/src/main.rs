use clap::Parser;
use ferrocrypt::{
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
    /// Hybrid and Symmetric: File or directory path to be encrypted or file path to be decrypted
    #[clap(short, long, value_parser, default_value = "")]
    inpath: String,

    /// Hybrid and Symmetric: Destination directory path
    #[clap(short, long, value_parser, default_value = "")]
    outpath: String,

    /// Hybrid: Public key path for encryption or private key path for decryption
    #[clap(short, long, value_parser, default_value = "")]
    key: String,

    /// Hybrid: Passphrase for decrypting the private key
    /// Symmetric: Passphrase for symmetric key derivation on encryption and decryption
    #[clap(short, long, value_parser, default_value = "")]
    passphrase: String,

    /// Hybrid: Generate private and public key pair
    #[clap(short, long)]
    generate: bool,

    /// Hybrid: Key length in bits on key pair generation
    #[clap(short, long, default_value_t = 4096)]
    bit_size: u32,

    /// Symmetric: For large input file that doesn't fit to RAM. Much slower
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
        if args.inpath.ends_with(".fch") {
            decrypt_file_hybrid(&args.inpath, &args.outpath, &mut args.key, &mut args.passphrase)?;
        } else {
            encrypt_file_hybrid(&args.inpath, &args.outpath, &args.key)?;
        }
    } else if !args.passphrase.is_empty() {
        if args.large || args.inpath.ends_with(".fcls") {
            if args.inpath.ends_with(".fcls") {
                decrypt_large_file_symmetric(&args.inpath, &args.outpath, &mut args.passphrase)?;
            } else {
                encrypt_large_file_symmetric(&args.inpath, &args.outpath, &mut args.passphrase)?;
            }
        } else if args.inpath.ends_with(".fcs") {
            decrypt_file_symmetric(&args.inpath, &args.outpath, &mut args.passphrase)?;
        } else {
            encrypt_file_symmetric(&args.inpath, &args.outpath, &mut args.passphrase)?;
        }
    } else {
        eprintln!("Error: No sufficient arguments supplied!");
    }

    Ok(())
}