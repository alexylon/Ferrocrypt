use clap::Parser;
use ferrocrypt::{
    CryptoError,
    hybrid_encryption,
    generate_asymmetric_key_pair,
    symmetric_encryption,
};

#[derive(Parser, Debug)]
#[clap(author, version, about, long_about = None)]
struct Args {
    /// Hybrid and Symmetric: File or directory path that needs to be encrypted, or the file path that needs to be decrypted
    #[clap(short, long, value_parser, default_value = "")]
    inpath: String,

    /// Hybrid and Symmetric: Destination directory path
    #[clap(short, long, value_parser, default_value = "")]
    outpath: String,

    /// Hybrid: Path to the public key for encryption, or the path to the private key for decryption
    #[clap(short, long, value_parser, default_value = "")]
    key: String,

    /// Hybrid: Passphrase to decrypt the private key
    /// Symmetric: Passphrase to derive the symmetric key for encryption and decryption
    #[clap(short, long, value_parser, default_value = "")]
    passphrase: String,

    /// Hybrid: Generate a private/public key pair
    #[clap(short, long)]
    generate: bool,

    /// Hybrid: Length of the key in bits for the key pair generation
    #[clap(short, long, default_value_t = 4096)]
    bit_size: u32,

    /// Symmetric: For large input file(s) that cannot fit to the RAM.
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
        hybrid_encryption(&args.inpath, &args.outpath, &mut args.key, &mut args.passphrase)?;
    } else if !args.passphrase.is_empty() {
        symmetric_encryption(&args.inpath, &args.outpath, &mut args.passphrase, args.large)?;
    } else {
        eprintln!("Error: No sufficient arguments supplied!");
    }

    Ok(())
}
