use clap::Parser;
use utf8_read::Reader;

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

// const FILE_PATH: &str = "src/test_files/test1.txt";
/// RSA-4096 PKCS#1 public key encoded as PEM
// const RSA_4096_PUB_PEM: &str = include_str!("key_examples/rsa4096-pub.pem");
/// RSA-4096 PKCS#1 private key encoded as PEM
// const RSA_4096_PRIV_PEM: &str = include_str!("key_examples/rsa4096-priv.pem");
// const FILE_PATH_DECRYPTED: &str = "src/test_files/test1_decrypted.txt";
// let priv_key = RsaPrivateKey::from_pkcs1_der(RSA_4096_PRIV_DER).unwrap();
// let pub_key = RsaPublicKey::from_pkcs1_der(RSA_4096_PUB_DER).unwrap();

fn main() {
    let args = Args::parse();

    match std::fs::File::open(args.key) {
        Ok(key_path) => {
            let mut reader = Reader::new(&key_path);
            let mut key = String::from("");
            for x in reader.into_iter() {
                match x {
                    Ok(character) => { key.push(character) }
                    Err(e) => { println!("Cannot get char: {}", e) }
                }
            }

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
