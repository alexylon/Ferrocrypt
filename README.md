# Ferrocrypt

Tiny, easy-to-use, and incredibly secure CLI encryption tool

## ABOUT

Ferrocrypt is a very small and simple encryption tool written in pure Rust.
Its name comes from the Latin words for iron, "ferrum" and for rust, "ferrugo".
With a user-friendly command-line interface, Ferrocrypt makes it easy
to encrypt and decrypt data using industry-standard algorithms.
The tool utilizes Rust's strong memory safety guarantees and performance benefits
to ensure the highest level of security and speed.

Ferrocrypt supports two different encryption modes:

1. Hybrid encryption: This method leverages both symmetric and asymmetric encryption algorithms
   to provide a robust and reliable encryption process.
   Specifically, Ferrocrypt uses the industry-standard AES-GCM symmetric algorithm to encrypt the data
   and RSA asymmetric encryption to encrypt the symmetric data key,
   providing an added layer of security.

2. Symmetric encryption: This mode uses the XChaCha20Poly1305 encryption algorithm,
   which is a variant of the popular ChaCha20-Poly1305 algorithm that provides stronger
   security guarantees.
   Additionally, Ferrocrypt employs the Argon2id password-based key derivation function
   to generate secure encryption keys from user passwords,
   making it easy for users to protect their data with a strong and unique password.

The two crates, implementing the AES-GCM and ChaCha20Poly1305 encryption algorithms,
`aes-gcm` and `chacha20poly1305`, have received security audits, with no significant findings.

The code is separated in two projects - a client `ferrocrypt-cli` and a library `ferrocrypt-lib`.

## BUILD

`cargo build --release`

The binary file will be generated in `target/release/fc` (macOS and Linux)
or `target\release\fc.exe` (Windows).

<br/>

## USAGE

The tool can automatically detect whether the source path requires
encryption or decryption, and which decryption mode should be used.

The commands listed below are compatible with macOS and Linux.
For Windows, simply substitute "./fc" with "fc" in each command.

The flags for each command can be used in any order.

<br/>

### Hybrid encryption

An ideal choice for secure data exchange, allowing files or directories
to be encrypted using a public key. However, decryption is only possible
with the corresponding private key and passphrase that unlocks the key.

- Generate a private/public key pair and set a passphrase for encrypting the private key

`./fc --generate --bit-size <BIT_SIZE> --passphrase <PASSPHRASE> --out <DEST_DIR_PATH>`

or

`./fc -g -b <BIT_SIZE> -p <PASSPHRASE> -o <DEST_DIR_PATH>`

- Encrypt file or directory

`./fc --inpath <SRC_PATH> --out <DEST_DIR_PATH> --key <PUBLIC_PEM_KEY>`

or

`./fc -i <SRC_PATH> -o <DEST_DIR_PATH> -k <PUBLIC_PEM_KEY>`

- Decrypt file:

`./fc --inpath <SRC_FILE_PATH> --out <DEST_DIR_PATH> --key <PRIVATE_PEM_KEY> --passphrase <PASSPHRASE>`

or

`./fc -i <SRC_FILE_PATH> -o <DEST_DIR_PATH> -k <PRIVATE_PEM_KEY> -p <PASSPHRASE>`

<br/>

### Symmetric encryption, which utilizes password-based key derivation

An excellent option for personal use cases. With this mode, data is encrypted
and decrypted using the same password, providing a simple and straightforward
approach to securing sensitive information.

- Encrypt file or directory | decrypt file

`./fc --inpath <SRC_PATH> --out <DEST_DIR_PATH> --passphrase <PASSPHRASE>`

or

`./fc -i <SRC_PATH> -o <DEST_DIR_PATH> -p <PASSPHRASE>`

<br/>

## OPTIONS:

| Flag                        | Description                                                                                                                           |
|-----------------------------|---------------------------------------------------------------------------------------------------------------------------------------|
| -i, --inpath <SRC_PATH>     | Hybrid and Symmetric: File or directory path that needs to be encrypted, <br/>or the file path that needs to be decrypted [default: ] |
| -o, --outpath <DEST_DIR>    | Hybrid and Symmetric: Destination directory path [default: ]                                                                          |                                                                             
| -k, --key <KEY_PATH>        | Hybrid: Path to the public key for encryption, <br/>or the path to the private key for decryption [default: ]                         |                                                         
| -p, --passphrase <PASSWORD> | Hybrid: Password to decrypt the private key <br/>Symmetric: Password to derive the symmetric key [default: ]                          |
| -g, --generate              | Hybrid: Generate a private/public key pair                                                                                            |                                                                                                 
| -b, --bit-size <BIT_SIZE>   | Hybrid: Length of the key in bits for the key pair generation [default: 4096]                                                         |                                                                          
| -l, --large                 | Symmetric: For large input file that cannot fit to the RAM. <br/>This is significantly slower.                                        |                                                                       
| -h, --help                  | Print help                                                                                                                            |                                                                                                                                   
| -V, --version               | Print version                                                                                                                         |                                                                                                                             |

<br/>

[![forthebadge](https://forthebadge.com/images/badges/made-with-rust.svg)](https://forthebadge.com)
