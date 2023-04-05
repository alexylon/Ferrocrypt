# Ferrocrypt

## CLI encrypting / decrypting tool

### ABOUT

Ferrocrypt is a pure Rust implementation of a client-side encryption tool.

Supports two kinds of encryption:

- Hybrid, relying on the combination of using both symmetric AES-GCM algorithm, for encrypting the data
  and asymmetric RSA algorithm, for encrypting the symmetric data key.
- Symmetric, using XChaCha20Poly1305 algorithms and Argon2id password-based key derivation function.

The two crates, implementing the AES-GCM and ChaCha20Poly1305 encryption algorithms,
`aes-gcm` and `chacha20poly1305`, have received security audits, with no significant findings.

The code is separated in two projects - a client `ferrocrypt-cli` and a library `ferrocrypt-lib`.

### BUILD

`cargo build --release` - the binary file is located in `target/release/fc` (macOS and Linux) or `target\release\fc.exe` (Windows).

<br/>

### USAGE

#### macOS and Linux (flags after the command can be in any order)

<br/>

##### Hybrid encryption 

Suitable for data exchange, where the files or directories can be encrypted with any public key, 
but can be only decrypted with the corresponding private key and the passphrase, which decrypts this key.

###### Generate private / public key pair with a passphrase for the encryption of the private key

`./fc --generate --bit-size <BIT_SIZE> --passphrase <PASSPHRASE> --out <DEST_DIR_PATH>`

or

`./fc -g -b <BIT_SIZE> -p <PASSPHRASE> -o <DEST_DIR_PATH>`

###### Encrypt file or directory

`./fc --inpath <SRC_PATH> --out <DEST_DIR_PATH> --key <PUBLIC_PEM_KEY>`

or

`./fc -i <SRC_PATH> -o <DEST_DIR_PATH> -k <PUBLIC_PEM_KEY>`

###### Decrypt file:

`./fc --inpath <SRC_FILE_PATH> --out <DEST_DIR_PATH> --key <PRIVATE_PEM_KEY> --passphrase <PASSPHRASE>`

or

`./fc -i <SRC_FILE_PATH> -o <DEST_DIR_PATH> -k <PRIVATE_PEM_KEY> -p <PASSPHRASE>`

<br/>

##### Symmetric encryption with password-based key derivation

Suitable for personal use, where the data is encrypted and decrypted with the same password.

###### Encrypt file or directory / Decrypt file

`./fc --inpath <SRC_PATH> --out <DEST_DIR_PATH> --passphrase <PASSPHRASE>`

or

`./fc -i <SRC_PATH> -o <DEST_DIR_PATH> -p <PASSPHRASE>`

<br/>

#### Windows:

Just replace the command `./fc` with `fc`

<br/>

### OPTIONS:

| Flag                          | Description                                                                                                                                        |
|-------------------------------|----------------------------------------------------------------------------------------------------------------------------------------------------|
| -i, --inpath <INPATH>         | Hybrid and Symmetric: File or directory path to be encrypted or file path to be decrypted [default: ]                                              |
| -o, --outpath <OUTPATH>       | Hybrid and Symmetric: Destination directory path [default: ]                                                                                       |                                                                             
| -k, --key <KEY>               | Hybrid: Public key path for encryption or private key path for decryption [default: ]                                                              |                                                         
| -p, --passphrase <PASSPHRASE> | Hybrid: Passphrase for decrypting the private key <br/>Symmetric: Passphrase for symmetric key derivation on encryption and decryption [default: ] |
| -g, --generate                | Hybrid: Generate private and public key pair                                                                                                       |                                                                                                 
| -b, --bit-size <BIT_SIZE>     | Hybrid: Key length in bits on key pair generation [default: 4096]                                                                                  |                                                                          
| -l, --large                   | Symmetric: For large input file that doesn't fit to RAM. Much slower                                                                               |                                                                       
| -h, --help                    | Print help                                                                                                                                         |                                                                                                                                   
| -V, --version                 | Print version                                                                                                                                      |                                                                                                                             |

<br/>

[![forthebadge](https://forthebadge.com/images/badges/made-with-rust.svg)](https://forthebadge.com)
