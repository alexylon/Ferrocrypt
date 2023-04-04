# rusty-crypto

## CLI encrypting / decrypting tool

### ABOUT

**rusty-crypto** is a pure Rust implementation of a client-side encryption tool.

Supports two kinds of encryption:

- Hybrid, relying on the combination of using both symmetric AES-GCM algorithm, for encrypting the data
  and asymmetric RSA algorithm, for encrypting the symmetric data key.
- Symmetric, using XChaCha20Poly1305 algorithms and Argon2id password-based key derivation function.

The two crates, implementing the AES-GCM and ChaCha20Poly1305 encryption algorithms,
`aes-gcm` and `chacha20poly1305`, have received security audits, with no significant findings.

The code is separated in two projects - a client `crypto-cli` and a library `crypto-lib`.

### USAGE

#### BUILD

`cargo build --release` - the binary file is located in `target/release/crypto` (macOS and Linux) or `target\release\crypto.exe` (Windows).

### macOS and Linux

#### Hybrid encryption

##### Generate private / public key pair with a passphrase for the encryption of the private key

`./crypto --generate --bit-size <BIT_SIZE> --passphrase <PASSPHRASE> --out <DEST_DIR_PATH>`

or

`./crypto -g -b <BIT_SIZE> -p <PASSPHRASE> -o <DEST_DIR_PATH>`

##### Encrypt file or directory

`./crypto --encrypt <SRC_PATH> --out <DEST_DIR_PATH> --key <PUBLIC_PEM_KEY>`

or

`./crypto -e <SRC_PATH> -o <DEST_DIR_PATH> -k <PUBLIC_PEM_KEY>`

##### Decrypt file:

`./crypto --decrypt <SRC_FILE_PATH> --out <DEST_DIR_PATH> --key <PRIVATE_PEM_KEY>`

or

`./crypto -d <SRC_FILE_PATH> -o <DEST_DIR_PATH> -k <PRIVATE_PEM_KEY>`
<br/><br/>

#### Symmetric encryption with password-based key derivation

##### Encrypt file or directory

`./crypto --encrypt <SRC_PATH> --out <DEST_DIR_PATH> --passphrase <PASSPHRASE>`

or

`./crypto -e <SRC_PATH> -o <DEST_DIR_PATH> -p <PASSPHRASE>`

##### Decrypt file:

`./crypto --decrypt <SRC_FILE_PATH> --out <DEST_DIR_PATH> --passphrase <PASSPHRASE>`

or

`./crypto -d <SRC_FILE_PATH> -o <DEST_DIR_PATH> -p <PASSPHRASE>`
<br/><br/>

### Windows:

Just replace the command `./crypto` with `crypto`

### OPTIONS:

| Flag                            | Description                                                                           |
|---------------------------------|---------------------------------------------------------------------------------------|
| `-b, --bit-size <BIT_SIZE>`     | Generate private and public key pair directory path [default:4096]                    |
| `-d, --decrypt <SRC_FILE_PATH>` | File path to be decrypted [default: ]                                                 |
| `-e, --encrypt <SRC_PATH>`      | File or directory path to be encrypted [default: ]                                    |
| `-g, --generate`                | Generate private and public key pair                                                  |
| `-h, --help`                    | Print help information                                                                |
| `-k, --key <KEY_PATH>`          | Key path: public key for encryption or private key for decryption [default: ]         |
| `-o, --out <DEST_DIR_PATH>`     | Destination path [default: ]                                                          |
| `-p, --passphrase <PASSPHRASE>` | Passphrase for decrypting the private key or for symmetric key derivation [default: ] |
| `-V, --version`                 | Print version information                                                             |

[![forthebadge](https://forthebadge.com/images/badges/made-with-rust.svg)](https://forthebadge.com)
