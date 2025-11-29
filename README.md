# Ferrocrypt

Tiny, easy-to-use, and highly secure multiplatform encryption tool with CLI and GUI interfaces.
Written entirely in Rust.

<br/>

<div align="center"><img align="center" src="/ferrocrypt-gui-tauri/src/images/ferrocrypt_screenshot.png" width="400" alt="Ferrocrypt"></div>

<br/>

## ABOUT

Ferrocrypt is a simple encryption tool leveraging Rust's memory safety guarantees and performance benefits.
The name comes from Latin: "ferrum" (iron) and "ferrugo" (rust).

**GUI Options:**
- Tauri app (Rust + React frontend)
- Dioxus desktop app (pure Rust)

**Encryption Modes:**

1. **Symmetric** - Uses XChaCha20-Poly1305 encryption with Argon2id password-based key derivation. Ideal for personal use where the same password encrypts and decrypts data. Produces `.fcs` vault files.

2. **Hybrid** - Combines XChaCha20-Poly1305 (data encryption) with RSA-4096 (key encryption). Each file/folder gets a unique random key, encrypted with your public key. Requires both the private key AND password for decryption, providing dual-layer security. Produces `.fch` vault files.

**Security Features:**

- **Audited encryption**: Uses the `chacha20poly1305` crate, which has undergone successful security audits
- **Secure secret handling**: Passphrases are protected using the `secrecy` crate, preventing accidental exposure through Debug/Display traits and ensuring automatic memory zeroization when dropped
- **Error correction**: Reed-Solomon parity bytes protect cryptographic headers from corruption due to bit rot or data transfer errors, enabling reliable data recovery

The code is separated in multiple projects - the library `ferrocrypt-lib`, a CLI client `ferrocrypt-cli`,
a [**TAURI**](https://tauri.app/) based GUI app `ferrocrypt-gui-tauri`, and a [**Dioxus**](https://dioxuslabs.com/) based GUI app `ferrocrypt-gui-dioxus`.

<br/>

## BUILD the GUI apps (tested on macOS)

### Tauri GUI

After installing [Rust](https://www.rust-lang.org/learn/get-started) and [Node.js](https://nodejs.org/) (at least v.18),
navigate to the `ferrocrypt-gui-tauri` directory and run the following commands:

### Install the `create-tauri-app` utility:

```cargo install create-tauri-app```

### Install the Tauri CLI:

```cargo install tauri-cli```

### Install node modules:

```npm install```

### Build the app to a binary executable file:

```cargo tauri build```

The binary executable file of the GUI app will be generated in `ferrocrypt-gui-tauri/src-tauri/target/release/`

### Build a DMG installer for macOS:

```cargo tauri build --bundles dmg```

The DMG image file of the GUI app will be generated in `ferrocrypt-gui-tauri/src-tauri/target/release/bundle/dmg/`

### You can start a live dev session with:

```cargo tauri dev```

<br/>

### Dioxus GUI

After [installing Rust](https://www.rust-lang.org/tools/install), install the Dioxus CLI:

- Install `cargo-binstall`:

```bash
curl -L --proto '=https' --tlsv1.2 -sSf https://raw.githubusercontent.com/cargo-bins/cargo-binstall/main/install-from-binstall-release.sh | bash
```

- Install Dioxus CLI:

```bash
cargo binstall dioxus-cli
```

Navigate to the `ferrocrypt-gui-dioxus` directory and run:

### Build release binary:

```bash
cargo build --release
```

The binary will be generated in `target/release/ferrocrypt-gui-dioxus`

### Start a live dev session:

```bash
dx serve
```

### Bundle the desktop app:

```bash
dx bundle
```

<br/>

## USING the GUI App

Drag and drop a file or folder into the app window, then select the encryption mode. When decrypting, the app auto-detects the mode.

### Symmetric Encryption Mode

Encrypt/decrypt using the same password. Choose a password, destination folder, and click "Encrypt". For large files, enable "Large files (low RAM usage)" to reduce memory consumption.

### Hybrid Encryption Mode

Ideal for secure data exchange. Encrypt using a _public_ RSA key (PEM format), decrypt using the corresponding _private_ key and password.

### Key Pair Creation

Select "Create key pair", enter a password to protect the private key, choose output folder, and generate RSA-4096 keys.

<br/>

## BUILD the CLI app

After [installing Rust](https://www.rust-lang.org/learn/get-started),
run from the workspace root directory:

```bash
cargo build --release -p fc
```

Or navigate to `ferrocrypt-cli` and run:

```bash
cargo build --release
```

The binary executable file will be generated in `target/release/fc` (macOS and Linux)
or `target\release\fc.exe` (Windows).

<br/>

## USING the CLI app

The CLI auto-detects encryption/decryption mode. Commands shown are for macOS/Linux (use `fc` instead of `./fc` on Windows). Flags can be used in any order.

<br/>

### Symmetric encryption, which utilizes password-based key derivation

- Encrypt file or directory | decrypt file

`./fc --inpath <SRC_PATH> --out <DEST_DIR_PATH> --passphrase <PASSPHRASE>`

or

`./fc -i <SRC_PATH> -o <DEST_DIR_PATH> -p <PASSPHRASE>`

<br/>

### Hybrid encryption

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

## OPTIONS:

| Flag                          | Description                                                                                                                           |
|-------------------------------|---------------------------------------------------------------------------------------------------------------------------------------|
| `-i, --inpath <SRC_PATH>`     | Hybrid and Symmetric: File or directory path that needs to be <br/>encrypted, or the file path that needs to be decrypted [default: ] |
| `-o, --outpath <DEST_DIR>`    | Hybrid and Symmetric: Destination directory path [default: ]                                                                          |                                                                             
| `-k, --key <KEY_PATH>`        | Hybrid: Path to the public key for encryption, <br/>or the path to the private key for decryption [default: ]                         |                                                         
| `-p, --passphrase <PASSWORD>` | Hybrid: Password to decrypt the private key <br/>Symmetric: Password to derive the symmetric key [default: ]                          |
| `-g, --generate`              | Hybrid: Generate a private/public key pair                                                                                            |                                                                                                 
| `-b, --bit-size <BIT_SIZE>`   | Hybrid: Length of the key in bits for <br/>the key pair generation [default: 4096]                                                    |                                                                          
| `-l, --large`                 | Symmetric: For large input file(s) that cannot fit to the available RAM.*                                                             |                                                                       
| `-h, --help`                  | Print help                                                                                                                            |                                                                                                                                   
| `-V, --version`               | Print version                                                                                                                         |                                                                                                                             |

* Use `-l, --large` when encrypting files larger than available RAM or to minimize memory usage. Omitting it provides faster encryption for smaller files. The decryption process automatically uses the same method as encryption.

<br/>

[![forthebadge](https://forthebadge.com/images/badges/made-with-rust.svg)](https://forthebadge.com)
