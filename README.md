# Ferrocrypt

![](https://github.com/alexylon/Ferrocrypt/actions/workflows/rust.yml/badge.svg)
&nbsp; 
[![crate: ferrocrypt](https://img.shields.io/crates/v/ferrocrypt.svg?label=crate%3A%20ferrocrypt&color=blue)](https://crates.io/crates/ferrocrypt)
&nbsp;
[![crate: ferrocrypt-cli](https://img.shields.io/crates/v/ferrocrypt-cli.svg?label=crate%3A%20ferrocrypt-cli&color=blue)](https://crates.io/crates/ferrocrypt-cli)

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

The CLI supports two usage modes:

1. **Direct subcommands** (recommended for scripts and automation)
2. **Interactive command mode** (REPL), entered when you run `./fc` with no arguments

Commands shown are for macOS/Linux (use `fc` instead of `./fc` on Windows).  
Flags can be used in any order.

Available subcommands:

- `keygen`    – Generate a hybrid (asymmetric) key pair
- `hybrid`    – Hybrid encryption/decryption using public/private keys
- `symmetric` – Symmetric encryption/decryption using a passphrase

---

## 1. Direct subcommand usage

### Symmetric encryption (password-based key derivation)

- Encrypt file or directory | decrypt file

`./fc symmetric --inpath <SRC_PATH> --outpath <DEST_DIR_PATH> --passphrase <PASSPHRASE>`

or

`./fc symmetric -i <SRC_PATH> -o <DEST_DIR_PATH> -p <PASSPHRASE>`

<br/>

### Hybrid encryption

#### Generate a private/public key pair and set a passphrase for encrypting the private key

`./fc keygen --bit-size <BIT_SIZE> --passphrase <PASSPHRASE> --outpath <DEST_DIR_PATH>`

or

`./fc keygen -b <BIT_SIZE> -p <PASSPHRASE> -o <DEST_DIR_PATH>`

If `--bit-size` is omitted, the default is `4096`.

#### Encrypt file or directory (using a public key)

`./fc hybrid --inpath <SRC_PATH> --outpath <DEST_DIR_PATH> --key <PUBLIC_PEM_KEY>`

or

`./fc hybrid -i <SRC_PATH> -o <DEST_DIR_PATH> -k <PUBLIC_PEM_KEY>`

#### Decrypt file (using a private key)

`./fc hybrid --inpath <SRC_FILE_PATH> --outpath <DEST_DIR_PATH> --key <PRIVATE_PEM_KEY> --passphrase <PASSPHRASE>`

or

`./fc hybrid -i <SRC_FILE_PATH> -o <DEST_DIR_PATH> -k <PRIVATE_PEM_KEY> -p <PASSPHRASE>`

---

## 2. Interactive command mode (REPL)

Running `./fc` **without any arguments** starts an interactive shell:

```text
$ ./fc
Ferrocrypt interactive mode
Type `keygen`, `hybrid`, or `symmetric` with flags, or `quit` to exit.

fc> keygen -o keys -p "my secret"
fc> hybrid -i secret.txt -o out -k public.pem
fc> symmetric -i secret.txt -o out -p "my secret"
fc> quit
```

This mode is convenient for exploratory or repeated use.  
Under the hood, it uses the same subcommands and flags as the direct CLI.

---

## SUBCOMMANDS AND OPTIONS

### Global options

```markdown
| Flag             | Description    |
|------------------|----------------|
| `-h, --help`     | Print help     |
| `-V, --version`  | Print version  |
```

<br/>

### `symmetric` subcommand

```markdown
| Flag                             | Description                                                                                                  |
|----------------------------------|--------------------------------------------------------------------------------------------------------------|
| `-i, --inpath <SRC_PATH>`        | File or directory path that needs to be encrypted, or the file path that needs to be decrypted              |
| `-o, --outpath <DEST_DIR>`       | Destination directory path                                                                                   |
| `-p, --passphrase <PASSWORD>`    | Password to derive the symmetric key for encryption and decryption                                          |
| `-l, --large`                    | For large input file(s) that cannot fit into the available RAM.*                                            |
```

\* Use `-l, --large` when encrypting files larger than available RAM or to minimize memory usage. Omitting it provides faster encryption for smaller files. The decryption process automatically uses the same method as encryption.

<br/>

### `hybrid` subcommand

```markdown
| Flag                             | Description                                                                                                  |
|----------------------------------|--------------------------------------------------------------------------------------------------------------|
| `-i, --inpath <SRC_PATH>`        | File or directory path that needs to be encrypted, or the file path that needs to be decrypted              |
| `-o, --outpath <DEST_DIR>`       | Destination directory path                                                                                   |
| `-k, --key <KEY_PATH>`           | Path to the public key for encryption, or the path to the private key for decryption                        |
| `-p, --passphrase <PASSWORD>`    | Password to decrypt the private key (only required when using a private key)                                |
```

<br/>

### `keygen` subcommand

```markdown
| Flag                             | Description                                                                                                  |
|----------------------------------|--------------------------------------------------------------------------------------------------------------|
| `-o, --outpath <DEST_DIR>`       | Destination directory path where the generated key pair will be written                                     |
| `-p, --passphrase <PASSWORD>`    | Passphrase to encrypt the generated private key                                                              |
| `-b, --bit-size <BIT_SIZE>`      | Length of the key in bits for the key pair generation (default: `4096`)                                     |
```

<br/>


[![forthebadge](https://forthebadge.com/images/badges/made-with-rust.svg)](https://forthebadge.com)
