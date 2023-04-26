# Ferrocrypt

Tiny, easy-to-use, and incredibly secure multiplatform encryption tool with CLI (Command Line Interface)
and GUI (Graphical User Interface)

## ABOUT

Ferrocrypt is a very small and simple encryption tool written in pure Rust.
Its name comes from the Latin words for iron, "ferrum" and for rust, "ferrugo".
With a user-friendly command-line interface, Ferrocrypt makes it easy
to encrypt and decrypt data using industry-standard algorithms.
The tool utilizes Rust's strong memory safety guarantees and performance benefits
to ensure the highest level of security and speed.

Ferrocrypt supports two different encryption modes:

1. Symmetric encryption mode: This mode uses XChaCha20-Poly1305, based on the ChaCha20 stream cipher
   and the Poly1305 MAC, which together provide stronger security guarantees.
   Additionally, Ferrocrypt employs the Argon2id password-based key derivation function
   to generate secure encryption keys from user passwords,
   making it easy for users to protect their data with a strong and unique password.
   The vaults that are produced have the file extension ".fcs".

2. Hybrid encryption mode: This method combines both symmetric and asymmetric encryption algorithms.
   In this mode, the XChaCha20-Poly1305 symmetric algorithm is used to encrypt the data,
   while the RSA asymmetric (public key) algorithm is used to encrypt the symmetric data key,
   providing an added layer of security.
   Unlike the Symmetric mode above, where a password-derived key is used to encrypt all files or folders,
   each file or folder is encrypted with a random key in Hybrid mode. Even if someone guesses your password,
   the random key renders it useless without the private key. Moreover, if someone gains access to your private key,
   they would still need the password to decrypt it.
   Vaults produced by the Hybrid mode have a file extension of ".fch".

The `chacha20poly1305` crate, which implements the ChaCha20Poly1305 encryption algorithms,
has undergone successful security audits.

Ferrocrypt enhances the security of header data, which comprises crucial cryptographic components,
by generating additional Reed-Solomon parity (recovery) bytes. In the event of header corruption,
which may occur due to hard drive bit rot, data transfer or other factors, these parity bytes enable Ferrocrypt
to successfully recover the header and decrypt your data with a high degree of reliability.

The code is separated in three projects - the library `ferrocrypt-lib`, a CLI client `ferrocrypt-cli`
and a [**TAURI**](https://tauri.app/) based GUI app `ferrocrypt-gui`.

## BUILD the CLI app

After [installing Rust](https://www.rust-lang.org/learn/get-started),
just run the following command in the root directory:

```cargo build --release```

The binary executable file will be generated in `target/release/fc` (macOS and Linux)
or `target\release\fc.exe` (Windows).

<br/>

## USING the CLI app

The tool can automatically detect whether the source path requires
encryption or decryption, and which decryption mode should be used.

The commands listed below are compatible with macOS and Linux.
For Windows, simply substitute "./fc" with "fc" in each command.

The flags for each command can be used in any order.

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

### Hybrid encryption

Apart from personal use, this mode is an ideal choice for secure data exchange, allowing files or directories
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

* The decision of whether to include the `-l, --large` flag depends on the total size of the files to be encrypted.
  If the size is smaller than the available RAM, omitting the flag can result in a much faster encryption/decryption
  process.
  On the other hand, if the total size exceeds the available RAM, using the flag can significantly speed up the process.
  It's important to note that the `-l, --large` flag is recommended when minimizing RAM consumption is a priority and
  the encryption/decryption process
  shouldn't affect the user's work. Using this flag significantly reduces RAM usage, providing a smoother user
  experience.
  If the encryption process is carried out with the specified flag, there's no need to specify it when decrypting the
  file(s).
  The decryption process will automatically use the same method that was used for encryption.

<br/>

## BUILD the GUI app

After installing [Rust](https://www.rust-lang.org/learn/get-started),
and [Node.js](https://nodejs.org/) just run the following commands in the `ferrocrypt-gui` directory:

Install the `create-tauri-app` utility:

```cargo install create-tauri-app```

Install the Tauri CLI:

```cargo install tauri-cli```

Install node modules:

```npm install```

Build the app to a binary executable file:

```cargo tauri build```

The binary executable file of the GUI app will be generated in `ferrocrypt-gui/src-tauri/target/release/bundle/`

You can start a live dev session with ```cargo tauri dev```

<br/>

## USING the GUI App

To encrypt or decrypt a file or folder, drag and drop it into the app window. 
Then select either symmetric or hybrid encryption modes.
When decrypting a vault, the app detects the appropriate mode automatically, 
and it's not possible to switch between modes during the decryption process.

### Symmetric Encryption Mode
To encrypt a file or folder using symmetric encryption mode, choose a password and a destination folder, 
then click the "Start" button. If the files you want to encrypt are too large for the available RAM 
or you want to avoid excessive RAM consumption, select the "Large files (low RAM usage)" option 
(see the "OPTIONS" section above for more information). 

The decryption process is the same as the encryption process, 
which is why it's called symmetric.

### Hybrid Encryption Mode
To encrypt a file or folder using hybrid encryption mode, select a public RSA key in PEM format, 
choose the destination folder, and click the "Start" button. 

To decrypt a file or folder using this mode, select your private RSA key in PEM format, 
enter the password to unlock it, choose the destination folder, and click the "Start" button.

### Asymmetric Key Pair Creation Mode
To generate a public/private key pair for Hybrid encryption mode, select "Create key pair". 
Enter your password to encrypt the private key, choose the output folder, and click the "Start" button to generate your RSA-4096 keys.

<br/>

[![forthebadge](https://forthebadge.com/images/badges/made-with-rust.svg)](https://forthebadge.com)
