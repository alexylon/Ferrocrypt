# rusty-crypto
## CLI encrypting / decrypting tool

### ABOUT
**rusty-crypto** is a pure Rust implementation of a client-side encryption tool, 
relying on the combination of using both symmetric and asymmetric algorithms together, 
also known as hybrid encryption.

Both crates, implementing the AES-GCM and RSA encryption ciphers - `aes-gcm` and `rsa` - have received security audits, with no significant findings.
In order to encrypt or decrypt a file or a directory you need only a pair of PEM keys - a public one for encrypting and a private one for decrypting. 
For testing purposes you could use the included `.pem` keys in `/key_examples`.

The code is separated in two projects - `crypto-cli` and `crypto-lib` - the latter can be used independently as a library.


#### When encrypting the tool: 

- Zips the file or directory

- Generates a random symmetric AES-GSM 256-bit key and a random 96-bit nonce - both _unique_ for each file. 

- Encrypts the file with the symmetric key.

- Encrypts the symmetric key with the public RSA key in PEM format and deletes the plain text one from memory.

- Puts the encrypted symmetric key, the nonce and the encrypted file in an envelope .

- Writes the envelope in the current directory. The name of the encrypted path will be `./FILE_NAME.crypto` or `./DIRECTORY_NAME.crypto`.

#### When decrypting the tool:

- Splits the envelope in three: the encrypted symmetric key, the nonce and the encrypted file.

- Decrypts the encrypted symmetric key with the private RSA key in PEM format.

- Decrypts the file with the symmetric key and the nonce.

- Unzips the file or directory

- Writes the decrypted file or directory on the file system in the current directory, removing the `.crypto` extension. 
If a file was encrypted, the decrypted path will be `./FILE_NAME/FILE_NAME.ext`
  <br/><br/>

### USAGE

#### BUILD

`cargo build --release` - the binary file is located in `target\release\crypto.exe` (Windows) 
or `target/release/crypto` (macOS and Linux).

#### Encrypt file:

##### Windows:

`crypto --encrypt <FILE_PATH> --key <PUBLIC_PEM_KEY>`

OR

`crypto -e <FILE_PATH> -k <PUBLIC_PEM_KEY>`

#### Decrypt file:

`crypto --decrypt <FILE_PATH> --key <PRIVATE_PEM_KEY>`

OR

`crypto -d <FILE_PATH> -k <PRIVATE_PEM_KEY>`
<br/><br/>

##### macOS and Linux:

Just replace the command with `./crypto`

### OPTIONS:

`-d, --decrypt <FILE_PATH>`&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;Decrypt file path

`-e, --encrypt <FILE_PATH>`&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;Encrypt file path

`-h, --help`&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;Print help information

`-k, --key <KEY>`&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;Key path (public RSA key for encryption or private RSA key for decryption)

`-V, --version`&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;Print version information

[![forthebadge](https://forthebadge.com/images/badges/made-with-rust.svg)](https://forthebadge.com)
