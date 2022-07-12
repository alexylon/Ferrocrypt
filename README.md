# rusty-crypto
## CLI encrypting / decrypting tool

### ABOUT
**rusty-crypto** is a pure Rust implementation of a client-side encryption tool, 
relying on the combination of using both symmetric and asymmetric algorithms together, 
also known as hybrid encryption.

Both crates, implementing the AES-GCM and RSA encryption ciphers - `aes-gcm` and `rsa` - have received security audits, with no significant findings.
In order to encrypt or decrypt a file you need only a pair of PEM keys - a public one for encrypting and a private one for decrypting. 
For testing purposes you could use the included `.pem` keys in `/key_examples`.


#### When encrypting the tool: 

- Generates a random symmetric AES-GSM 256-bit key and a random 96-bit nonce - both _unique_ for each file. 

- Encrypts the file with the symmetric key.

- Encrypts the symmetric key with the public RSA key in PEM format and deletes the plain text one from memory.

- Puts the encrypted symmetric key, the nonce and the encrypted file in an envelope .

- Writes the envelope on the file system. The name of the encrypted file will be the original file name + `_encrypted`.

#### When decrypting the tool:

- Splits the envelope in three: the encrypted symmetric key, the nonce and the encrypted file.

- Decrypts the encrypted symmetric key with the private RSA key in PEM format.

- Decrypts the file with the symmetric key and the nonce.

- Writes the decrypted file on the file system.
  <br/><br/>

### USAGE

#### Encrypt file:

`rusty_crypto --encrypt --infile <INPUT_FILE_PATH> --key <PUBLIC_PEM_KEY>`

OR

`rusty_crypto -e -i <INPUT_FILE_PATH> -k <PUBLIC_PEM_KEY>`

#### Decrypt file:

`rusty_crypto --decrypt --infile <INPUT_FILE_PATH> --outfile <OUTPUT_FILE_PATH> --key <PRIVATE_PEM_KEY>`

OR

`rusty_crypto -d -i <INPUT_FILE_PATH> -o <OUTPUT_FILE_PATH> -k <PRIVATE_PEM_KEY>`
<br/><br/>

### OPTIONS:

`-d, --decrypt`&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;Decrypt

`-e, --encrypt`&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;Encrypt

`-h, --help`&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;Print help information

`-i, --infile <INPUT_FILE_PATH>`&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;Input file path (used for encryption or decryption)

`-k, --key <KEY>`&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;Path to the key (public RSA key for encryption or private RSA key for decryption)

`-o, --outfile <OUTPUT_FILE_PATH>`&nbsp;&nbsp;Output file path (used for decryption only)

`-V, --version`&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;Print version information

