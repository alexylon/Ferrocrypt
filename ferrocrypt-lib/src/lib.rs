//! # ferrocrypt
//!
//! High-level helpers for encrypting and decrypting files or directories using
//! password-based symmetric encryption or hybrid (asymmetric + symmetric)
//! encryption. Designed for straightforward, scriptable workflows rather than
//! low-level cryptographic building blocks.
//!
//! ## Design goals
//! - **Confidentiality + integrity** for small-to-medium file trees.
//! - **Simple ergonomics**: pick symmetric (password) or hybrid (public/private
//!   key + optional passphrase) based on your distribution needs.
//! - **Batteries included**: temporary workspace management, path normalization,
//!   and output file naming are handled for you.
//!
//! ## Quick start (symmetric path, mirrors `ferrocrypt symmetric` CLI)
//! ```rust,no_run
//! use ferrocrypt::{symmetric_encryption, CryptoError, secrecy::SecretString};
//!
//! # fn run() -> Result<(), CryptoError> {
//! // Encrypt a folder to out/secrets.fcs
//! let passphrase = SecretString::from("correct horse battery staple".to_string());
//! let produced = symmetric_encryption("./secrets", "./out", &passphrase, false)?;
//! println!("wrote {produced}");
//!
//! // Decrypt the archive back
//! let recovered = symmetric_encryption("./out/secrets.fcs", "./restored", &passphrase, false)?;
//! println!("restored to {recovered}");
//! # Ok(()) }
//! # fn main() { run().unwrap(); }
//! ```
//!
//! ## Quick start (hybrid path, mirrors `ferrocrypt hybrid` CLI)
//! ```rust,no_run
//! use ferrocrypt::{generate_asymmetric_key_pair, hybrid_encryption, CryptoError, secrecy::SecretString};
//!
//! # fn run() -> Result<(), CryptoError> {
//! // 1) Generate RSA keypair files under ./keys
//! //    The passphrase encrypts the private key file itself
//! let passphrase = SecretString::from("my-key-pass".to_string());
//! let _msg = generate_asymmetric_key_pair(4096, &passphrase, "./keys")?;
//!
//! // 2) Encrypt to out/payload.fch using the public key (no passphrase needed)
//! let mut pub_key_path = "./keys/rsa-4096-pub-key.pem".to_string();
//! let empty_passphrase = SecretString::from("".to_string());
//! let produced = hybrid_encryption("./payload", "./out", &mut pub_key_path, &empty_passphrase)?;
//! println!("wrote {produced}");
//!
//! // 3) Decrypt out/payload.fch using the private key + passphrase to unlock it
//! let mut priv_key_path = "./keys/rsa-4096-priv-key.pem".to_string();
//! let restored = hybrid_encryption("./out/payload.fch", "./restored", &mut priv_key_path, &passphrase)?;
//! println!("restored to {restored}");
//! # Ok(()) }
//! # fn main() { run().unwrap(); }
//! ```
//!
//! ## When to choose which mode
//! - **Symmetric**: Fastest; same password encrypts and decrypts. Great for
//!   personal backups or team secrets when you can share the password securely.
//!   Produces `.fcs` files.
//! - **Hybrid**: Safer for distribution—encrypt with a recipient's public key
//!   (no password needed for encryption); only their passphrase-protected
//!   private key can decrypt. Each file gets a unique random key. Produces
//!   `.fch` files.
//!
//! ## Security notes
//! - All cryptographic operations depend on a secure OS RNG; ensure the target
//!   platform provides one.
//! - Ciphertext integrity is enforced; modification or wrong keys will yield
//!   `CryptoError` results rather than corrupted plaintext.
//! - This crate is **not** third-party audited and is not advertised as
//!   compliance-certified.
//!
//! ## Error handling
//! Every fallible operation returns `Result<T, CryptoError>`. See `CryptoError`
//! for variant meanings and remediation hints.
//!
//! ## License
//! Licensed under GPL-3.0-only. See the LICENSE file in the repository.

use std::fs;

use secrecy::SecretString;

use crate::common::normalize_paths;
pub use crate::error::CryptoError;

// Re-export secrecy so library users don't need to add secrecy as a dependency
pub use secrecy;

mod archiver;
mod common;
mod error;
mod hybrid;
mod reed_solomon;
mod symmetric;
mod tests;

/// Encrypt or decrypt files/directories using password-based symmetric crypto.
///
/// - **Encrypt**: if `input_path` is not already an `.fcs` archive, it is
///   packaged and encrypted to `output_dir` (writing `<name>.fcs`).
/// - **Decrypt**: if `input_path` ends with `.fcs`, it is decrypted and
///   extracted into `output_dir`.
/// - `large = true` mirrors the CLI `--large` flag for streaming large inputs.
///
/// Returns the path to the produced file or directory.
pub fn symmetric_encryption(input_path: &str, output_dir: &str, password: &SecretString, large: bool) -> Result<String, CryptoError> {
    let (normalized_input_path, normalized_output_dir) = normalize_paths(input_path, output_dir);

    let tmp_dir_path = &format!("{}.tmp_zip/", normalized_output_dir);
    fs::create_dir_all(tmp_dir_path)?;

    let result = if input_path.ends_with(".fcs") {
        symmetric::decrypt_file(&normalized_input_path, &normalized_output_dir, password, tmp_dir_path)
    } else {
        symmetric::encrypt_file(&normalized_input_path, &normalized_output_dir, password, large, tmp_dir_path)
    };

    fs::remove_dir_all(tmp_dir_path)?;
    result
}

/// Encrypt or decrypt using hybrid (RSA + XChaCha20-Poly1305) envelope encryption.
///
/// - `rsa_key_pem` is a **mutable string containing a file path** (not PEM
///   contents); it is zeroized after decryption for security.
/// - **Encrypt** when `input_path` is not `.fch`: uses the public key file
///   at `rsa_key_pem` to seal a random symmetric key, producing `<name>.fch`.
///   The `passphrase` parameter is **ignored during encryption** (pass empty
///   string).
/// - **Decrypt** when `input_path` ends with `.fch`: uses the private key file
///   at `rsa_key_pem`. The `passphrase` is **required** to decrypt the private
///   key file (must match the passphrase used when generating the keypair).
///
/// Returns a human-readable message describing the output path.
pub fn hybrid_encryption(input_path: &str, output_dir: &str, rsa_key_pem: &mut str, passphrase: &SecretString) -> Result<String, CryptoError> {
    let (normalized_input_path, normalized_output_dir) = normalize_paths(input_path, output_dir);

    let tmp_dir_path = &format!("{}.tmp_zip/", normalized_output_dir);
    fs::create_dir_all(tmp_dir_path)?;

    let result = if input_path.ends_with(".fch") {
        hybrid::decrypt_file(&normalized_input_path, &normalized_output_dir, rsa_key_pem, passphrase, tmp_dir_path)
    } else {
        hybrid::encrypt_file(&normalized_input_path, &normalized_output_dir, rsa_key_pem, tmp_dir_path)
    };

    fs::remove_dir_all(tmp_dir_path)?;
    result
}

/// Generate and store an RSA key pair for hybrid encryption (default: RSA-4096).
///
/// - `byte_size` is the RSA modulus size in **bits** (e.g., 4096),
///   aligned with the CLI flag `--bit-size`.
/// - Keys are written into `output_dir` as `rsa-<bits>-priv-key.pem` and
///   `rsa-<bits>-pub-key.pem`.
/// - The `passphrase` **encrypts the private key file** for protection at rest;
///   the same passphrase is needed later when decrypting. The public key file
///   is unencrypted.
///
/// Returns a human-readable message pointing to the output directory.
pub fn generate_asymmetric_key_pair(byte_size: u32, passphrase: &SecretString, output_dir: &str) -> Result<String, CryptoError> {
    let normalized_output_dir = normalize_paths("", output_dir).1;
    hybrid::generate_asymmetric_key_pair(byte_size, passphrase, &normalized_output_dir)
}
