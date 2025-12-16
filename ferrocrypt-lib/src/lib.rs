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
//! ## Quick start (symmetric path)
//! ```rust,no_run
//! use ferrocrypt_lib::{symmetric_encryption, CryptoError, secrecy::SecretString};
//!
//! # fn run() -> Result<(), CryptoError> {
//! let password = SecretString::new("correct horse battery staple".into());
//! let output_dir = "./out";
//! let produced = symmetric_encryption("./secrets", output_dir, &password, false)?;
//! println!("wrote {produced}");
//! # Ok(()) }
//! # fn main() { run().unwrap(); }
//! ```
//!
//! ## Quick start (hybrid path)
//! ```rust,no_run
//! use ferrocrypt_lib::{generate_asymmetric_key_pair, hybrid_encryption, CryptoError, secrecy::SecretString};
//!
//! # fn run() -> Result<(), CryptoError> {
//! let passphrase = SecretString::new("my-key-pass".into());
//! let (key_path_msg) = generate_asymmetric_key_pair(2048, &passphrase, "./keys")?;
//! println!("{key_path_msg}");
//!
//! let produced = hybrid_encryption("./payload", "./out", &mut std::fs::read_to_string("./keys/public.pem")?, &passphrase)?;
//! println!("wrote {produced}");
//! # Ok(()) }
//! # fn main() { run().unwrap(); }
//! ```
//!
//! ## When to choose which mode
//! - **Symmetric**: fastest; share one password out-of-band; great for personal
//!   backups or team secrets kept in a vault.
//! - **Hybrid**: safer for distribution—encrypt with a recipient’s public key so
//!   only their private key (optionally passphrase-protected) can decrypt.
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
//! Dual-licensed under MIT and Apache-2.0; see LICENSE files in the repository.

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
///   packaged and encrypted to `output_dir`.
/// - **Decrypt**: if `input_path` ends with `.fcs`, it is decrypted and
///   extracted into `output_dir`.
/// - `large = true` uses a memory-friendlier path for big inputs.
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

/// Encrypt or decrypt using hybrid envelope encryption with RSA keys.
///
/// - **Encrypt** when `input_path` is not an `.fch` archive: wraps data with
///   a random symmetric key sealed to `rsa_key_pem` (public key PEM).
/// - **Decrypt** when `input_path` ends with `.fch`: unwraps using the
///   corresponding private key PEM, optionally protected by `passphrase`.
///
/// Returns the path to the produced file or directory.
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

/// Generate and store an RSA key pair for hybrid encryption.
///
/// - `byte_size` controls key strength (e.g., 2048 or 4096).
/// - Keys are written into `output_dir` (public/private PEM files).
/// - The private key is encrypted with `passphrase`.
///
/// Returns a message describing where the keys were written.
pub fn generate_asymmetric_key_pair(byte_size: u32, passphrase: &SecretString, output_dir: &str) -> Result<String, CryptoError> {
    let normalized_output_dir = normalize_paths("", output_dir).1;
    hybrid::generate_asymmetric_key_pair(byte_size, passphrase, &normalized_output_dir)
}
