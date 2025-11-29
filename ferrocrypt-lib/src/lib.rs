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

pub fn generate_asymmetric_key_pair(byte_size: u32, passphrase: &SecretString, output_dir: &str) -> Result<String, CryptoError> {
    let normalized_output_dir = normalize_paths("", output_dir).1;
    hybrid::generate_asymmetric_key_pair(byte_size, passphrase, &normalized_output_dir)
}
