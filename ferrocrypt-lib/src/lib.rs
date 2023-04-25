use std::fs;
use crate::common::normalize_paths;
use crate::error::CryptoError;

mod archiver;
mod symmetric;
mod hybrid;
mod common;
mod reed_solomon;
mod error;
mod tests;


pub fn symmetric_encryption(input_path: &str, output_dir: &str, password: &mut str, large: bool) -> Result<String, CryptoError> {
    let (normalized_input_path, normalized_output_dir) = normalize_paths(input_path, output_dir);

    let tmp_dir_path = &format!("{}.tmp_zip/", normalized_output_dir);
    fs::create_dir_all(tmp_dir_path)?;

    let result = if input_path.ends_with(".fcv") {
        symmetric::decrypt_file(&normalized_input_path, &normalized_output_dir, password, tmp_dir_path)
    } else {
        symmetric::encrypt_file(&normalized_input_path, &normalized_output_dir, password, large, tmp_dir_path)
    };

    if let Err(err) = result {
        fs::remove_dir_all(tmp_dir_path)?;
        return Err(err);
    }

    fs::remove_dir_all(tmp_dir_path)?;

    result
}

pub fn hybrid_encryption(input_path: &str, output_dir: &str, rsa_key_pem: &mut str, passphrase: &mut str) -> Result<String, CryptoError> {
    let (normalized_input_path, normalized_output_dir) = normalize_paths(input_path, output_dir);

    let tmp_dir_path = &format!("{}.tmp_zip/", normalized_output_dir);
    fs::create_dir_all(tmp_dir_path)?;

    let result = if input_path.ends_with(".fch") {
        hybrid::decrypt_file(&normalized_input_path, &normalized_output_dir, rsa_key_pem, passphrase, tmp_dir_path)
    } else {
        hybrid::encrypt_file(&normalized_input_path, &normalized_output_dir, rsa_key_pem, tmp_dir_path)
    };

    if let Err(err) = result {
        fs::remove_dir_all(tmp_dir_path)?;
        return Err(err);
    }

    fs::remove_dir_all(tmp_dir_path)?;

    result
}

pub fn generate_asymmetric_key_pair(byte_size: u32, passphrase: &str, output_dir: &str) -> Result<String, CryptoError> {
    let normalized_output_dir = normalize_paths("", output_dir).1;

    let result = hybrid::generate_asymmetric_key_pair(byte_size, passphrase, &normalized_output_dir)?;

    Ok(result)
}
