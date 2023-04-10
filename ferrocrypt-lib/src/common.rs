use std::path::Path;
use sha3::{Digest, Sha3_256};
use constant_time_eq::constant_time_eq_32;
use crate::CryptoError;
use crate::CryptoError::Message;

pub fn normalize_paths(src_file_path: &str, dest_dir_path: &str) -> (String, String) {
    let src_file_path_norm = src_file_path.replace('\\', "/");
    let mut dest_dir_path_norm = dest_dir_path.replace('\\', "/");

    if !dest_dir_path.ends_with('/') && !dest_dir_path.is_empty() {
        dest_dir_path_norm = format!("{}/", dest_dir_path);
    };


    (src_file_path_norm, dest_dir_path_norm)
}

pub fn get_file_stem_to_string(filename: &str) -> Result<String, CryptoError> {
    let file_stem_string = Path::new(filename)
        .file_stem().ok_or(Message("Cannot get file stem".to_string()))?
        .to_str().ok_or(Message("Cannot convert file stem to &str".to_string()))?.to_string();

    Ok(file_stem_string)
}

pub fn sha3_hash(byte_string: &[u8]) -> Result<[u8; 32], CryptoError> {
    let mut hasher = Sha3_256::new();
    hasher.update(byte_string);
    let byte_string_hash: [u8; 32] = hasher.finalize().as_slice().try_into()?;

    Ok(byte_string_hash)
}

// Compares two 256-bit byte strings in constant time
pub fn constant_time_compare_256_bit(byte_string1: &[u8; 32], byte_string2: &[u8; 32]) -> bool {
    constant_time_eq_32(byte_string1, byte_string2)
}
