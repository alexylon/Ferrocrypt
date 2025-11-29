use std::path::Path;

use constant_time_eq::constant_time_eq_32;
use sha3::{Digest, Sha3_256};

use crate::CryptoError;

pub fn normalize_paths(src_file_path: &str, dest_dir_path: &str) -> (String, String) {
    let src_file_path_norm = src_file_path.replace('\\', "/");
    let mut dest_dir_path_norm = dest_dir_path.replace('\\', "/");

    if !dest_dir_path_norm.ends_with('/') && !dest_dir_path_norm.is_empty() {
        dest_dir_path_norm = format!("{}/", dest_dir_path_norm);
    }

    (src_file_path_norm, dest_dir_path_norm)
}

pub fn get_file_stem_to_string(filename: impl AsRef<Path>) -> Result<String, CryptoError> {
    let file_stem_string = filename
        .as_ref()
        .file_stem()
        .ok_or_else(|| CryptoError::Message("Cannot get file stem".to_string()))?
        .to_str()
        .ok_or_else(|| CryptoError::Message("Cannot convert file stem to &str".to_string()))?
        .to_string();

    Ok(file_stem_string)
}

pub fn sha3_32_hash(byte_string: &[u8]) -> Result<[u8; 32], CryptoError> {
    let mut hasher = Sha3_256::new();
    hasher.update(byte_string);
    let digest: [u8; 32] = hasher.finalize().as_slice().try_into()?;

    Ok(digest)
}

/// Compares two 256-bit byte strings in constant time.
pub fn constant_time_compare_256_bit(byte_string1: &[u8; 32], byte_string2: &[u8; 32]) -> bool {
    constant_time_eq_32(byte_string1, byte_string2)
}

pub fn get_duration(seconds: f64) -> String {
    if seconds < 60_f64 {
        format!("{:.2} sec", seconds)
    } else {
        format!("{} min, {:.2} sec", seconds as u32 / 60, seconds % 60_f64)
    }
}
