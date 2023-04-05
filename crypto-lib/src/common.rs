use std::fs;
use std::fs::File;
use std::io::Read;
use std::path::Path;
use crate::CryptoError;
use crate::CryptoError::Message;

pub fn normalize_paths(src_file_path: &str, dest_dir_path: &str) -> (String, String) {
    let src_file_path_norm = src_file_path.replace('\\', "/");
    let mut dest_dir_path_norm = dest_dir_path.replace('\\', "/");

    if !dest_dir_path.ends_with('/') && !dest_dir_path.is_empty() {
        dest_dir_path_norm = format!("{dest_dir_path}/");
    }


    (src_file_path_norm, dest_dir_path_norm)
}

pub fn get_file_as_byte_vec(filename: &str) -> std::io::Result<Vec<u8>> {
    let mut file = File::open(filename)?;
    let metadata = fs::metadata(filename)?;
    let mut buffer = vec![0; metadata.len() as usize];
    file.read_exact(&mut buffer)?;

    Ok(buffer)
}

pub fn get_file_stem_to_string(filename: &str) -> Result<String, CryptoError> {
    let file_stem_str = Path::new(filename)
        .file_stem().ok_or(Message("Cannot get file stem".to_string()))?
        .to_str().ok_or(Message("Cannot convert file stem to &str".to_string()))?.to_string();

    Ok(file_stem_str)
}
