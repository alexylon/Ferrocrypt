use std::fs;
use thiserror::Error;
use crate::common::normalize_paths;

mod archiver;
mod symmetric;
mod hybrid;
mod common;
mod reed_solomon;

#[derive(Error, Debug)]
pub enum CryptoError {
    #[error(transparent)]
    Io(#[from] std::io::Error),
    #[error(transparent)]
    ChaCha20Poly1305Error(#[from] chacha20poly1305::Error),
    #[error(transparent)]
    Argon2Error(#[from] argon2::Error),
    #[error(transparent)]
    OpensslError(#[from] openssl::error::ErrorStack),
    #[error(transparent)]
    WalkDirError(#[from] walkdir::Error),
    #[error(transparent)]
    ZipError(#[from] zip::result::ZipError),
    #[error(transparent)]
    ReedSolomonError(#[from] reed_solomon_erasure::Error),
    #[error(transparent)]
    BinCodeError(#[from] Box<bincode::ErrorKind>),
    #[error(transparent)]
    TryFromSliceError(#[from] std::array::TryFromSliceError),
    #[error("The provided password is incorrect")]
    Decryption(String),
    #[error("Input file or folder missing")]
    InputPath(String),
    #[error("Message Error")]
    Message(String),
    #[error("Unknown error!")]
    Unknown,
}

// We must manually implement serde::Serialize for `tauri`
impl serde::Serialize for CryptoError {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
        where
            S: serde::ser::Serializer,
    {
        serializer.serialize_str(self.to_string().as_ref())
    }
}

#[cfg(test)]
mod tests {
    use std::fs;
    use crate::{CryptoError, symmetric_encryption};
    // use zeroize::Zeroize;

    const SRC_FILE_PATH: &str = "src/test_files/test-file.txt";
    const ENCRYPTED_FILE_PATH: &str = "src/dest/test-file.fcv";
    const ENCRYPTED_LARGE_FILE_PATH: &str = "src/dest_large/test-file.fcv";
    const DEST_DIR_PATH: &str = "src/dest/";
    const DEST_DIR_PATH_LARGE: &str = "src/dest_large/";
    const SRC_DIR_PATH: &str = "src/test_files/test-folder";
    const ENCRYPTED_DIR_PATH: &str = "src/dest/test-folder.fcv";
    const PASSPHRASE: &str = "strong_passphrase";

    #[test]
    fn encrypt_file_test() -> Result<(), CryptoError> {
        fs::create_dir_all(DEST_DIR_PATH)?;
        // let mut passphrase = rpassword::prompt_password("passphrase:")?;
        let mut passphrase = PASSPHRASE.to_string();
        symmetric_encryption(SRC_FILE_PATH, DEST_DIR_PATH, &mut passphrase, false)?;

        // passphrase.zeroize();

        Ok(())
    }

    #[test]
    fn decrypt_file_test() -> Result<(), CryptoError> {
        // let mut password = rpassword::prompt_password("password:")?;
        let mut passphrase = PASSPHRASE.to_string();
        symmetric_encryption(ENCRYPTED_FILE_PATH, DEST_DIR_PATH, &mut passphrase, false)?;

        // password.zeroize();

        Ok(())
    }

    #[test]
    fn encrypt_large_file_test() -> Result<(), CryptoError> {
        fs::create_dir_all(DEST_DIR_PATH_LARGE)?;
        // let mut passphrase = rpassword::prompt_password("passphrase:")?;
        let mut passphrase = PASSPHRASE.to_string();
        symmetric_encryption(SRC_FILE_PATH, DEST_DIR_PATH_LARGE, &mut passphrase, true)?;

        // passphrase.zeroize();

        Ok(())
    }

    #[test]
    fn decrypt_large_file_test() -> Result<(), CryptoError> {
        // let mut password = rpassword::prompt_password("password:")?;
        let mut passphrase = "strong_passphrase".to_string();
        symmetric_encryption(ENCRYPTED_LARGE_FILE_PATH, DEST_DIR_PATH_LARGE, &mut passphrase, true)?;

        // password.zeroize();

        Ok(())
    }

    #[test]
    fn encrypt_dir_test() -> Result<(), CryptoError> {
        fs::create_dir_all("src/dest")?;
        // let mut passphrase = rpassword::prompt_password("passphrase:")?;
        let mut passphrase = PASSPHRASE.to_string();
        symmetric_encryption(SRC_DIR_PATH, DEST_DIR_PATH, &mut passphrase, false)?;

        // passphrase.zeroize();

        Ok(())
    }

    #[test]
    fn decrypt_dir_test() -> Result<(), CryptoError> {
        // let mut password = rpassword::prompt_password("password:")?;
        let mut passphrase = PASSPHRASE.to_string();
        symmetric_encryption(ENCRYPTED_DIR_PATH, DEST_DIR_PATH, &mut passphrase, false)?;

        // password.zeroize();

        Ok(())
    }
}

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

pub fn hybrid_encryption(input_path: &str, output_dir: &str, rsa_key_pem: &mut str, passphrase: &mut str) -> Result<(), CryptoError> {
    let (normalized_input_path, normalized_output_dir) = normalize_paths(input_path, output_dir);
    if input_path.ends_with(".fch") {
        hybrid::decrypt_file(&normalized_input_path, &normalized_output_dir, rsa_key_pem, passphrase)?;
    } else {
        hybrid::encrypt_file(&normalized_input_path, &normalized_output_dir, rsa_key_pem)?;
    }

    Ok(())
}

pub fn generate_asymmetric_key_pair(byte_size: u32, passphrase: &str, output_dir: &str) -> Result<(), CryptoError> {
    let normalized_output_dir = normalize_paths("", output_dir).1;
    hybrid::generate_asymmetric_key_pair(byte_size, passphrase, &normalized_output_dir)?;

    Ok(())
}
