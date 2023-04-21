use thiserror::Error;

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

pub fn hybrid_encryption(input_path: &str, output_dir: &str, rsa_key_pem: &mut str, passphrase: &mut str) -> Result<(), CryptoError> {
    if input_path.ends_with(".fch") {
        hybrid::decrypt_file(input_path, output_dir, rsa_key_pem, passphrase)?;
    } else {
        hybrid::encrypt_file(input_path, output_dir, rsa_key_pem)?;
    }

    Ok(())
}

pub fn generate_asymmetric_key_pair(byte_size: u32, passphrase: &str, dest_dir_path: &str) -> Result<(), CryptoError> {
    hybrid::generate_asymmetric_key_pair(byte_size, passphrase, dest_dir_path)?;

    Ok(())
}

pub fn symmetric_encryption(input_path: &str, output_dir: &str, password: &mut str, large: bool) -> Result<String, CryptoError> {
    let result = if input_path.ends_with(".fcv") {
        symmetric::decrypt_file(input_path, output_dir, password)?
    } else {
        symmetric::encrypt_file(input_path, output_dir, password, large)?
    };

    Ok(result)
}
