use thiserror::Error;

mod archiver;
mod symmetric;
mod hybrid;
mod common;
mod reed_solomon;

#[derive(Error, Debug)]
pub enum CryptoError {
    #[error("IO Error!")]
    Io(#[from] std::io::Error),
    #[error("ChaCha20Poly1305 encryption/decryption failure!")]
    ChaCha20Poly1305Error(#[from] chacha20poly1305::Error),
    #[error("Argon2 Error!")]
    Argon2Error(#[from] argon2::Error),
    #[error("RSA encryption/decryption failure!")]
    OpensslError(#[from] openssl::error::ErrorStack),
    #[error("WalkDir Error!")]
    WalkDirError(#[from] walkdir::Error),
    #[error("Zip Error!")]
    ZipError(#[from] zip::result::ZipError),
    #[error("ReedSolomon Error!")]
    ReedSolomonError(#[from] reed_solomon_erasure::Error),
    #[error("BinCode Error!")]
    BinCodeError(#[from] Box<bincode::ErrorKind>),
    #[error("TryFromSlice Error!")]
    TryFromSliceError(#[from] std::array::TryFromSliceError),
    #[error("")]
    Message(String),
    #[error("Unknown error!")]
    Unknown,
}

// We must manually implement serde::Serialize
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

pub fn symmetric_encryption(input_path: &str, output_dir: &str, password: &mut str, large: bool) -> Result<(), CryptoError> {
    if input_path.ends_with(".fcs") || input_path.ends_with(".fcls") {
        symmetric::decrypt_file(input_path, output_dir, password)?;
    } else {
        symmetric::encrypt_file(input_path, output_dir, password, large)?;
    }

    Ok(())
}
