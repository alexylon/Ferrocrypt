use thiserror::Error;

mod archiver;
mod symmetric;
mod hybrid;
mod common;


#[derive(Error, Debug)]
pub enum CryptoError {
    #[error("IO Error!")]
    Io(#[from] std::io::Error),
    #[error("AES encryption/decryption failure!")]
    AesError(#[from] aes_gcm::Error),
    #[error("RSA encryption/decryption failure!")]
    OpensslError(#[from] openssl::error::ErrorStack),
    #[error("WalkDir Error!")]
    WalkDirError(#[from] walkdir::Error),
    #[error("Zip Error!")]
    ZipError(#[from] zip::result::ZipError),
    #[error("")]
    Message(String),
    #[error("Unknown error!")]
    Unknown,
}

pub fn encrypt_file_hybrid(src_file_path: &str, dest_file_path: &str, rsa_public_pem: &str) -> Result<(), CryptoError> {
    hybrid::encrypt_file(src_file_path, dest_file_path, rsa_public_pem)?;

    Ok(())
}

pub fn decrypt_file_hybrid(encrypted_file_path: &str, dest_path: &str, rsa_private_pem: &mut str, passphrase: &mut str) -> Result<(), CryptoError> {
    hybrid::decrypt_file(encrypted_file_path, dest_path, rsa_private_pem, passphrase)?;

    Ok(())
}

pub fn generate_asymmetric_key_pair(byte_size: u32, passphrase: &str, dest_dir_path: &str) -> Result<(), CryptoError> {
    hybrid::generate_asymmetric_key_pair(byte_size, passphrase, dest_dir_path)?;

    Ok(())
}

pub fn encrypt_file_symmetric(source_file_path: &str, dest_file_path: &str, password: &mut str) -> Result<(), anyhow::Error> {
    symmetric::encrypt_file(source_file_path, dest_file_path, password)?;

    Ok(())
}

pub fn decrypt_file_symmetric(source_file_path: &str, dest_file_path: &str, password: &mut str) -> Result<(), anyhow::Error> {
    symmetric::decrypt_file(source_file_path, dest_file_path, password)?;

    Ok(())
}
