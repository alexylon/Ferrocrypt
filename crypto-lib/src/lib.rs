use crate::hybrid::CryptoError;

mod archiver;
mod symmetric;
mod hybrid;

pub fn encrypt_file_hybrid(file_path: &str, rsa_public_pem: &str) -> Result<(), CryptoError> {
    hybrid::encrypt_file(file_path, rsa_public_pem)?;

    Ok(())
}

pub fn decrypt_file_hybrid(encrypted_file_path: &str, rsa_private_pem: &str, passphrase: &str) -> Result<(), CryptoError> {
    hybrid::decrypt_file(encrypted_file_path, rsa_private_pem, passphrase)?;

    Ok(())
}

pub fn generate_asymmetric_key_pair(byte_size: u32, passphrase: &str) -> Result<(), CryptoError> {
    hybrid::generate_asymmetric_key_pair(byte_size, passphrase)?;

    Ok(())
}

pub fn encrypt_file_symmetric(source_file_path: &str, dest_file_path: &str, password: &str) -> Result<(), anyhow::Error> {
    symmetric::encrypt_file(source_file_path, dest_file_path, password)?;

    Ok(())
}

pub fn decrypt_file_symmetric(source_file_path: &str, dest_file_path: &str, password: &str) -> Result<(), anyhow::Error> {
    symmetric::decrypt_file(source_file_path, dest_file_path, password)?;

    Ok(())
}
