extern crate hex;
extern crate openssl;
extern crate rsa;

use std::{fs, str};
use std::fs::{File, OpenOptions};
use std::io::{Read, Write};

use aes_gcm::{Aes256Gcm, AesGcm, Key, Nonce};
// Or `Aes128Gcm`
use aes_gcm::aead::{Aead, NewAead};
use aes_gcm::aead::generic_array::{GenericArray, typenum};
use aes_gcm::aes::Aes256;
use openssl::pkey::Private;
use openssl::rsa::{Padding, Rsa};
use openssl::symm::Cipher;
use rand::distributions::Alphanumeric;
use rand::prelude::*;
// use rsa::{PaddingScheme,
//           pkcs1::{DecodeRsaPrivateKey, DecodeRsaPublicKey}, PublicKey, RsaPrivateKey, RsaPublicKey};
use substring::Substring;
use thiserror::Error;

#[cfg(test)]
mod tests {
    use std::fs;

    use aes_gcm::aead::generic_array::{GenericArray, typenum};
    use aes_gcm::Key;

    use crate::{decrypt_file, decrypt_key, encrypt_file, encrypt_key, random_bytes};

    const FILE_PATH: &str = "src/test_files/test1.txt";
    // RSA-4096 PKCS#1 public key encoded as PEM
    const RSA_PUB_PEM: &str = "src/key_examples/rsa-4096-pub-key.pem";
    // RSA-4096 PKCS#1 private key encoded as PEM
    const RSA_PRIV_PEM: &str = "src/key_examples/rsa-4096-priv-key.pem";
    const PASSPHRASE: &str = "strong_passphrase";

    const FILE_PATH_ENCRYPTED: &str = "src/test_files/encrypted/test1.txt.crypto";
    const FILE_PATH_DECRYPTED: &str = "src/test_files/encrypted/decrypted/test1.txt";

    #[test]
    fn encrypt_decrypt_file_test() {
        let pub_key = fs::read_to_string(RSA_PUB_PEM).unwrap();
        encrypt_file(FILE_PATH, &pub_key).unwrap();

        let priv_key = fs::read_to_string(RSA_PRIV_PEM).unwrap();
        decrypt_file(FILE_PATH_ENCRYPTED, &priv_key, PASSPHRASE).unwrap();

        let file_original = fs::read_to_string(FILE_PATH).unwrap();
        let file_decrypted = fs::read_to_string(FILE_PATH_DECRYPTED).unwrap();

        assert_eq!(file_original, file_decrypted);

        fs::remove_file(FILE_PATH_ENCRYPTED).unwrap();
        fs::remove_file(FILE_PATH_DECRYPTED).unwrap();
    }

    #[test]
    fn encrypt_decrypt_key_test() {
        let pub_key = fs::read_to_string(RSA_PUB_PEM).unwrap();
        let priv_key = fs::read_to_string(RSA_PRIV_PEM).unwrap();
        let rand_bytes_32 = random_bytes(32);
        let symmetric_key: &GenericArray<u8, typenum::U32> = Key::from_slice(&rand_bytes_32);
        let encrypted_symmetric_key = encrypt_key(symmetric_key.to_vec(), &pub_key).unwrap();
        let decrypted_symmetric_key = decrypt_key(&encrypted_symmetric_key, &priv_key, PASSPHRASE).unwrap();

        assert_eq!(symmetric_key.to_vec(), decrypted_symmetric_key);
    }

    #[test]
    fn random_bytes_test() {
        let rand_bytes_32 = random_bytes(32);
        let rand_bytes_12 = random_bytes(12);

        assert_eq!(rand_bytes_32.len(), 32);
        assert_eq!(rand_bytes_12.len(), 12);
    }
}

#[derive(Error, Debug)]
pub enum CryptoError {
    #[error("IO Error!")]
    Io(#[from] std::io::Error),
    #[error("AES encryption/decryption failure!")]
    AesError(#[source] aes_gcm::Error),
    #[error("Cannot get RSA key!")]
    Pkcs1Error(#[source] rsa::pkcs1::Error),
    #[error("RSA encryption/decryption failure!")]
    RsaError(#[source] rsa::errors::Error),
    #[error("RSA encryption/decryption failure!")]
    OpensslError(#[source] openssl::error::ErrorStack),
    #[error("")]
    Message(String),
    #[error("Unknown error!")]
    Unknown,
}

// Encrypt file with AES-GCM algorithm
pub fn encrypt_file(file_path: &str, rsa_public_pem: &str) -> Result<(), CryptoError> {
    if let Some(dir_path_index) = file_path.rfind('/') {
        let dir_path = file_path.substring(0, dir_path_index);
        let file_name = file_path.substring(dir_path_index + 1, file_path.len());

        fs::create_dir_all(format!("{}/encrypted", dir_path))?;
        // The byte string for generating the symmetric key should be 256-bit (32-bytes)
        let rand_bytes_32 = random_bytes(32);
        // The byte string for the nonce should be 96-bit (12-bytes)
        let rand_bytes_12 = random_bytes(12);

        // Generate the symmetric AES-GCM 256-bit data key for data encryption/decryption (data key), unique per file
        let symmetric_key: &GenericArray<u8, typenum::U32> = Key::from_slice(&rand_bytes_32);
        // Create the AES-GCM cipher with a 256-bit key and 96-bit nonce
        let cipher: AesGcm<Aes256, typenum::U12> = Aes256Gcm::new(symmetric_key);
        // Create the 96-bit nonce, unique per file
        let nonce: &GenericArray<u8, typenum::U12> = Nonce::from_slice(&rand_bytes_12);
        let file_original = get_file_as_byte_vec(file_path)?;
        let ciphertext = cipher.encrypt(nonce, &*file_original).map_err(CryptoError::AesError)?;
        // Encrypt the data key
        let encrypted_symmetric_key: Vec<u8> = encrypt_key(symmetric_key.to_vec(), rsa_public_pem)?;
        let mut file_path_encrypted = OpenOptions::new()
            .write(true)
            .append(true)
            .create_new(true)
            .open(format!("{}/encrypted/{}.crypto", dir_path, file_name))?;

        // The output contains the encrypted data key, the nonce and the encrypted file
        file_path_encrypted.write_all(&encrypted_symmetric_key)?;
        file_path_encrypted.write_all(&nonce)?;
        file_path_encrypted.write_all(&ciphertext)?;
    } else {
        return Err(format!("No directory specified!")).map_err(CryptoError::Message);
    }

    Ok(())
}

// Decrypt file with AES-GCM algorithm
pub fn decrypt_file(encrypted_file_path: &str, rsa_private_pem: &str, passphrase: &str) -> Result<(), CryptoError> {
    if let Some(dir_path_index) = encrypted_file_path.rfind('/') {
        let dir_path = encrypted_file_path.substring(0, dir_path_index);
        let crypto_ext = encrypted_file_path.substring(encrypted_file_path.len() - 7, encrypted_file_path.len());
        if crypto_ext == ".crypto" {
            fs::create_dir_all(format!("{}/decrypted", dir_path))?;
            let file_name_decrypted = encrypted_file_path.substring(dir_path_index + 1, encrypted_file_path.len() - 7);
            let decrypted_file_path = format!("{}/decrypted/{}", dir_path, file_name_decrypted);
            let data = get_file_as_byte_vec(encrypted_file_path)?;
            // Split the nonce and the encrypted file
            let (encrypted_symmetric_key, data_file) = data.split_at(512);
            let (nonce_vec, ciphertext) = data_file.split_at(12);
            let nonce = Nonce::from_slice(nonce_vec);

            // Decrypt the data key
            let decrypted_symmetric_key = decrypt_key(encrypted_symmetric_key, rsa_private_pem, passphrase)?;
            // Convert the vector into array
            // let symmetric_key_array: [u8; 32] = decrypted_symmetric_key.try_into()
            //     .unwrap_or_else(|v: Vec<u8>| panic!("Expected a Vec of length {} but it was {}", 32, v.len()));
            let symmetric_key_slice = decrypted_symmetric_key.as_slice();
            let symmetric_key_array: [u8; 32] = match symmetric_key_slice.try_into() {
                Ok(ba) => ba,
                Err(e) => panic!("Expected a Vec of length {} but it was {}: {}", 32, decrypted_symmetric_key.len(), e),
            };
            let symmetric_key: &GenericArray<u8, typenum::U32> = &GenericArray::from(symmetric_key_array);
            let cipher: AesGcm<Aes256, typenum::U12> = Aes256Gcm::new(symmetric_key);
            let file_decrypted = cipher.decrypt(nonce, ciphertext.as_ref()).map_err(CryptoError::AesError)?;
            // let my_str = str::from_utf8(&plaintext).unwrap();
            File::create(&decrypted_file_path)?;
            fs::write(&decrypted_file_path, file_decrypted)?;
        } else {
            return Err(format!("This file has no '.crypto' extension!")).map_err(CryptoError::Message);
        }
    } else {
        return Err(format!("No directory specified!")).map_err(CryptoError::Message);
    }

    Ok(())
}

fn random_bytes(n_bytes: usize) -> Vec<u8> {
    let rand_bytes = thread_rng()
        .sample_iter(&Alphanumeric)
        .take(n_bytes)
        .map(char::from)
        .collect::<String>().as_bytes().to_vec();

    rand_bytes
}

fn get_file_as_byte_vec(filename: &str) -> std::io::Result<Vec<u8>> {
    let mut file = File::open(&filename)?;
    let metadata = fs::metadata(&filename)?;
    let mut buffer = vec![0; metadata.len() as usize];
    file.read(&mut buffer)?;

    Ok(buffer)
}

// // Encrypt the data key with RSA algorithm
// fn encrypt_key_bk(symmetric_key: Vec<u8>, rsa_public_pem: &str) -> Result<Vec<u8>, CryptoError> {
//     let mut rng = thread_rng();
//     // let public_key = RsaPublicKey::from_pkcs1_der(RSA_4096_PUB_DER).unwrap();
//     let public_key = RsaPublicKey::from_pkcs1_pem(rsa_public_pem).map_err(CryptoError::Pkcs1Error)?;
//
//     Ok(public_key.encrypt(&mut rng, PaddingScheme::new_pkcs1v15_encrypt(), &symmetric_key[..]).map_err(CryptoError::RsaError)?)
// }
//
// // Decrypt the data key with RSA algorithm
// fn decrypt_key_bk(symmetric_key: &[u8], rsa_private_pem: &str) -> Result<Vec<u8>, CryptoError> {
//     let private_key = RsaPrivateKey::from_pkcs1_pem(rsa_private_pem).map_err(CryptoError::Pkcs1Error)?;
//     // let priv_key = RsaPrivateKey::from_pkcs1_der(RSA_4096_PRIV_DER).unwrap();
//     let decrypted_data = private_key.decrypt(PaddingScheme::new_pkcs1v15_encrypt(), &symmetric_key).map_err(CryptoError::RsaError)?;
//
//     Ok(decrypted_data)
// }

fn encrypt_key(symmetric_key: Vec<u8>, rsa_public_pem: &str) -> Result<Vec<u8>, CryptoError> {
    // Encrypt with public key
    let rsa = Rsa::public_key_from_pem(rsa_public_pem.as_bytes()).map_err(CryptoError::OpensslError)?;
    let mut buf: Vec<u8> = vec![0; rsa.size() as usize];
    rsa.public_encrypt(&*symmetric_key, &mut buf, Padding::PKCS1).map_err(CryptoError::OpensslError)?;

    Ok(buf)
}

fn decrypt_key(symmetric_key: &[u8], rsa_private_pem: &str, passphrase: &str) -> Result<Vec<u8>, CryptoError> {
    // Decrypt with private key
    let rsa = Rsa::private_key_from_pem_passphrase(rsa_private_pem.as_bytes(), passphrase.as_bytes()).map_err(CryptoError::OpensslError)?;
    let mut buf: Vec<u8> = vec![0; rsa.size() as usize];
    rsa.private_decrypt(&symmetric_key, &mut buf, Padding::PKCS1).map_err(CryptoError::OpensslError)?;

    Ok(buf[0..32].to_vec())
}

fn generate_key_pair(byte_size: u32, passphrase: &str) -> Result<(), CryptoError> {
    // Generate asymmetric key pair
    let rsa: Rsa<Private> = Rsa::generate(byte_size).map_err(CryptoError::OpensslError)?;
    let private_key: Vec<u8> = rsa.private_key_to_pem_passphrase(Cipher::aes_256_cbc(), passphrase.as_bytes()).map_err(CryptoError::OpensslError)?;
    let public_key: Vec<u8> = rsa.public_key_to_pem().map_err(CryptoError::OpensslError)?;

    let mut private_key_file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(format!("rsa-{}-priv-key.pem", byte_size))?;
    private_key_file.write_all(&private_key)?;

    let mut public_key_file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(format!("rsa-{}-pub-key.pem", byte_size))?;
    public_key_file.write_all(&public_key)?;

    Ok(())
}
