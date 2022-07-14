extern crate hex;
extern crate rsa;

use std::{fs, str};
use std::error::Error;
use std::fs::{File, OpenOptions};
use std::io::{Read, Write};

use aes_gcm::{Aes256Gcm, AesGcm, Key, Nonce};
// Or `Aes128Gcm`
use aes_gcm::aead::{Aead, NewAead};
use aes_gcm::aead::generic_array::{GenericArray, typenum};
use aes_gcm::aes::Aes256;
use rand::distributions::Alphanumeric;
use rand::prelude::*;
use rsa::{PaddingScheme,
          pkcs1::{DecodeRsaPrivateKey, DecodeRsaPublicKey}, PublicKey, RsaPrivateKey, RsaPublicKey};

// use thiserror::Error;

#[cfg(test)]
mod tests {
    use std::fs;

    use crate::crypto::{decrypt_file, encrypt_file};

    const FILE_PATH: &str = "src/test_files/test1.txt";
    // RSA-4096 PKCS#1 public key encoded as PEM
    const RSA_4096_PUB_PEM: &str = "src/key_examples/rsa4096-pub.pem";
    // RSA-4096 PKCS#1 private key encoded as PEM
    const RSA_4096_PRIV_PEM: &str = "src/key_examples/rsa4096-priv.pem";
    const FILE_PATH_ENCRYPTED: &str = "src/test_files/test1.txt_encrypted";
    const FILE_PATH_DECRYPTED: &str = "src/test_files/test1_decrypted.txt";

    #[test]
    fn encrypt_decrypt_test() {
        let pub_key = fs::read_to_string(RSA_4096_PUB_PEM).unwrap();
        encrypt_file(FILE_PATH, &pub_key).unwrap();

        let priv_key = fs::read_to_string(RSA_4096_PRIV_PEM).unwrap();
        decrypt_file(FILE_PATH_ENCRYPTED, FILE_PATH_DECRYPTED, &priv_key).unwrap();

        let file_original = fs::read_to_string(FILE_PATH).unwrap();
        let file_decrypted = fs::read_to_string(FILE_PATH_DECRYPTED).unwrap();

        assert_eq!(file_original, file_decrypted);

        fs::remove_file(FILE_PATH_ENCRYPTED).unwrap();
        fs::remove_file(FILE_PATH_DECRYPTED).unwrap();
    }
}

// #[derive(Error, Debug)]
// pub enum CryptoError {
//     #[error("There is no such file!")]
//     Io(#[from] std::io::Error),
//     // #[error("AES encryption failure!")]
//     // EncryptionAes(#[source] aes_gcm::Error),
//     #[error("RSA encryption failure!")]
//     EncryptionRsa(#[source] rsa::errors::Error),
//     #[error("String error!")]
//     StringError(String),
//     #[error("Unknown error!")]
//     Unknown,
// }

// Encrypt file with AES-GCM algorithm
pub fn encrypt_file(file_path: &str, rsa_public_pem: &str) -> Result<(), Box<dyn Error>> {
    // The string for generating the symmetric key should be 256-bit (32-bytes)
    let rand_string_32: String = thread_rng()
        .sample_iter(&Alphanumeric)
        .take(32)
        .map(char::from)
        .collect();

    // The string for the nonce should be 96-bit (12-bytes)
    let rand_string_12: String = thread_rng()
        .sample_iter(&Alphanumeric)
        .take(12)
        .map(char::from)
        .collect();

    // Generate the symmetric AES-GCM 256-bit key for data encryption/decryption (data key), unique per file
    let symmetric_key: &GenericArray<u8, typenum::U32> = Key::from_slice(rand_string_32.as_bytes());
    // Create the AES-GCM cipher with a 256-bit key and 96-bit nonce
    let cipher: AesGcm<Aes256, typenum::U12> = Aes256Gcm::new(symmetric_key);
    // Create the 96-bit nonce, unique per file
    let nonce: &GenericArray<u8, typenum::U12> = Nonce::from_slice(rand_string_12.as_bytes());
    let file_original = get_file_as_byte_vec(file_path)?; //{
    // Ok(file_original) => {
    match file_original {
        None => { return Err(format!("No file found!").into()); }
        Some(file_original) => {// Encrypt the file with AES-GCM algorithm
            match cipher.encrypt(nonce, &*file_original) {
                Ok(ciphertext) => {
                    // Encrypt the data key
                    match encrypt_key_rsa(symmetric_key.to_vec(), rsa_public_pem)? {
                        None => { return Err(format!("There is no relevant key").into()); }
                        Some(encrypted_symmetric_key) => {
                            let mut file_path_encrypted = OpenOptions::new()
                                .write(true)
                                .append(true)
                                .create_new(true)
                                .open(format!("{}_encrypted", file_path))?;

                            // The output contains the encrypted data key, the nonce and the encrypted file
                            file_path_encrypted.write_all(&encrypted_symmetric_key)?;
                            file_path_encrypted.write_all(&nonce)?;
                            file_path_encrypted.write_all(&ciphertext)?;
                        }
                    }
                }
                Err(e) => { return Err(format!("Encryption failure: {}", e).into()); }
            }
        }
    }
    // }
    // Err(e) => { return Err(format!("No file found: {}", e).into()); }
    // }
    Ok(())
}

// Decrypt file with AES-GCM algorithm
pub fn decrypt_file(encrypted_file_path: &str, decrypted_file_path: &str, rsa_private_pem: &str) -> Result<(), Box<dyn Error>> {
    if let Some(data) = get_file_as_byte_vec(encrypted_file_path)? {
        // Split the nonce and the encrypted file
        let (encrypted_symmetric_key, data_file) = data.split_at(512);
        let (nonce_vec, ciphertext) = data_file.split_at(12);
        let nonce = Nonce::from_slice(nonce_vec);

        // Decrypt the data key
        match decrypt_key_rsa(encrypted_symmetric_key, rsa_private_pem)? {
            None => { return Err(format!("Cannot decrypt key!").into()); }
            Some(decrypted_symmetric_key) => {
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
                match cipher.decrypt(nonce, ciphertext.as_ref()) {
                    Ok(file_decrypted) => {
                        // let my_str = str::from_utf8(&plaintext).unwrap();
                        match File::create(decrypted_file_path) {
                            Ok(_) => {
                                match fs::write(decrypted_file_path, file_decrypted) {
                                    Ok(_) => {}
                                    Err(e) => { return Err(format!("Cannot write file: {}", e).into()); }
                                }
                            }
                            Err(e) => { return Err(format!("Cannot create file: {}", e).into()); }
                        }
                    }
                    Err(e) => { return Err(format!("Decryption failure: {}", e).into()); }
                }
            }
        }
    } else {
        return Err(format!("Cannot get file as bytes").into());
    }

    Ok(())
}

fn get_file_as_byte_vec(filename: &str) -> Result<Option<Vec<u8>>, Box<dyn Error>> {
    match File::open(&filename) {
        Ok(mut file) => {
            match fs::metadata(&filename) {
                Ok(metadata) => {
                    let mut buffer = vec![0; metadata.len() as usize];
                    match file.read(&mut buffer) {
                        Ok(_) => {
                            Ok(Some(buffer))
                        }
                        Err(e) => {
                            return Err(format!("Buffer overflow: {}", e).into());
                        }
                    }
                }
                Err(e) => {
                    return Err(format!("Unable to read metadata: {}", e).into());
                }
            }
        }
        Err(e) => {
            return Err(format!("Cannot open file: {}", e).into());
        }
    }
}

// Encrypt the data key with RSA algorithm
fn encrypt_key_rsa(symmetric_key: Vec<u8>, rsa_public_pem: &str) -> Result<Option<Vec<u8>>, Box<dyn Error>> {
    let mut rng = thread_rng();
    // let public_key = RsaPublicKey::from_pkcs1_der(RSA_4096_PUB_DER).unwrap();
    match RsaPublicKey::from_pkcs1_pem(rsa_public_pem) {
        Ok(public_key) => {
            match public_key.encrypt(&mut rng, PaddingScheme::new_pkcs1v15_encrypt(), &symmetric_key[..]) {
                Ok(encrypted_data) => { Ok(Some(encrypted_data)) }
                Err(e) => {
                    return Err(format!("Cannot encrypt key: {}", e).into());
                }
            }
        }
        Err(e) => {
            return Err(format!("Cannot encrypt key: {}", e).into());
        }
    }
}

// Decrypt the data key with RSA algorithm
fn decrypt_key_rsa(symmetric_key: &[u8], rsa_private_pem: &str) -> Result<Option<Vec<u8>>, Box<dyn Error>> {
    match RsaPrivateKey::from_pkcs1_pem(rsa_private_pem) {
        Ok(private_key) => {
            // let priv_key = RsaPrivateKey::from_pkcs1_der(RSA_4096_PRIV_DER).unwrap();
            match private_key.decrypt(PaddingScheme::new_pkcs1v15_encrypt(), &symmetric_key) {
                Ok(decrypted_data) => { Ok(Some(decrypted_data)) }
                Err(e) => {
                    return Err(format!("Cannot decrypt key: {}", e).into());
                }
            }
        }
        Err(e) => {
            return Err(format!("Cannot decrypt key: {}", e).into());
        }
    }
}
