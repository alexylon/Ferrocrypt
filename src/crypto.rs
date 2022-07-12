extern crate hex;
extern crate rsa;

use std::{fs, str};
use std::convert::TryInto;
use std::fs::{File, OpenOptions};
use std::io::{Error, Read, Write};

use aes_gcm::{Aes256Gcm, AesGcm, Key, Nonce};
// Or `Aes128Gcm`
use aes_gcm::aead::{Aead, NewAead};
use aes_gcm::aead::generic_array::{GenericArray, typenum};
use aes_gcm::aes::Aes256;
use rand::distributions::Alphanumeric;
use rand::prelude::*;
use rsa::{PaddingScheme,
          pkcs1::{DecodeRsaPrivateKey, DecodeRsaPublicKey}, PublicKey, RsaPrivateKey, RsaPublicKey};


// Encrypt file with AES-GCM algorithm
pub fn encrypt_file(file_path: &str, rsa_public_pem: &str) -> Result<(), Error> {
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
    match get_file_as_byte_vec(file_path) {
        Ok(file_original) => {
            match file_original {
                None => { println!("There is no file!") }
                Some(file_original) => {// Encrypt the file with AES-GCM algorithm
                    println!("Encrypting {}", file_path);
                    match cipher.encrypt(nonce, &*file_original) {
                        Ok(ciphertext) => {
                            // Encrypt the data key
                            match encrypt_key_rsa(symmetric_key.to_vec(), rsa_public_pem)? {
                                None => { println!("There is no key!") }
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
                        Err(e) => { println!("Encryption failure: {}", e) }
                    }
                }
            }
        }
        Err(e) => { println!("Cannot get file as bytes: {}", e) }
    }

    Ok(())
}

// Decrypt file with AES-GCM algorithm
pub fn decrypt_file(encrypted_file_path: &str, decrypted_file_path: &str, rsa_private_pem: &str) -> Result<(), Error> {
    if let Some(data) = get_file_as_byte_vec(encrypted_file_path)? {
        // Split the nonce and the encrypted file
        let (encrypted_symmetric_key, data_file) = data.split_at(512);
        let (nonce_vec, ciphertext) = data_file.split_at(12);
        let nonce = Nonce::from_slice(nonce_vec);

        // Decrypt the data key
        match decrypt_key_rsa(encrypted_symmetric_key, rsa_private_pem)? {
            None => { println!("Cannot decrypt key!") }
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
                println!("Decrypting {}", encrypted_file_path);
                match cipher.decrypt(nonce, ciphertext.as_ref()) {
                    Ok(file_decrypted) => {
                        // let my_str = str::from_utf8(&plaintext).unwrap();
                        match File::create(decrypted_file_path) {
                            Ok(_) => {
                                match fs::write(decrypted_file_path, file_decrypted) {
                                    Ok(_) => {}
                                    Err(e) => { println!("Cannot write file: {}", e) }
                                }
                            }
                            Err(e) => { println!("Cannot create file: {}", e) }
                        }
                    }
                    Err(e) => { println!("Decryption failure: {}", e) }
                }
            }
        }
    } else {
        println!("Cannot get file as bytes!");
    }

    Ok(())
}

fn get_file_as_byte_vec(filename: &str) -> Result<Option<Vec<u8>>, Error> {
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
                            println!("Buffer overflow: {}", e);
                            Ok(None)
                        }
                    }
                }
                Err(e) => {
                    println!("Unable to read metadata: {}", e);
                    Ok(None)
                }
            }
        }
        Err(e) => {
            println!("Cannot open file: {}", e);
            Ok(None)
        }
    }
}

// Encrypt the data key with RSA algorithm
fn encrypt_key_rsa(symmetric_key: Vec<u8>, rsa_public_pem: &str) -> Result<Option<Vec<u8>>, Error> {
    let mut rng = thread_rng();
    // let public_key = RsaPublicKey::from_pkcs1_der(RSA_4096_PUB_DER).unwrap();
    match RsaPublicKey::from_pkcs1_pem(rsa_public_pem) {
        Ok(public_key) => {
            match public_key.encrypt(&mut rng, PaddingScheme::new_pkcs1v15_encrypt(), &symmetric_key[..]) {
                Ok(encrypted_data) => { Ok(Some(encrypted_data)) }
                Err(e) => {
                    println!("Cannot encrypt key: {}", e);
                    Ok(None)
                }
            }
        }
        Err(e) => {
            println!("Cannot encrypt key: {}", e);
            Ok(None)
        }
    }
}

// Decrypt the data key with RSA algorithm
fn decrypt_key_rsa(symmetric_key: &[u8], rsa_private_pem: &str) -> Result<Option<Vec<u8>>, Error> {
    match RsaPrivateKey::from_pkcs1_pem(rsa_private_pem) {
        Ok(private_key) => {
            // let priv_key = RsaPrivateKey::from_pkcs1_der(RSA_4096_PRIV_DER).unwrap();
            match private_key.decrypt(PaddingScheme::new_pkcs1v15_encrypt(), &symmetric_key) {
                Ok(decrypted_data) => { Ok(Some(decrypted_data)) }
                Err(e) => {
                    println!("Cannot decrypt key: {}", e);
                    Ok(None)
                }
            }
        }
        Err(e) => {
            println!("Cannot decrypt key: {}", e);
            Ok(None)
        }
    }
}
