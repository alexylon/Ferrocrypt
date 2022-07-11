extern crate hex;
extern crate rsa;

use std::{fs, str};
use std::env;
use std::fs::{File, OpenOptions};
use std::io::{Error, Read, Write};
use std::convert::TryInto;

use aes_gcm::{Aes256Gcm, AesGcm, Key, Nonce};
// Or `Aes128Gcm`
use aes_gcm::aead::{Aead, NewAead};
use aes_gcm::aead::generic_array::{GenericArray, typenum};
use aes_gcm::aes::Aes256;
use rand::distributions::Alphanumeric;
use rand::prelude::*;
use rsa::{PaddingScheme,
          pkcs1::{DecodeRsaPrivateKey, DecodeRsaPublicKey}, PublicKey, RsaPrivateKey, RsaPublicKey};

const FILE_PATH_DECRYPTED: &str = "src/test_files/test1_decrypted.txt";

// TODO: clean up all unwraps

// Encrypt file with AES-GCM algorithm
pub fn encrypt_file(file_path: &str, rsa_public_pem: &str) {
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
    let file_original = get_file_as_byte_vec(file_path).unwrap();

    // Encrypt the file with AES-GCM algorithm
    println!("Encrypting {}", file_path);
    let ciphertext = cipher.encrypt(nonce, &*file_original)
        .expect("encryption failure!"); // NOTE: handle this error to avoid panics!

    // Encrypt the data key
    let encrypted_symmetric_key = encrypt_key_rsa(symmetric_key.to_vec(), rsa_public_pem).unwrap();

    let mut file_path_encrypted = OpenOptions::new()
        .write(true)
        .append(true)
        .create_new(true)
        // either use ? or unwrap since it returns a Result
        .open(format!("{}_encrypted", file_path)).unwrap();

    // The output contains the encrypted data key, the nonce and the encrypted file
    file_path_encrypted.write_all(&encrypted_symmetric_key).unwrap();
    file_path_encrypted.write_all(&nonce).unwrap();
    file_path_encrypted.write_all(&ciphertext).unwrap();
}

// Decrypt file with AES-GCM algorithm
pub fn decrypt_file(encrypted_file_path: &str, rsa_private_pem: &str) {
    let data = get_file_as_byte_vec(encrypted_file_path).expect("Unable to read file");
    // Split the nonce and the encrypted file
    let (encrypted_symmetric_key, data_file) = data.split_at(512);
    let (nonce_vec, ciphertext) = data_file.split_at(12);
    let nonce = Nonce::from_slice(nonce_vec);

    // Decrypt the data key
    let decrypted_symmetric_key: Vec<u8> = decrypt_key_rsa(encrypted_symmetric_key, rsa_private_pem).unwrap();
    let symmetric_key_array: [u8; 32] = decrypted_symmetric_key.try_into()
        .unwrap_or_else(|v: Vec<u8>| panic!("Expected a Vec of length {} but it was {}", 32, v.len()));
    let symmetric_key: &GenericArray<u8, typenum::U32> = &GenericArray::from(symmetric_key_array);
    let cipher: AesGcm<Aes256, typenum::U12> = Aes256Gcm::new(symmetric_key);
    println!("Decrypting {}", encrypted_file_path);
    let file_decrypted = cipher.decrypt(nonce, ciphertext.as_ref())
        .expect("decryption failure!"); // NOTE: handle this error to avoid panics!

    // let my_str = str::from_utf8(&plaintext).unwrap();

    File::create(FILE_PATH_DECRYPTED).unwrap();
    fs::write(FILE_PATH_DECRYPTED, file_decrypted).unwrap();
}

fn get_file_as_byte_vec(filename: &str) -> Result<Vec<u8>, Error> {
    let mut f = File::open(&filename).expect("no file found");
    let metadata = fs::metadata(&filename).expect("unable to read metadata");
    let mut buffer = vec![0; metadata.len() as usize];
    f.read(&mut buffer).expect("buffer overflow");

    Ok(buffer)
}

// Encrypt the data key with RSA algorithm
fn encrypt_key_rsa(symmetric_key: Vec<u8>, rsa_public_pem: &str) -> Result<Vec<u8>, Error> {
    let mut rng = rand::thread_rng();
    // let public_key = RsaPublicKey::from_pkcs1_der(RSA_4096_PUB_DER).unwrap();
    let public_key = RsaPublicKey::from_pkcs1_pem(rsa_public_pem).unwrap();
    let encrypted_data = public_key.encrypt(&mut rng, PaddingScheme::new_pkcs1v15_encrypt(), &symmetric_key[..]).expect("failed to encrypt");

    Ok(encrypted_data)
}

// Decrypt the data key with RSA algorithm
fn decrypt_key_rsa(symmetric_key: &[u8], rsa_private_pem: &str) -> Result<Vec<u8>, Error> {
    let private_key = RsaPrivateKey::from_pkcs1_pem(rsa_private_pem).unwrap();
    // let priv_key = RsaPrivateKey::from_pkcs1_der(RSA_4096_PRIV_DER).unwrap();
    let decrypted_data = private_key.decrypt(PaddingScheme::new_pkcs1v15_encrypt(), &symmetric_key).expect("failed to decrypt");

    Ok(decrypted_data)
}
