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

// TODO: cleanup all unwraps

pub fn encrypt_aes_gcm(file_path: &str, rsa_public_pem: &str) {
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

    // Generate the symmetric AES-GCM 256-bit key, unique per file
    let symmetric_key: &GenericArray<u8, typenum::U32> = Key::from_slice(rand_string_32.as_bytes());
    // Create the AES-GCM cipher with a 256-bit key and 96-bit nonce
    let cipher: AesGcm<Aes256, typenum::U12> = Aes256Gcm::new(symmetric_key);
    // Create the 96-bit nonce, unique per file
    let nonce: &GenericArray<u8, typenum::U12> = Nonce::from_slice(rand_string_12.as_bytes());
    let file_original = get_file_as_byte_vec(file_path).unwrap();

    // Encrypt the file with AES-GCM algorithm
    let ciphertext = cipher.encrypt(nonce, &*file_original)
        .expect("encryption failure!"); // NOTE: handle this error to avoid panics!

    let encrypted_symmetric_key = encrypt_key(symmetric_key.to_vec(), rsa_public_pem).unwrap();

    // let decrypted_symmetric_key = decrypt_key(encrypted_symmetric_key);
    // println!("symmetric_key {:?}", symmetric_key);
    // println!("encrypted_symmetric_key_length {}", encrypted_symmetric_key.len());

    let mut file_path_encrypted = OpenOptions::new()
        .write(true)
        .append(true)
        .create_new(true)
        // either use ? or unwrap since it returns a Result
        .open(format!("{}_encrypted", file_path)).unwrap();

    // The output contains both the nonce and the encrypted file
    file_path_encrypted.write_all(&encrypted_symmetric_key).unwrap();
    file_path_encrypted.write_all(&nonce).unwrap();
    file_path_encrypted.write_all(&ciphertext).unwrap();
}

pub fn decrypt_aes_gcm(encrypted_file_path: &str, rsa_private_pem: &str) {
    let data = get_file_as_byte_vec(encrypted_file_path).expect("Unable to read file");
    // Split the nonce and the encrypted file
    let (encrypted_symmetric_key, data_file) = data.split_at(512);
    let (nonce_vec, ciphertext) = data_file.split_at(12);
    let nonce = Nonce::from_slice(nonce_vec);

    let decrypted_symmetric_key: Vec<u8> = decrypt_key(encrypted_symmetric_key, rsa_private_pem).unwrap();
    let symmetric_key_array: [u8; 32] = decrypted_symmetric_key.try_into()
        .unwrap_or_else(|v: Vec<u8>| panic!("Expected a Vec of length {} but it was {}", 32, v.len()));
    let symmetric_key: &GenericArray<u8, typenum::U32> = &GenericArray::from(symmetric_key_array);
    let cipher: AesGcm<Aes256, typenum::U12> = Aes256Gcm::new(symmetric_key);

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

fn encrypt_key(symmetric_key: Vec<u8>, rsa_public_pem: &str) -> Result<Vec<u8>, Error> {
    let mut rng = rand::thread_rng();

    // let priv_key = RsaPrivateKey::from_pkcs1_der(RSA_4096_PRIV_DER).unwrap();
    // let pub_key = RsaPublicKey::from_pkcs1_der(RSA_4096_PUB_DER).unwrap();

    let pub_key = RsaPublicKey::from_pkcs1_pem(rsa_public_pem).unwrap();
    let enc_data = pub_key.encrypt(&mut rng, PaddingScheme::new_pkcs1v15_encrypt(), &symmetric_key[..]).expect("failed to encrypt");

    Ok(enc_data)
}

fn decrypt_key(symmetric_key: &[u8], rsa_private_pem: &str) -> Result<Vec<u8>, Error> {
    let priv_key = RsaPrivateKey::from_pkcs1_pem(rsa_private_pem).unwrap();
    let dec_data = priv_key.decrypt(PaddingScheme::new_pkcs1v15_encrypt(), &symmetric_key).expect("failed to decrypt");

    Ok(dec_data)
}
