extern crate openssl;

use std::{fs, str};
use std::fs::{File, OpenOptions, read};
use std::io::{Write};
use aes_gcm::aead::{Aead, KeyInit, OsRng};
use aes_gcm::{Aes256Gcm, Nonce};
// Or `Aes128Gcm`
use aes_gcm::aead::generic_array::{GenericArray, typenum};
use aes_gcm::aead::rand_core::RngCore;
use openssl::pkey::Private;
use openssl::rsa::{Padding, Rsa};
use openssl::symm::Cipher;
use zeroize::Zeroize;
use crate::{archiver, CryptoError};
use crate::common::{get_file_stem_to_string};


// Encrypt file with AES-GCM algorithm and symmetric key with RSA algorithm
pub fn encrypt_file(input_path: &str, output_dir: &str, rsa_public_pem: &str, tmp_dir_path: &str) -> Result<String, CryptoError> {
    let file_stem = &archiver::archive(input_path, tmp_dir_path)?;
    let file_name_zipped = &format!("{}{}.zip", tmp_dir_path, file_stem);
    println!("\nencrypting {} ...", file_name_zipped);

    // Generate the symmetric AES-GCM 256-bit data key for data encryption/decryption (data key), unique per file
    let mut symmetric_key = Aes256Gcm::generate_key(&mut OsRng);

    // Create the AES-GCM cipher with a 256-bit key and 96-bit nonce
    let cipher = Aes256Gcm::new(&symmetric_key);

    // Create the 96-bit nonce, unique per file
    let mut nonce = [0u8; 12];
    OsRng.fill_bytes(&mut nonce);

    let file_original = read(file_name_zipped)?;
    let ciphertext = cipher.encrypt(nonce.as_ref().into(), &*file_original)?;

    // Encrypt the data key
    let pub_key_str = fs::read_to_string(rsa_public_pem)?;
    let encrypted_symmetric_key: Vec<u8> = encrypt_key(symmetric_key.to_vec(), &pub_key_str)?;

    let mut file_path_encrypted = OpenOptions::new()
        .write(true)
        .append(true)
        .create_new(true)
        .open(format!("{}{}.fch", &output_dir, file_stem))?;

    // The output contains the encrypted data key, the nonce and the encrypted file
    file_path_encrypted.write_all(&encrypted_symmetric_key)?;
    file_path_encrypted.write_all(&nonce)?;
    file_path_encrypted.write_all(&ciphertext)?;

    let encrypted_file_name = &format!("{}{}.fch", output_dir, file_stem);
    let result = format!("Encrypted to {}", encrypted_file_name);
    println!("\n{}", result);

    nonce.zeroize();
    symmetric_key.zeroize();

    Ok(result)
}

// Decrypt file with AES-GCM algorithm and symmetric key with RSA algorithm
pub fn decrypt_file(input_path: &str, output_dir: &str, rsa_private_pem: &mut str, passphrase: &mut str, tmp_dir_path: &str) -> Result<String, CryptoError> {
    let nonce_len = 12;
    let priv_key_str = fs::read_to_string(&rsa_private_pem)?;

    println!("decrypting {} ...\n", input_path);

    let encrypted_file: Vec<u8> = read(input_path)?;

    // Get public key size
    let rsa_pub_pem_size = get_public_key_size_from_private_key(&priv_key_str, passphrase)?;

    // Split the encrypted_symmetric_key, nonce and the encrypted file
    let (encrypted_symmetric_key, data_file) = encrypted_file.split_at(rsa_pub_pem_size as usize);
    let (nonce_vec, ciphertext) = data_file.split_at(nonce_len);
    let nonce = Nonce::from_slice(nonce_vec);

    // Decrypt the data key
    let decrypted_symmetric_key = decrypt_key(encrypted_symmetric_key, &priv_key_str, passphrase)?;

    let mut symmetric_key: GenericArray<u8, typenum::U32> = GenericArray::from(decrypted_symmetric_key);
    let cipher = Aes256Gcm::new(&symmetric_key);
    let file_decrypted = cipher.decrypt(nonce, ciphertext.as_ref())?;
    let file_stem_decrypted = &get_file_stem_to_string(input_path)?;
    let decrypted_file_path: String = format!("{}{}.zip", tmp_dir_path, file_stem_decrypted);

    File::create(&decrypted_file_path)?;
    fs::write(&decrypted_file_path, file_decrypted)?;
    archiver::unarchive(&decrypted_file_path, output_dir)?;

    println!("\ndecrypted to {}", output_dir);

    symmetric_key.zeroize();
    rsa_private_pem.zeroize();
    passphrase.zeroize();

    let result = format!("Decrypted to {}", output_dir);
    println!("\n{}", result);

    Ok(result)
}

fn get_public_key_size_from_private_key(rsa_private_pem: &str, passphrase: &str) -> Result<u32, CryptoError> {
    let rsa_private = Rsa::private_key_from_pem_passphrase(rsa_private_pem.as_bytes(), passphrase.as_bytes())?;
    let rsa_public_pem: Vec<u8> = rsa_private.public_key_to_pem()?;
    let rsa_public = Rsa::public_key_from_pem(&rsa_public_pem)?;

    Ok(rsa_public.size())
}

// Encrypt the data key with RSA algorithm
fn encrypt_key(symmetric_key: Vec<u8>, rsa_public_pem: &str) -> Result<Vec<u8>, CryptoError> {
    // Encrypt with public key
    let rsa = Rsa::public_key_from_pem(rsa_public_pem.as_bytes())?;
    let mut buf: Vec<u8> = vec![0; rsa.size() as usize];
    rsa.public_encrypt(&symmetric_key, &mut buf, Padding::PKCS1)?;

    Ok(buf)
}

// Decrypt the data key with RSA algorithm
fn decrypt_key(symmetric_key: &[u8], rsa_private_pem: &str, passphrase: &str) -> Result<[u8; 32], CryptoError> {
    // Decrypt with private key
    let rsa = Rsa::private_key_from_pem_passphrase(rsa_private_pem.as_bytes(), passphrase.as_bytes())?;
    let mut buf: Vec<u8> = vec![0; rsa.size() as usize];
    rsa.private_decrypt(symmetric_key, &mut buf, Padding::PKCS1)?;

    // Return only the first 32 elements of the vector as a fixed-size array
    let mut result: [u8; 32] = Default::default();
    result.copy_from_slice(&buf[0..32]);

    Ok(result)
}

pub fn generate_asymmetric_key_pair(bit_size: u32, passphrase: &str, output_dir: &str) -> Result<String, CryptoError> {
    // Generate asymmetric key pair
    let rsa: Rsa<Private> = Rsa::generate(bit_size)?;
    let private_key: Vec<u8> = rsa.private_key_to_pem_passphrase(Cipher::aes_256_cbc(), passphrase.as_bytes())?;
    let public_key: Vec<u8> = rsa.public_key_to_pem()?;
    let private_key_path = format!("{}rsa-{}-priv-key.pem", &output_dir, bit_size);
    let public_key_path = format!("{}rsa-{}-pub-key.pem", &output_dir, bit_size);

    println!("Writing private key to {} ...", &private_key_path);
    let mut private_key_file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(&private_key_path)?;
    private_key_file.write_all(&private_key)?;

    println!("Writing public key to {} ...", &public_key_path);
    let mut public_key_file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(&public_key_path)?;
    public_key_file.write_all(&public_key)?;

    let result = format!("Generated key pair to {}", output_dir);
    println!("\n{}", result);

    Ok(result)
}