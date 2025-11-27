use std::fs::{self, File, OpenOptions, read};
use std::io::Write;

use chacha20poly1305::{
    aead::{Aead, KeyInit, OsRng, generic_array::{GenericArray, typenum}, rand_core::RngCore},
    XChaCha20Poly1305,
};
use openssl::pkey::Private;
use openssl::rsa::{Padding, Rsa};
use openssl::symm::Cipher;
use zeroize::Zeroize;

use crate::{archiver, CryptoError};
use crate::common::{get_duration, get_file_stem_to_string};
use crate::reed_solomon::{rs_decode, rs_encode};

const NONCE_24_SIZE: usize = 24;
const KEY_SIZE: usize = 32;

/// Encrypts a file with XChaCha20Poly1305 algorithm and symmetric key with RSA algorithm.
pub fn encrypt_file(input_path: &str, output_dir: &str, rsa_public_pem: &str, tmp_dir_path: &str) -> Result<String, CryptoError> {
    let start_time = std::time::Instant::now();
    let file_stem = &archiver::archive(input_path, tmp_dir_path)?;
    let zipped_file_name = &format!("{}{}.zip", tmp_dir_path, file_stem);
    println!("\nEncrypting {} ...", zipped_file_name);

    // Generate the symmetric key for data encryption/decryption (data key), unique per file
    let mut symmetric_key = XChaCha20Poly1305::generate_key(&mut OsRng);

    let cipher = XChaCha20Poly1305::new(&symmetric_key);

    let mut nonce_24 = [0u8; NONCE_24_SIZE];
    OsRng.fill_bytes(&mut nonce_24);

    let zipped_file = read(zipped_file_name)?;
    let ciphertext = cipher.encrypt(nonce_24.as_ref().into(), &*zipped_file)?;

    let pub_key_str = fs::read_to_string(rsa_public_pem)?;
    let encrypted_symmetric_key: Vec<u8> = match encrypt_key(symmetric_key.to_vec(), &pub_key_str) {
        Ok(encrypted_symmetric_key) => encrypted_symmetric_key,
        Err(_) => return Err(CryptoError::EncryptionDecryptionError("The provided public key is not valid".to_string())),
    };

    let mut encrypted_file_path = OpenOptions::new()
        .write(true)
        .append(true)
        .create_new(true)
        .open(format!("{}{}.fch", &output_dir, file_stem))?;

    // Reserve header information for decryption
    let flags: [bool; 4] = [false, false, false, false];
    let serialized_flags: Vec<u8> = bincode::encode_to_vec(&flags, bincode::config::standard())?;

    let encoded_encrypted_symmetric_key: Vec<u8> = rs_encode(&encrypted_symmetric_key)?;
    let encoded_nonce_24: Vec<u8> = rs_encode(&nonce_24)?;

    encrypted_file_path.write_all(&serialized_flags)?;
    encrypted_file_path.write_all(&encoded_encrypted_symmetric_key)?;
    encrypted_file_path.write_all(&encoded_nonce_24)?;
    encrypted_file_path.write_all(&ciphertext)?;

    let encrypted_file_name = &format!("{}{}.fch", output_dir, file_stem);
    let result = format!("Encrypted to {} for {}", encrypted_file_name, get_duration(start_time.elapsed().as_secs_f64()));
    println!("\n{}", result);

    nonce_24.zeroize();
    symmetric_key.zeroize();

    Ok(result)
}

/// Decrypts a file with XChaCha20Poly1305 algorithm and symmetric key with RSA algorithm.
pub fn decrypt_file(input_path: &str, output_dir: &str, rsa_private_pem: &mut str, passphrase: &mut str, tmp_dir_path: &str) -> Result<String, CryptoError> {
    let start_time = std::time::Instant::now();

    let priv_key_str = fs::read_to_string(&rsa_private_pem)?;

    println!("Decrypting {} ...\n", input_path);

    let encrypted_file: Vec<u8> = read(input_path)?;

    let rsa_pub_pem_size = match get_public_key_size_from_private_key(&priv_key_str, passphrase) {
        Ok(rsa_pub_pem_size) => rsa_pub_pem_size,
        Err(_) => return Err(CryptoError::EncryptionDecryptionError("Incorrect password or wrong private key provided".to_string())),
    };

    let (serialized_flags, rem_data) = encrypted_file.split_at(4);
    let (_flags, _): ([bool; 4], usize) = bincode::decode_from_slice(serialized_flags, bincode::config::standard())?;
    let (encoded_encrypted_symmetric_key, rem_data) = rem_data.split_at((rsa_pub_pem_size * 3) as usize);
    let (encoded_nonce_24, ciphertext) = rem_data.split_at(72);

    let encrypted_symmetric_key = rs_decode(encoded_encrypted_symmetric_key)?;
    let nonce_24 = rs_decode(encoded_nonce_24)?;

    let decrypted_symmetric_key = decrypt_key(&encrypted_symmetric_key, &priv_key_str, passphrase)?;

    let mut symmetric_key: GenericArray<u8, typenum::U32> = GenericArray::from(decrypted_symmetric_key);
    let cipher = XChaCha20Poly1305::new(&symmetric_key);
    let file_decrypted = cipher.decrypt(nonce_24[0..NONCE_24_SIZE].as_ref().into(), ciphertext.as_ref())?;
    let file_stem_decrypted = &get_file_stem_to_string(input_path)?;
    let decrypted_file_path: String = format!("{}{}.zip", tmp_dir_path, file_stem_decrypted);

    File::create(&decrypted_file_path)?;
    fs::write(&decrypted_file_path, file_decrypted)?;
    let output_path = archiver::unarchive(&decrypted_file_path, output_dir)?;

    symmetric_key.zeroize();
    rsa_private_pem.zeroize();
    passphrase.zeroize();

    let result = format!("Decrypted to {} for {}", output_path, get_duration(start_time.elapsed().as_secs_f64()));
    println!("\n{}", result);

    Ok(result)
}

fn get_public_key_size_from_private_key(rsa_private_pem: &str, passphrase: &str) -> Result<u32, CryptoError> {
    let rsa_private = Rsa::private_key_from_pem_passphrase(rsa_private_pem.as_bytes(), passphrase.as_bytes())?;
    let rsa_public_pem: Vec<u8> = rsa_private.public_key_to_pem()?;
    let rsa_public = Rsa::public_key_from_pem(&rsa_public_pem)?;

    Ok(rsa_public.size())
}

/// Encrypts the data key with RSA algorithm.
fn encrypt_key(symmetric_key: Vec<u8>, rsa_public_pem: &str) -> Result<Vec<u8>, CryptoError> {
    let rsa = Rsa::public_key_from_pem(rsa_public_pem.as_bytes())?;
    let mut buf: Vec<u8> = vec![0; rsa.size() as usize];
    rsa.public_encrypt(&symmetric_key, &mut buf, Padding::PKCS1)?;

    Ok(buf)
}

/// Decrypts the data key with RSA algorithm.
fn decrypt_key(symmetric_key: &[u8], rsa_private_pem: &str, passphrase: &str) -> Result<[u8; KEY_SIZE], CryptoError> {
    let rsa = Rsa::private_key_from_pem_passphrase(rsa_private_pem.as_bytes(), passphrase.as_bytes())?;
    let mut buf: Vec<u8> = vec![0; rsa.size() as usize];
    rsa.private_decrypt(symmetric_key, &mut buf, Padding::PKCS1)?;

    let mut result: [u8; KEY_SIZE] = Default::default();
    result.copy_from_slice(&buf[0..KEY_SIZE]);

    Ok(result)
}

/// Generates an asymmetric RSA key pair.
pub fn generate_asymmetric_key_pair(bit_size: u32, passphrase: &mut str, output_dir: &str) -> Result<String, CryptoError> {
    let rsa: Rsa<Private> = Rsa::generate(bit_size)?;

    let private_key: Vec<u8> = rsa.private_key_to_pem_passphrase(Cipher::chacha20_poly1305(), passphrase.as_bytes())?;
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

    passphrase.zeroize();

    let result = format!("Generated key pair to {}", output_dir);
    println!("\n{}", result);

    Ok(result)
}