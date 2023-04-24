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


#[cfg(test)]
mod tests {
    use std::fs;

    use aes_gcm::{Aes256Gcm};
    use aes_gcm::aead::{KeyInit, OsRng};

    use crate::hybrid::{decrypt_file, decrypt_key, encrypt_file, encrypt_key, generate_asymmetric_key_pair, get_public_key_size_from_private_key};

    const SRC_FILE_PATH: &str = "src/test_files/test-file.txt";
    const SRC_DIR_PATH: &str = "src/test_files/test-folder/";
    const DEST_DIRPATH: &str = "src/dest/";
    const FILE_PATH_ENCRYPTED: &str = "src/dest/test-file.fch";
    const FILE_PATH_DECRYPTED: &str = "src/dest/test-file.txt";
    const DIR_PATH_ENCRYPTED: &str = "src/dest/test-folder.fch";
    // RSA-4096 PKCS#1 public key encoded as PEM
    const RSA_PUB_PEM: &str = "src/key_examples/rsa-4096-pub-key.pem";
    // RSA-4096 PKCS#1 private key encoded as PEM
    const RSA_PRIV_PEM: &str = "src/key_examples/rsa-4096-priv-key.pem";
    const PASSPHRASE: &str = "strong_passphrase";

    #[test]
    fn encrypt_decrypt_file_test() {
        let mut rsa_priv_pem = RSA_PRIV_PEM.to_string();
        let mut passphrase = PASSPHRASE.to_string();
        encrypt_file(SRC_FILE_PATH, DEST_DIRPATH, RSA_PUB_PEM).unwrap();
        decrypt_file(FILE_PATH_ENCRYPTED, DEST_DIRPATH, &mut rsa_priv_pem, &mut passphrase).unwrap();

        let file_original = fs::read_to_string(SRC_FILE_PATH).unwrap();
        let file_decrypted = fs::read_to_string(FILE_PATH_DECRYPTED).unwrap();

        assert_eq!(file_original, file_decrypted);
    }

    #[test]
    fn encrypt_file_test() {
        encrypt_file(SRC_FILE_PATH, DEST_DIRPATH, RSA_PUB_PEM).unwrap();
    }

    #[test]
    fn decrypt_file_test() {
        let mut rsa_priv_pem = RSA_PRIV_PEM.to_string();
        let mut passphrase = PASSPHRASE.to_string();
        decrypt_file(FILE_PATH_ENCRYPTED, DEST_DIRPATH, &mut rsa_priv_pem, &mut passphrase).unwrap();
    }

    #[test]
    fn encrypt_dir_test() {
        encrypt_file(SRC_DIR_PATH, DEST_DIRPATH, RSA_PUB_PEM).unwrap();
    }

    #[test]
    fn decrypt_dir_test() {
        let mut rsa_priv_pem = RSA_PRIV_PEM.to_string();
        let mut passphrase = PASSPHRASE.to_string();
        decrypt_file(DIR_PATH_ENCRYPTED, DEST_DIRPATH, &mut rsa_priv_pem, &mut passphrase).unwrap();
    }

    #[test]
    fn encrypt_decrypt_key_test() {
        let pub_key = fs::read_to_string(RSA_PUB_PEM).unwrap();
        let priv_key = fs::read_to_string(RSA_PRIV_PEM).unwrap();
        let symmetric_key = Aes256Gcm::generate_key(&mut OsRng);
        let encrypted_symmetric_key = encrypt_key(symmetric_key.to_vec(), &pub_key).unwrap();
        let decrypted_symmetric_key = decrypt_key(&encrypted_symmetric_key, &priv_key, PASSPHRASE).unwrap();

        assert_eq!(symmetric_key.to_vec(), decrypted_symmetric_key);
    }

    #[test]
    fn generate_key_pair_test() {
        let passphrase = "test";
        generate_asymmetric_key_pair(4096, passphrase, DEST_DIRPATH).unwrap();
    }

    #[test]
    fn get_rsa_key_size_test() {
        let priv_key = fs::read_to_string(RSA_PRIV_PEM).unwrap();
        let rsa_pub_key_size = get_public_key_size_from_private_key(&priv_key, PASSPHRASE).unwrap();
        println!("rsa_pub_key_size: {rsa_pub_key_size}");
    }
}

// Encrypt file with AES-GCM algorithm and symmetric key with RSA algorithm
pub fn encrypt_file(input_path: &str, output_dir: &str, rsa_public_pem: &str) -> Result<(), CryptoError> {
    let file_stem = &archiver::archive(input_path, output_dir)?;
    let file_name_zipped = &format!("{}{}.zip", output_dir, file_stem);
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

    fs::remove_file(file_name_zipped)?;
    let file_name_encrypted = &format!("{}{}.fch", output_dir, file_stem);
    println!("\nencrypted to {}", file_name_encrypted);

    nonce.zeroize();
    symmetric_key.zeroize();

    Ok(())
}

// Decrypt file with AES-GCM algorithm and symmetric key with RSA algorithm
pub fn decrypt_file(input_path: &str, output_dir: &str, rsa_private_pem: &mut str, passphrase: &mut str) -> Result<(), CryptoError> {
    let nonce_len = 12;
    let priv_key_str = fs::read_to_string(&rsa_private_pem)?;

    if input_path.ends_with(".fch") {
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
        let decrypted_file_path: String = format!("{}{}.zip", output_dir, file_stem_decrypted);
        File::create(&decrypted_file_path)?;
        fs::write(&decrypted_file_path, file_decrypted)?;
        archiver::unarchive(&decrypted_file_path, output_dir)?;
        fs::remove_file(&decrypted_file_path)?;
        println!("\ndecrypted to {}", output_dir);

        symmetric_key.zeroize();
        rsa_private_pem.zeroize();
        passphrase.zeroize();
    } else {
        return Err(CryptoError::Message("This file should have '.fch' extension!".to_string()));
    }

    Ok(())
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

pub fn generate_asymmetric_key_pair(bit_size: u32, passphrase: &str, output_dir: &str) -> Result<(), CryptoError> {
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

    Ok(())
}