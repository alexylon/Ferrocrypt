use chacha20poly1305::{aead::{stream, KeyInit, OsRng}, {aead::rand_core::RngCore}, XChaCha20Poly1305};
use std::{fs, fs::File, io::{Read, Write}};
use std::fs::OpenOptions;
use std::path::Path;
use zeroize::Zeroize;
use crate::{archiver, CryptoError};
use crate::common::normalize_paths;
use crate::CryptoError::{ChaCha20Poly1305Error, Message};


#[cfg(test)]
mod tests {
    // use zeroize::Zeroize;
    use crate::symmetric::{decrypt_file, encrypt_file};

    const SRC_FILE_PATH: &str = "src/test_files/test-file.txt";
    // const SRC_FILE_PATH: &str = "src/dest/test-file.rcs";
    const ENCRYPTED_FILE_PATH: &str = "src/dest/test-file.rcs";
    // const DECRYPTED_FILE_PATH: &str = "src/dest/test-file.txt";
    // const SRC_FILE_PATH: &str = "src/test_files/test-folder";
    // const SRC_FILE_PATH: &str = "src/dest/test-folder.rcs";
    const DEST_DIR_PATH: &str = "src/dest/";
    const PASSPHRASE: &str = "strong_passphrase";

    #[test]
    fn encrypt_file_test() -> Result<(), anyhow::Error> {
        // let mut passphrase = rpassword::prompt_password("passphrase:")?;
        let mut passphrase = PASSPHRASE.to_string();
        encrypt_file(SRC_FILE_PATH, DEST_DIR_PATH, &mut passphrase)?;

        // passphrase.zeroize();

        Ok(())
    }

    #[test]
    fn decrypt_file_test() -> Result<(), anyhow::Error> {
        // let mut password = rpassword::prompt_password("password:")?;
        let mut passphrase = PASSPHRASE.to_string();
        decrypt_file(ENCRYPTED_FILE_PATH, DEST_DIR_PATH, &mut passphrase)?;

        // password.zeroize();

        Ok(())
    }
}

// Encrypt file with XChaCha20Poly1305 algorithm
pub fn encrypt_file(src_file_path: &str, dest_dir_path: &str, passphrase: &mut str) -> Result<(), CryptoError> {
    let (src_file_path_norm, dest_dir_path_norm) = normalize_paths(src_file_path, dest_dir_path);
    let file_stem = &archiver::archive(&src_file_path_norm, &dest_dir_path_norm)?;
    let file_name_zipped = &format!("{dest_dir_path_norm}{file_stem}.zip");
    let mut source_file = File::open(file_name_zipped)?;
    let argon2_config = argon2_config();
    let mut salt = [0u8; 32];
    let mut nonce = [0u8; 19];
    OsRng.fill_bytes(&mut salt);
    OsRng.fill_bytes(&mut nonce);

    let mut key = argon2::hash_raw(passphrase.as_bytes(), &salt, &argon2_config)?;
    let aead = XChaCha20Poly1305::new(key[..32].as_ref().into());
    let mut stream_encryptor = stream::EncryptorBE32::from_aead(aead, nonce.as_ref().into());

    const BUFFER_LEN: usize = 500;
    let mut buffer = [0u8; BUFFER_LEN];
    let mut file_path_encrypted = OpenOptions::new()
        .write(true)
        .append(true)
        .create_new(true)
        .open(format!("{}{}.rcs", &dest_dir_path_norm, file_stem))?;

    file_path_encrypted.write_all(&salt)?;
    file_path_encrypted.write_all(&nonce)?;

    loop {
        let read_count = source_file.read(&mut buffer)?;

        if read_count == BUFFER_LEN {
            let ciphertext = stream_encryptor
                .encrypt_next(buffer.as_slice())
                .map_err(ChaCha20Poly1305Error)?;
            file_path_encrypted.write_all(&ciphertext)?;
        } else {
            let ciphertext = stream_encryptor
                .encrypt_last(&buffer[..read_count])
                .map_err(ChaCha20Poly1305Error)?;
            file_path_encrypted.write_all(&ciphertext)?;
            break;
        }
    }

    fs::remove_file(file_name_zipped)?;
    let file_name_encrypted = &format!("{dest_dir_path_norm}{file_stem}.rcs");
    println!();
    println!("encrypted to {file_name_encrypted}");

    salt.zeroize();
    nonce.zeroize();
    key.zeroize();
    passphrase.zeroize();

    Ok(())
}

// Decrypt file with XChaCha20Poly1305 algorithm
pub fn decrypt_file(encrypted_file_path: &str, dest_dir_path: &str, passphrase: &mut str) -> Result<(), CryptoError> {
    let (encrypted_file_path_norm, dest_dir_path_norm) = normalize_paths(encrypted_file_path, dest_dir_path);

    if encrypted_file_path_norm.ends_with(".rcs") {
        let mut salt = [0u8; 32];
        let mut nonce = [0u8; 19];
        let mut encrypted_file = File::open(&encrypted_file_path_norm)?;
        let file_stem_decrypted = Path::new(&encrypted_file_path_norm)
            .file_stem().ok_or(Message("Cannot get file stem".to_string()))?
            .to_str().ok_or(Message("Cannot convert file stem to &str".to_string()))?;
        // let decrypted_file_path: String = format!("{}{}.zip", dest_dir_path_norm, file_stem_decrypted);
        // File::create(&decrypted_file_path)?;
        let decrypted_file_path = format!("{}{}.zip", dest_dir_path_norm, file_stem_decrypted);
        let mut decrypted_file = OpenOptions::new()
            .write(true)
            .append(true)
            .create_new(true)
            .open(&decrypted_file_path)?;

        let mut read_count = encrypted_file.read(&mut salt)?;
        if read_count != salt.len() {
            return Err(Message("Error reading salt!".to_string()));
        }

        read_count = encrypted_file.read(&mut nonce)?;
        if read_count != nonce.len() {
            return Err(Message("Error reading nonce!".to_string()));
        }

        let argon2_config = argon2_config();
        let mut key = argon2::hash_raw(passphrase.as_bytes(), &salt, &argon2_config)?;
        let aead = XChaCha20Poly1305::new(key[..32].as_ref().into());
        let mut stream_decryptor = stream::DecryptorBE32::from_aead(aead, nonce.as_ref().into());

        const BUFFER_LEN: usize = 500 + 16;
        let mut buffer = [0u8; BUFFER_LEN];

        loop {
            let read_count = encrypted_file.read(&mut buffer)?;

            if read_count == BUFFER_LEN {
                let plaintext = stream_decryptor
                    .decrypt_next(buffer.as_slice())
                    .map_err(ChaCha20Poly1305Error)?;
                decrypted_file.write_all(&plaintext)?;
            } else if read_count == 0 {
                break;
            } else {
                let plaintext = stream_decryptor
                    .decrypt_last(&buffer[..read_count])
                    .map_err(ChaCha20Poly1305Error)?;
                decrypted_file.write_all(&plaintext)?;
                break;
            }
        }

        archiver::unarchive(&decrypted_file_path, &dest_dir_path_norm)?;
        fs::remove_file(&decrypted_file_path)?;
        println!();
        println!("decrypted to {dest_dir_path_norm}");

        salt.zeroize();
        nonce.zeroize();
        key.zeroize();
        passphrase.zeroize();
    } else {
        return Err(Message("This file should have '.rcs' extension!".to_string()));
    }

    Ok(())
}

fn argon2_config<'a>() -> argon2::Config<'a> {
    argon2::Config {
        variant: argon2::Variant::Argon2id,
        hash_length: 32,
        lanes: 8,
        mem_cost: 16 * 1024,
        time_cost: 8,
        ..Default::default()
    }
}
