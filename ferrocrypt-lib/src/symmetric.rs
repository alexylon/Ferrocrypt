use chacha20poly1305::{aead::{stream, KeyInit, OsRng}, {aead::rand_core::RngCore}, XChaCha20Poly1305};
use std::{fs, fs::File, io::{Read, Write}};
use std::fs::OpenOptions;
use argon2::Variant;
use chacha20poly1305::aead::Aead;
use zeroize::Zeroize;
use crate::{archiver, CryptoError};
use crate::common::{constant_time_compare_256_bit, get_file_as_byte_vec, get_file_stem_to_string, normalize_paths, sha3_hash};
use crate::CryptoError::{ChaCha20Poly1305Error, Message};


#[cfg(test)]
mod tests {
    use std::fs;
    use crate::CryptoError;
    // use zeroize::Zeroize;
    use crate::symmetric::{decrypt_file, decrypt_large_file, encrypt_file, encrypt_large_file};

    const SRC_FILE_PATH: &str = "src/test_files/test-file.txt";
    const SRC_DIR_PATH: &str = "src/test_files/test-folder";
    const ENCRYPTED_FILE_PATH: &str = "src/dest/test-file.fcs";
    const ENCRYPTED_DIR_PATH: &str = "src/dest/test-folder.fcs";
    const ENCRYPTED_LARGE_FILE_PATH: &str = "src/dest/test-file.fcls";
    const DEST_DIR_PATH: &str = "src/dest/";
    const PASSPHRASE: &str = "strong_passphrase";

    #[test]
    fn encrypt_file_test() -> Result<(), CryptoError> {
        fs::create_dir_all("src/dest")?;
        // let mut passphrase = rpassword::prompt_password("passphrase:")?;
        let mut passphrase = PASSPHRASE.to_string();
        encrypt_file(SRC_FILE_PATH, DEST_DIR_PATH, &mut passphrase)?;

        // passphrase.zeroize();

        Ok(())
    }

    #[test]
    fn decrypt_file_test() -> Result<(), CryptoError> {
        // let mut password = rpassword::prompt_password("password:")?;
        let mut passphrase = "strong_passphrase".to_string();
        decrypt_file(ENCRYPTED_FILE_PATH, DEST_DIR_PATH, &mut passphrase)?;

        // password.zeroize();

        Ok(())
    }

    #[test]
    fn encrypt_dir_test() -> Result<(), CryptoError> {
        fs::create_dir_all("src/dest")?;
        // let mut passphrase = rpassword::prompt_password("passphrase:")?;
        let mut passphrase = PASSPHRASE.to_string();
        encrypt_file(SRC_DIR_PATH, DEST_DIR_PATH, &mut passphrase)?;

        // passphrase.zeroize();

        Ok(())
    }

    #[test]
    fn decrypt_dir_test() -> Result<(), CryptoError> {
        // let mut password = rpassword::prompt_password("password:")?;
        let mut passphrase = PASSPHRASE.to_string();
        decrypt_file(ENCRYPTED_DIR_PATH, DEST_DIR_PATH, &mut passphrase)?;

        // password.zeroize();

        Ok(())
    }

    #[test]
    fn encrypt_large_file_test() -> Result<(), CryptoError> {
        fs::create_dir_all("src/dest")?;
        // let mut passphrase = rpassword::prompt_password("passphrase:")?;
        let mut passphrase = PASSPHRASE.to_string();
        encrypt_large_file(SRC_FILE_PATH, DEST_DIR_PATH, &mut passphrase)?;

        // passphrase.zeroize();

        Ok(())
    }

    #[test]
    fn decrypt_large_file_test() -> Result<(), CryptoError> {
        // let mut password = rpassword::prompt_password("password:")?;
        let mut passphrase = "strong_passphrase".to_string();
        decrypt_large_file(ENCRYPTED_LARGE_FILE_PATH, DEST_DIR_PATH, &mut passphrase)?;

        // password.zeroize();

        Ok(())
    }
}

// Encrypt file with XChaCha20Poly1305 algorithm
pub fn encrypt_file(input_path: &str, output_dir: &str, passphrase: &mut str) -> Result<(), CryptoError> {
    let (input_path_norm, output_dir_norm) = normalize_paths(input_path, output_dir);
    let file_stem = &archiver::archive(&input_path_norm, &output_dir_norm)?;
    let file_name_zipped = &format!("{}{}.zip", output_dir_norm, file_stem);
    println!("\nencrypting {} ...", file_name_zipped);

    let argon2_config = argon2_config();
    let mut salt = [0u8; 32];
    let mut nonce = [0u8; 24];
    OsRng.fill_bytes(&mut salt);
    OsRng.fill_bytes(&mut nonce);

    let mut key = argon2::hash_raw(passphrase.as_bytes(), &salt, &argon2_config)?;

    // Hash the encryption key for comparison when decrypting
    let key_hash_ref: [u8; 32] = sha3_hash(&key)?;

    let cipher = XChaCha20Poly1305::new(key[..32].as_ref().into());
    let file_original = get_file_as_byte_vec(file_name_zipped)?;
    let ciphertext = cipher.encrypt(nonce.as_ref().into(), &*file_original)?;
    let mut file_path_encrypted = OpenOptions::new()
        .write(true)
        .append(true)
        .create_new(true)
        .open(format!("{}{}.fcs", &output_dir_norm, file_stem))?;

    file_path_encrypted.write_all(&salt)?;
    file_path_encrypted.write_all(&nonce)?;
    file_path_encrypted.write_all(&key_hash_ref)?;
    file_path_encrypted.write_all(&ciphertext)?;

    fs::remove_file(file_name_zipped)?;
    let file_name_encrypted = &format!("{}{}.fcs", output_dir_norm, file_stem);
    println!();
    println!("encrypted to {}", file_name_encrypted);

    salt.zeroize();
    nonce.zeroize();
    key.zeroize();
    passphrase.zeroize();

    Ok(())
}

// Decrypt file with XChaCha20Poly1305 algorithm
pub fn decrypt_file(input_path: &str, output_dir: &str, passphrase: &mut str) -> Result<(), CryptoError> {
    let (input_path_norm, output_dir_norm) = normalize_paths(input_path, output_dir);

    if input_path_norm.ends_with(".fcs") {
        println!("decrypting {} ...\n", input_path);

        let salt_len = 32;
        let nonce_len = 24;
        let key_hash_ref_len = 32;
        let encrypted_file: Vec<u8> = get_file_as_byte_vec(&input_path_norm)?;

        // Split the salt, nonce and the encrypted file
        let (salt, rem_data) = encrypted_file.split_at(salt_len);
        let (nonce, rem_data) = rem_data.split_at(nonce_len);
        let (key_hash_ref, ciphertext) = rem_data.split_at(key_hash_ref_len);

        let argon2_config = argon2_config();
        let mut key = argon2::hash_raw(passphrase.as_bytes(), salt, &argon2_config)?;

        // Hash the encryption key for comparison and compare it in constant time with the ref key hash
        let key_hash: [u8; 32] = sha3_hash(&key)?;
        let key_correct = constant_time_compare_256_bit(&key_hash, key_hash_ref[..32].try_into()?);

        if key_correct {
            let cipher = XChaCha20Poly1305::new(key[..32].as_ref().into());
            let file_decrypted = cipher.decrypt(nonce.as_ref().into(), ciphertext.as_ref())?;
            let file_stem_decrypted = &get_file_stem_to_string(&input_path_norm)?;
            let decrypted_file_path: String = format!("{}{}.zip", output_dir_norm, file_stem_decrypted);

            File::create(&decrypted_file_path)?;
            fs::write(&decrypted_file_path, file_decrypted)?;
            archiver::unarchive(&decrypted_file_path, &output_dir_norm)?;
            fs::remove_file(&decrypted_file_path)?;
            println!("\ndecrypted to {}", output_dir_norm);

            key.zeroize();
            passphrase.zeroize();
        } else {
            return Err(Message("The provided password is incorrect!".to_string()));
        }
    } else {
        return Err(Message("This file should have '.fcs' extension!".to_string()));
    }

    Ok(())
}

// Encrypt large file, that doesn't fit in RAM, with XChaCha20Poly1305 algorithm. This is much slower
pub fn encrypt_large_file(input_path: &str, output_dir: &str, passphrase: &mut str) -> Result<(), CryptoError> {
    let (input_path_norm, output_dir_norm) = normalize_paths(input_path, output_dir);
    let file_stem = &archiver::archive(&input_path_norm, &output_dir_norm)?;
    let file_name_zipped = &format!("{}{}.zip", output_dir_norm, file_stem);
    println!("\nencrypting {} ...", file_name_zipped);

    let mut source_file = File::open(file_name_zipped)?;
    let argon2_config = argon2_config();
    let mut salt = [0u8; 32];
    let mut nonce = [0u8; 19];
    OsRng.fill_bytes(&mut salt);
    OsRng.fill_bytes(&mut nonce);

    let mut key = argon2::hash_raw(passphrase.as_bytes(), &salt, &argon2_config)?;
    let aead = XChaCha20Poly1305::new(key[..32].as_ref().into());
    let mut stream_encryptor = stream::EncryptorBE32::from_aead(aead, nonce.as_ref().into());

    // Hash the encryption key for comparison when decrypting
    let key_hash_ref: [u8; 32] = sha3_hash(&key)?;

    // XChaCha20-Poly1305 is an AEAD cipher and appends a 16 bytes authentication tag to each encrypted message, so the buffer becomes 516 bits
    const BUFFER_LEN: usize = 500;
    let mut buffer = [0u8; BUFFER_LEN];
    let mut file_path_encrypted = OpenOptions::new()
        .write(true)
        .append(true)
        .create_new(true)
        .open(format!("{}{}.fcls", &output_dir_norm, file_stem))?;

    file_path_encrypted.write_all(&salt)?;
    file_path_encrypted.write_all(&nonce)?;
    file_path_encrypted.write_all(&key_hash_ref)?;

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
    let file_name_encrypted = &format!("{}{}.fcls", output_dir_norm, file_stem);
    println!();
    println!("encrypted to {}", file_name_encrypted);

    salt.zeroize();
    nonce.zeroize();
    key.zeroize();
    passphrase.zeroize();

    Ok(())
}

// Decrypt large file, that doesn't fit in RAM, with XChaCha20Poly1305 algorithm. This is much slower
pub fn decrypt_large_file(input_path: &str, output_dir: &str, passphrase: &mut str) -> Result<(), CryptoError> {
    let (input_path_norm, output_dir_norm) = normalize_paths(input_path, output_dir);

    if input_path_norm.ends_with(".fcls") {
        println!("decrypting {} ...\n", input_path);

        let mut salt = [0u8; 32];
        let mut nonce = [0u8; 19];
        let mut key_hash_ref = [0u8; 32];
        let mut encrypted_file = File::open(&input_path_norm)?;
        let mut read_count = encrypted_file.read(&mut salt)?;

        if read_count != salt.len() {
            return Err(Message("Error reading salt!".to_string()));
        }

        read_count = encrypted_file.read(&mut nonce)?;
        if read_count != nonce.len() {
            return Err(Message("Error reading nonce!".to_string()));
        }

        read_count = encrypted_file.read(&mut key_hash_ref)?;
        if read_count != key_hash_ref.len() {
            return Err(Message("Error reading key_hash_ref!".to_string()));
        }

        let argon2_config = argon2_config();
        let mut key = argon2::hash_raw(passphrase.as_bytes(), &salt, &argon2_config)?;
        let aead = XChaCha20Poly1305::new(key[..32].as_ref().into());
        let mut stream_decryptor = stream::DecryptorBE32::from_aead(aead, nonce.as_ref().into());

        // Hash the encryption key for comparison and compare it in constant time with the ref key hash
        let key_hash: [u8; 32] = sha3_hash(&key)?;
        let key_correct = constant_time_compare_256_bit(&key_hash, key_hash_ref[..32].try_into()?);

        if key_correct {
            let file_stem_decrypted = &get_file_stem_to_string(&input_path_norm)?;
            let decrypted_file_path = format!("{}{}.zip", output_dir_norm, file_stem_decrypted);
            let mut decrypted_file = OpenOptions::new()
                .write(true)
                .append(true)
                .create_new(true)
                .open(&decrypted_file_path)?;

            // 500 bytes for the encrypted piece of data, and 16 bytes for the authentication tag, which was added on encryption
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

            archiver::unarchive(&decrypted_file_path, &output_dir_norm)?;
            fs::remove_file(&decrypted_file_path)?;
            println!("\ndecrypted to {}", output_dir_norm);

            salt.zeroize();
            nonce.zeroize();
            key.zeroize();
            passphrase.zeroize();
        } else {
            return Err(Message("The provided password is incorrect!".to_string()));
        }
    } else {
        return Err(Message("This file should have '.fcls' extension!".to_string()));
    }

    Ok(())
}

fn argon2_config<'a>() -> argon2::Config<'a> {
    argon2::Config {
        variant: Variant::Argon2id,
        hash_length: 32,
        lanes: 8,
        mem_cost: 1 * 1024,
        time_cost: 8,
        ..Default::default()
    }
}
