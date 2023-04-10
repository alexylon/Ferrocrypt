use chacha20poly1305::{aead::{stream, KeyInit, OsRng}, {aead::rand_core::RngCore}, XChaCha20Poly1305};
use std::{fs, fs::File, io::{Read, Write}};
use std::fs::OpenOptions;
use argon2::Variant;
use chacha20poly1305::aead::Aead;
use zeroize::Zeroize;
use crate::{archiver, CryptoError};
use crate::common::{constant_time_compare_256_bit, get_file_stem_to_string, normalize_paths, sha3_hash};
use crate::CryptoError::{ChaCha20Poly1305Error, Message};


#[cfg(test)]
mod tests {
    use std::fs;
    use crate::CryptoError;
    // use zeroize::Zeroize;
    use crate::symmetric::{decrypt_file, encrypt_file};

    const SRC_FILE_PATH: &str = "src/test_files/test-archive.zip";
    const SRC_DIR_PATH: &str = "src/test_files/test-folder";
    const ENCRYPTED_FILE_PATH: &str = "src/dest/test-archive.fcs";
    const ENCRYPTED_DIR_PATH: &str = "src/dest/test-folder.fcs";
    const ENCRYPTED_LARGE_FILE_PATH: &str = "src/dest/test-archive.fcls";
    const DEST_DIR_PATH: &str = "src/dest/";
    const PASSPHRASE: &str = "strong_passphrase";

    #[test]
    fn encrypt_file_test() -> Result<(), CryptoError> {
        fs::create_dir_all("src/dest")?;
        // let mut passphrase = rpassword::prompt_password("passphrase:")?;
        let mut passphrase = PASSPHRASE.to_string();
        encrypt_file(SRC_FILE_PATH, DEST_DIR_PATH, &mut passphrase, false)?;

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
        encrypt_file(SRC_DIR_PATH, DEST_DIR_PATH, &mut passphrase, false)?;

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
        encrypt_file(SRC_FILE_PATH, DEST_DIR_PATH, &mut passphrase, true)?;

        // passphrase.zeroize();

        Ok(())
    }

    #[test]
    fn decrypt_large_file_test() -> Result<(), CryptoError> {
        // let mut password = rpassword::prompt_password("password:")?;
        let mut passphrase = "strong_passphrase".to_string();
        decrypt_file(ENCRYPTED_LARGE_FILE_PATH, DEST_DIR_PATH, &mut passphrase)?;

        // password.zeroize();

        Ok(())
    }
}

// Encrypt file with XChaCha20Poly1305 algorithm
pub fn encrypt_file(input_path: &str, output_dir: &str, passphrase: &mut str, large: bool) -> Result<(), CryptoError> {
    let (input_path_norm, output_dir_norm) = normalize_paths(input_path, output_dir);
    let tmp_dir_path = &format!("{}zp_tmp/", output_dir_norm);
    fs::create_dir_all(tmp_dir_path)?;
    let file_stem = &archiver::archive(&input_path_norm, tmp_dir_path)?;
    let file_name_zipped = &format!("{}{}.zip", tmp_dir_path, file_stem);
    println!("\nencrypting {} ...", file_name_zipped);

    let argon2_config = argon2_config();
    let mut salt = [0u8; 32];
    OsRng.fill_bytes(&mut salt);

    let mut key = argon2::hash_raw(passphrase.as_bytes(), &salt, &argon2_config)?;
    let cipher = XChaCha20Poly1305::new(key[..32].as_ref().into());

    // Hash the encryption key for comparison when decrypting
    let key_hash_ref: [u8; 32] = sha3_hash(&key)?;

    let encr_ext = if !large { "fcs" } else { "fcls" };

    let mut file_path_encrypted = OpenOptions::new()
        .write(true)
        .append(true)
        .create_new(true)
        .open(format!("{}{}.{}", &output_dir_norm, file_stem, encr_ext))?;


    if !large {
        let mut nonce_24 = [0u8; 24];
        OsRng.fill_bytes(&mut nonce_24);

        let source_file = fs::read(file_name_zipped)?;
        let ciphertext = cipher.encrypt(nonce_24.as_ref().into(), &*source_file)?;

        file_path_encrypted.write_all(&salt)?;
        file_path_encrypted.write_all(&nonce_24)?;
        file_path_encrypted.write_all(&key_hash_ref)?;
        file_path_encrypted.write_all(&ciphertext)?;

        nonce_24.zeroize();
    } else {
        let mut nonce_19 = [0u8; 19];
        OsRng.fill_bytes(&mut nonce_19);

        let mut stream_encryptor = stream::EncryptorBE32::from_aead(cipher, nonce_19.as_ref().into());

        // XChaCha20-Poly1305 is an AEAD cipher and appends a 16 bytes authentication tag to each encrypted message, so the buffer becomes 516 bits
        const BUFFER_LEN: usize = 500;
        let mut buffer = [0u8; BUFFER_LEN];

        file_path_encrypted.write_all(&salt)?;
        file_path_encrypted.write_all(&nonce_19)?;
        file_path_encrypted.write_all(&key_hash_ref)?;

        let mut source_file = File::open(file_name_zipped)?;
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

        nonce_19.zeroize();
    }

    fs::remove_dir_all(tmp_dir_path)?;

    let file_name_encrypted = &format!("{}{}.{}", output_dir_norm, file_stem, encr_ext);
    println!("\nencrypted to {}", file_name_encrypted);

    salt.zeroize();
    key.zeroize();
    passphrase.zeroize();

    Ok(())
}

pub fn decrypt_file(input_path: &str, output_dir: &str, passphrase: &mut str) -> Result<(), CryptoError> {
    let (input_path_norm, output_dir_norm) = normalize_paths(input_path, output_dir);

    if input_path_norm.ends_with(".fcs") {
        decrypt_normal_file(&input_path_norm, &output_dir_norm, passphrase)?;
    } else if input_path_norm.ends_with(".fcls") {
        decrypt_large_file(&input_path_norm, &output_dir_norm, passphrase)?;
    }

    println!("\ndecrypted to {}", output_dir_norm);

    Ok(())
}

// Decrypt file with XChaCha20Poly1305 algorithm
fn decrypt_normal_file(input_path: &str, output_dir: &str, passphrase: &mut str) -> Result<(), CryptoError> {
    if input_path.ends_with(".fcs") {
        println!("decrypting {} ...\n", input_path);

        let salt_len = 32;
        let nonce_len = 24;
        let key_hash_ref_len = 32;
        let encrypted_file: Vec<u8> = fs::read(input_path)?;

        // Split the salt, nonce and the encrypted file
        let (salt, rem_data) = encrypted_file.split_at(salt_len);
        let (nonce_24, rem_data) = rem_data.split_at(nonce_len);
        let (key_hash_ref, ciphertext) = rem_data.split_at(key_hash_ref_len);

        let argon2_config = argon2_config();
        let mut key = argon2::hash_raw(passphrase.as_bytes(), salt, &argon2_config)?;

        // Hash the encryption key for comparison and compare it in constant time with the ref key hash
        let key_hash: [u8; 32] = sha3_hash(&key)?;
        let key_correct = constant_time_compare_256_bit(&key_hash, key_hash_ref[..32].try_into()?);

        if key_correct {
            let tmp_dir_path = &format!("{}zp_tmp/", output_dir);
            fs::create_dir_all(tmp_dir_path)?;
            let cipher = XChaCha20Poly1305::new(key[..32].as_ref().into());
            let plaintext = cipher.decrypt(nonce_24.as_ref().into(), ciphertext.as_ref())?;
            let file_stem_decrypted = &get_file_stem_to_string(input_path)?;
            let decrypted_file_path: String = format!("{}{}.zip", tmp_dir_path, file_stem_decrypted);

            File::create(&decrypted_file_path)?;
            fs::write(&decrypted_file_path, plaintext)?;
            archiver::unarchive(&decrypted_file_path, output_dir)?;

            key.zeroize();
            passphrase.zeroize();

            fs::remove_dir_all(tmp_dir_path)?;
        } else {
            return Err(Message("The provided password is incorrect!".to_string()));
        }
    } else {
        return Err(Message("This file should have '.fcs' extension!".to_string()));
    }

    Ok(())
}

// Decrypt large file, that doesn't fit in RAM, with XChaCha20Poly1305 algorithm. This is much slower
fn decrypt_large_file(input_path: &str, output_dir: &str, passphrase: &mut str) -> Result<(), CryptoError> {
    if input_path.ends_with(".fcls") {
        println!("decrypting {} ...\n", input_path);

        let mut salt = [0u8; 32];
        let mut nonce_19 = [0u8; 19];
        let mut key_hash_ref = [0u8; 32];
        let mut encrypted_file = File::open(input_path)?;
        let mut read_count = encrypted_file.read(&mut salt)?;

        if read_count != salt.len() {
            return Err(Message("Error reading salt!".to_string()));
        }

        read_count = encrypted_file.read(&mut nonce_19)?;
        if read_count != nonce_19.len() {
            return Err(Message("Error reading nonce!".to_string()));
        }

        read_count = encrypted_file.read(&mut key_hash_ref)?;
        if read_count != key_hash_ref.len() {
            return Err(Message("Error reading key_hash_ref!".to_string()));
        }

        let argon2_config = argon2_config();
        let mut key = argon2::hash_raw(passphrase.as_bytes(), &salt, &argon2_config)?;

        // Hash the encryption key for comparison and compare it in constant time with the ref key hash
        let key_hash: [u8; 32] = sha3_hash(&key)?;
        let key_correct = constant_time_compare_256_bit(&key_hash, key_hash_ref[..32].try_into()?);

        if key_correct {
            let tmp_dir_path = &format!("{}zp_tmp/", output_dir);
            fs::create_dir_all(tmp_dir_path)?;
            let cipher = XChaCha20Poly1305::new(key[..32].as_ref().into());
            let mut stream_decryptor = stream::DecryptorBE32::from_aead(cipher, nonce_19.as_ref().into());
            let file_stem_decrypted = &get_file_stem_to_string(input_path)?;
            let decrypted_file_path = format!("{}{}.zip", tmp_dir_path, file_stem_decrypted);
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

            archiver::unarchive(&decrypted_file_path, output_dir)?;

            key.zeroize();
            passphrase.zeroize();

            fs::remove_dir_all(tmp_dir_path)?;
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
        mem_cost: 1024,
        time_cost: 8,
        ..Default::default()
    }
}
