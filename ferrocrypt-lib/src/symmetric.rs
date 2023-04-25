use chacha20poly1305::{aead::{stream, KeyInit, OsRng}, {aead::rand_core::RngCore}, XChaCha20Poly1305};
use std::{fs, fs::File, io::{Read, Write}};
use std::fs::{OpenOptions, read};
use argon2::Variant;
use chacha20poly1305::aead::Aead;
use zeroize::Zeroize;
use crate::{archiver, CryptoError};
use crate::common::{constant_time_compare_256_bit, get_file_stem_to_string, sha3_32_hash};
use crate::CryptoError::{ChaCha20Poly1305Error, EncryptionDecryptionError, Message};
use crate::reed_solomon::{rs_encode, rs_decode};

// Encrypt file with XChaCha20Poly1305 algorithm
pub fn encrypt_file(input_path: &str, output_dir: &str, passphrase: &mut str, large: bool, tmp_dir_path: &str) -> Result<String, CryptoError> {
    let start_time = std::time::Instant::now();

    // Header information for decryption
    let mut flags: [bool; 4] = [false, false, false, false];
    if large { flags[0] = true; }
    let serialized_flags: Vec<u8> = bincode::serialize(&flags)?;

    let argon2_config = argon2_config();
    let mut salt_32 = [0u8; 32];
    OsRng.fill_bytes(&mut salt_32);

    let mut key = argon2::hash_raw(passphrase.as_bytes(), &salt_32, &argon2_config)?;
    let cipher = XChaCha20Poly1305::new(key[..32].as_ref().into());

    // Hash the encryption key for comparison when decrypting
    let key_hash_ref: [u8; 32] = sha3_32_hash(&key)?;

    let encrypted_extension = "fcs";
    let file_stem = &archiver::archive(input_path, tmp_dir_path)?;
    let zipped_file_name = &format!("{}{}.zip", tmp_dir_path, file_stem);
    println!("\nEncrypting {} ...", zipped_file_name);

    let mut encrypted_file_path = OpenOptions::new()
        .write(true)
        .append(true)
        .create_new(true)
        .open(format!("{}{}.{}", &output_dir, file_stem, encrypted_extension))?;


    // Encode with reed-solomon. The resulting size is three times that of the original
    let encoded_salt_32: Vec<u8> = rs_encode(&salt_32)?;
    let encoded_key_hash_ref: Vec<u8> = rs_encode(&key_hash_ref)?;

    if !large {
        let mut nonce_24 = [0u8; 24];
        OsRng.fill_bytes(&mut nonce_24);

        let encoded_nonce_24: Vec<u8> = rs_encode(&nonce_24)?;
        let zipped_file = read(zipped_file_name)?;
        let ciphertext = cipher.encrypt(nonce_24.as_ref().into(), &*zipped_file)?;

        encrypted_file_path.write_all(&serialized_flags)?;
        encrypted_file_path.write_all(&encoded_salt_32)?;
        encrypted_file_path.write_all(&encoded_nonce_24)?;
        encrypted_file_path.write_all(&encoded_key_hash_ref)?;
        encrypted_file_path.write_all(&ciphertext)?;
    } else {
        let mut nonce_19 = [0u8; 19];
        OsRng.fill_bytes(&mut nonce_19);
        let encoded_nonce_19: Vec<u8> = rs_encode(&nonce_19)?;
        let mut stream_encryptor = stream::EncryptorBE32::from_aead(cipher, nonce_19.as_ref().into());

        // XChaCha20-Poly1305 is an AEAD cipher and appends a 16 bytes authentication tag to each encrypted message, so the buffer becomes 516 bits
        const BUFFER_LEN: usize = 500;
        let mut buffer = [0u8; BUFFER_LEN];

        encrypted_file_path.write_all(&serialized_flags)?;
        encrypted_file_path.write_all(&encoded_salt_32)?;
        encrypted_file_path.write_all(&encoded_nonce_19)?;
        encrypted_file_path.write_all(&encoded_key_hash_ref)?;

        let mut source_file = File::open(zipped_file_name)?;
        loop {
            let read_count = source_file.read(&mut buffer)?;

            if read_count == BUFFER_LEN {
                let ciphertext = stream_encryptor
                    .encrypt_next(buffer.as_slice())
                    .map_err(ChaCha20Poly1305Error)?;
                encrypted_file_path.write_all(&ciphertext)?;
            } else {
                let ciphertext = stream_encryptor
                    .encrypt_last(&buffer[..read_count])
                    .map_err(ChaCha20Poly1305Error)?;
                encrypted_file_path.write_all(&ciphertext)?;
                break;
            }
        }
    }

    let encrypted_file_name = &format!("{}{}.{}", output_dir, file_stem, encrypted_extension);
    let result = format!("Encrypted to {}", encrypted_file_name);
    println!("\n{}", result);
    println!("\nEncryption elapsed: {}s", start_time.elapsed().as_secs_f64());

    key.zeroize();
    passphrase.zeroize();

    Ok(result)
}

pub fn decrypt_file(input_path: &str, output_dir: &str, passphrase: &mut str, tmp_dir_path: &str) -> Result<String, CryptoError> {
    let t0 = std::time::Instant::now();
    let file_bytes = read(input_path)?;
    let flags: [bool; 4] = bincode::deserialize(&file_bytes[..4])?;

    if flags[0] {
        decrypt_large_file(input_path, output_dir, passphrase, tmp_dir_path)?;
    } else {
        decrypt_normal_file(input_path, output_dir, passphrase, tmp_dir_path)?;
    }

    let result = format!("Decrypted to {}", output_dir);
    println!("\n{}", result);
    println!("\nDecryption elapsed: {}s", t0.elapsed().as_secs_f64());

    Ok(result)
}

// Decrypt file with XChaCha20Poly1305 algorithm
fn decrypt_normal_file(input_path: &str, output_dir: &str, passphrase: &mut str, tmp_dir_path: &str) -> Result<(), CryptoError> {
    println!("Decrypting {} ...\n", input_path);
    let encrypted_file: Vec<u8> = read(input_path)?;

    // Split salt, nonce, key hash and the encrypted file, and reconstruct with reed-solomon
    let (serialized_flags, rem_data) = encrypted_file.split_at(4);
    let _flags: [bool; 4] = bincode::deserialize(serialized_flags)?;
    let (encoded_salt_32, rem_data) = rem_data.split_at(96);
    let (encoded_nonce_24, rem_data) = rem_data.split_at(72);
    let (encoded_key_hash_ref, ciphertext) = rem_data.split_at(96);

    let salt_32 = rs_decode(encoded_salt_32)?;
    let nonce_24 = rs_decode(encoded_nonce_24)?;
    let key_hash_ref = rs_decode(encoded_key_hash_ref)?;

    let argon2_config = argon2_config();
    let mut key = argon2::hash_raw(passphrase.as_bytes(), &salt_32[0..32], &argon2_config)?;

    // Hash the encryption key for comparison and compare it in constant time with the ref key hash
    let key_hash: [u8; 32] = sha3_32_hash(&key)?;
    let key_correct = constant_time_compare_256_bit(&key_hash, key_hash_ref[0..32].try_into()?);

    if key_correct {
        let cipher = XChaCha20Poly1305::new(key[..32].as_ref().into());
        let plaintext: Vec<u8> = cipher.decrypt(nonce_24[0..24].as_ref().into(), ciphertext.as_ref())?;
        let decrypted_file_stem = &get_file_stem_to_string(input_path)?;
        let decrypted_file_path: String = format!("{}{}.zip", tmp_dir_path, decrypted_file_stem);

        File::create(&decrypted_file_path)?;
        fs::write(&decrypted_file_path, plaintext)?;
        archiver::unarchive(&decrypted_file_path, output_dir)?;

        key.zeroize();
        passphrase.zeroize();
    } else {
        return Err(EncryptionDecryptionError { msg: "The provided password is incorrect".to_string() });
    }

    Ok(())
}

// Decrypt large file, that doesn't fit in RAM, with XChaCha20Poly1305 algorithm. This is much slower
fn decrypt_large_file(input_path: &str, output_dir: &str, passphrase: &mut str, tmp_dir_path: &str) -> Result<(), CryptoError> {
    println!("Decrypting {} ...\n", input_path);

    let mut serialized_flags = [0u8; 4];
    let mut encoded_salt_32 = [0u8; 96];
    let mut encoded_nonce_19 = [0u8; 57];
    let mut encoded_key_hash_ref = [0u8; 96];
    let mut encrypted_file = File::open(input_path)?;

    let mut read_count = encrypted_file.read(&mut serialized_flags)?;
    if read_count != serialized_flags.len() {
        return Err(Message("Error reading flags!".to_string()));
    }
    let _flags: [bool; 4] = bincode::deserialize(&serialized_flags)?;

    read_count = encrypted_file.read(&mut encoded_salt_32)?;
    if read_count != encoded_salt_32.len() {
        return Err(Message("Error reading salt!".to_string()));
    }

    read_count = encrypted_file.read(&mut encoded_nonce_19)?;
    if read_count != encoded_nonce_19.len() {
        return Err(Message("Error reading nonce!".to_string()));
    }

    read_count = encrypted_file.read(&mut encoded_key_hash_ref)?;
    if read_count != encoded_key_hash_ref.len() {
        return Err(Message("Error reading key_hash_ref!".to_string()));
    }

    let salt_32 = rs_decode(&encoded_salt_32)?;
    let nonce_19: Vec<u8> = rs_decode(&encoded_nonce_19)?;
    let key_hash_ref = rs_decode(&encoded_key_hash_ref)?;

    let argon2_config = argon2_config();
    let mut key = argon2::hash_raw(passphrase.as_bytes(), &salt_32, &argon2_config)?;

    // Hash the encryption key for comparison and compare it in constant time with the ref key hash
    let key_hash: [u8; 32] = sha3_32_hash(&key)?;
    let key_correct = constant_time_compare_256_bit(&key_hash, key_hash_ref[..32].try_into()?);

    if key_correct {
        let cipher = XChaCha20Poly1305::new(key[..32].as_ref().into());
        let mut stream_decryptor = stream::DecryptorBE32::from_aead(cipher, nonce_19[..19].as_ref().into());
        let decrypted_file_stem = &get_file_stem_to_string(input_path)?;
        let decrypted_file_path = format!("{}{}.zip", tmp_dir_path, decrypted_file_stem);
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
    } else {
        return Err(Message("The provided password is incorrect!".to_string()));
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
