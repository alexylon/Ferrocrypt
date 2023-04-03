use anyhow::anyhow;
use chacha20poly1305::{aead::{stream, KeyInit, OsRng}, {aead::rand_core::RngCore}, XChaCha20Poly1305};
use std::{
    fs::File,
    io::{Read, Write},
};
use zeroize::Zeroize;


#[cfg(test)]
mod tests {
    // use zeroize::Zeroize;
    use crate::symmetric::{decrypt_file, encrypt_file};

    const FILE_PATH: &str = "src/test_files/test-file.txt";
    const PASSPHRASE: &str = "strong_passphrase";

    #[test]
    fn encrypt_decrypt_file_test() -> Result<(), anyhow::Error> {
        // let mut password = rpassword::prompt_password("password:")?;

        if FILE_PATH.ends_with(".encrypted") {
            let dest_file_path = FILE_PATH.strip_suffix(".encrypted").unwrap().to_string() + ".decrypted";
            decrypt_file(&FILE_PATH, &dest_file_path, PASSPHRASE)?;
        } else {
            let dest_file_path = FILE_PATH.to_string() + ".encrypted";
            encrypt_file(&FILE_PATH, &dest_file_path, PASSPHRASE)?;
        }

        // password.zeroize();

        Ok(())
    }
}

// Encrypt file with XChaCha20Poly1305 algorithm
pub fn encrypt_file(source_file_path: &str, dest_file_path: &str, password: &str) -> Result<(), anyhow::Error> {
    let argon2_config = argon2_config();

    let mut salt = [0u8; 32];
    let mut nonce = [0u8; 19];
    OsRng.fill_bytes(&mut salt);
    OsRng.fill_bytes(&mut nonce);

    let mut key = argon2::hash_raw(password.as_bytes(), &salt, &argon2_config)?;

    let aead = XChaCha20Poly1305::new(key[..32].as_ref().into());
    let mut stream_encryptor = stream::EncryptorBE32::from_aead(aead, nonce.as_ref().into());

    const BUFFER_LEN: usize = 500;
    let mut buffer = [0u8; BUFFER_LEN];

    let mut source_file = File::open(source_file_path)?;
    let mut dest_file = File::create(dest_file_path)?;

    dest_file.write(&salt)?;
    dest_file.write(&nonce)?;

    loop {
        let read_count = source_file.read(&mut buffer)?;

        if read_count == BUFFER_LEN {
            let ciphertext = stream_encryptor
                .encrypt_next(buffer.as_slice())
                .map_err(|err| anyhow!("Encrypting large file: {}", err))?;
            dest_file.write(&ciphertext)?;
        } else {
            let ciphertext = stream_encryptor
                .encrypt_last(&buffer[..read_count])
                .map_err(|err| anyhow!("Encrypting large file: {}", err))?;
            dest_file.write(&ciphertext)?;
            break;
        }
    }

    salt.zeroize();
    nonce.zeroize();
    key.zeroize();

    Ok(())
}

// Decrypt file with XChaCha20Poly1305 algorithm
pub fn decrypt_file(source_file_path: &str, dest_file_path: &str, password: &str) -> Result<(), anyhow::Error> {
    let mut salt = [0u8; 32];
    let mut nonce = [0u8; 19];

    let mut encrypted_file = File::open(source_file_path)?;
    let mut dest_file = File::create(dest_file_path)?;

    let mut read_count = encrypted_file.read(&mut salt)?;
    if read_count != salt.len() {
        return Err(anyhow!("Error reading salt."));
    }

    read_count = encrypted_file.read(&mut nonce)?;
    if read_count != nonce.len() {
        return Err(anyhow!("Error reading nonce."));
    }

    let argon2_config = argon2_config();

    let mut key = argon2::hash_raw(password.as_bytes(), &salt, &argon2_config)?;

    let aead = XChaCha20Poly1305::new(key[..32].as_ref().into());
    let mut stream_decryptor = stream::DecryptorBE32::from_aead(aead, nonce.as_ref().into());

    const BUFFER_LEN: usize = 500 + 16;
    let mut buffer = [0u8; BUFFER_LEN];

    loop {
        let read_count = encrypted_file.read(&mut buffer)?;

        if read_count == BUFFER_LEN {
            let plaintext = stream_decryptor
                .decrypt_next(buffer.as_slice())
                .map_err(|err| anyhow!("Decrypting large file: {}", err))?;
            dest_file.write(&plaintext)?;
        } else if read_count == 0 {
            break;
        } else {
            let plaintext = stream_decryptor
                .decrypt_last(&buffer[..read_count])
                .map_err(|err| anyhow!("Decrypting large file: {}", err))?;
            dest_file.write(&plaintext)?;
            break;
        }
    }

    salt.zeroize();
    nonce.zeroize();
    key.zeroize();

    Ok(())
}

fn argon2_config<'a>() -> argon2::Config<'a> {
    return argon2::Config {
        variant: argon2::Variant::Argon2id,
        hash_length: 32,
        lanes: 8,
        mem_cost: 16 * 1024,
        time_cost: 8,
        ..Default::default()
    };
}
