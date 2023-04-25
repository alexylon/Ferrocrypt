#[cfg(test)]
mod ferrocrypt_tests {
    use std::fs;
    use crate::{hybrid_encryption, symmetric_encryption};
    use crate::error::CryptoError;
    use crate::hybrid::generate_asymmetric_key_pair;
    // use zeroize::Zeroize;

    const SRC_FILE_PATH: &str = "src/test_files/test-file.txt";
    const ENCRYPTED_FILE_PATH_SYM: &str = "src/dest/test-file.fcv";
    const ENCRYPTED_LARGE_FILE_PATH_SYM: &str = "src/dest_large/test-file.fcv";
    const DEST_DIR_PATH: &str = "src/dest/";
    const DEST_DIR_PATH_LARGE: &str = "src/dest_large/";
    const DEST_DIR_PATH_HYB: &str = "src/dest_hyb/";
    const SRC_DIR_PATH: &str = "src/test_files/test-folder";
    const ENCRYPTED_DIR_PATH_SYM: &str = "src/dest/test-folder.fcv";
    const ENCRYPTED_FILE_PATH_HYB: &str = "src/dest_hyb/test-file.fch";
    const DECRYPTED_FILE_PATH_HYB: &str = "src/dest_hyb/test-file.txt";
    const ENCRYPTED_DIR_PATH_HYB: &str = "src/dest_hyb/test-folder.fch";
    const PASSPHRASE: &str = "strong_passphrase";
    // RSA-4096 PKCS#1 public key encoded as PEM
    const RSA_PUB_PEM: &str = "src/key_examples/rsa-4096-pub-key.pem";
    // RSA-4096 PKCS#1 private key encoded as PEM
    const RSA_PRIV_PEM: &str = "src/key_examples/rsa-4096-priv-key.pem";

    #[test]
    fn symmetric_encrypt_file_test() -> Result<(), CryptoError> {
        fs::create_dir_all(DEST_DIR_PATH)?;
        // let mut passphrase = rpassword::prompt_password("passphrase:")?;
        let mut passphrase = PASSPHRASE.to_string();
        symmetric_encryption(SRC_FILE_PATH, DEST_DIR_PATH, &mut passphrase, false)?;

        // passphrase.zeroize();

        Ok(())
    }

    #[test]
    fn symmetric_decrypt_file_test() -> Result<(), CryptoError> {
        // let mut password = rpassword::prompt_password("password:")?;
        let mut passphrase = PASSPHRASE.to_string();
        symmetric_encryption(ENCRYPTED_FILE_PATH_SYM, DEST_DIR_PATH, &mut passphrase, false)?;

        // password.zeroize();

        Ok(())
    }

    #[test]
    fn symmetric_encrypt_large_file_test() -> Result<(), CryptoError> {
        fs::create_dir_all(DEST_DIR_PATH_LARGE)?;
        // let mut passphrase = rpassword::prompt_password("passphrase:")?;
        let mut passphrase = PASSPHRASE.to_string();
        symmetric_encryption(SRC_FILE_PATH, DEST_DIR_PATH_LARGE, &mut passphrase, true)?;

        // passphrase.zeroize();

        Ok(())
    }

    #[test]
    fn symmetric_decrypt_large_file_test() -> Result<(), CryptoError> {
        // let mut password = rpassword::prompt_password("password:")?;
        let mut passphrase = "strong_passphrase".to_string();
        symmetric_encryption(ENCRYPTED_LARGE_FILE_PATH_SYM, DEST_DIR_PATH_LARGE, &mut passphrase, true)?;

        // password.zeroize();

        Ok(())
    }

    #[test]
    fn symmetric_encrypt_dir_test() -> Result<(), CryptoError> {
        fs::create_dir_all("src/dest")?;
        // let mut passphrase = rpassword::prompt_password("passphrase:")?;
        let mut passphrase = PASSPHRASE.to_string();
        symmetric_encryption(SRC_DIR_PATH, DEST_DIR_PATH, &mut passphrase, false)?;

        // passphrase.zeroize();

        Ok(())
    }

    #[test]
    fn symmetric_decrypt_dir_test() -> Result<(), CryptoError> {
        // let mut password = rpassword::prompt_password("password:")?;
        let mut passphrase = PASSPHRASE.to_string();
        symmetric_encryption(ENCRYPTED_DIR_PATH_SYM, DEST_DIR_PATH, &mut passphrase, false)?;

        // password.zeroize();

        Ok(())
    }

    #[test]
    fn hybrid_encrypt_decrypt_file_test() {
        fs::create_dir_all(DEST_DIR_PATH_HYB).unwrap();
        let mut rsa_priv_pem = RSA_PRIV_PEM.to_string();
        let mut rsa_pub_pem = RSA_PUB_PEM.to_string();
        let mut passphrase = PASSPHRASE.to_string();
        hybrid_encryption(SRC_FILE_PATH, DEST_DIR_PATH_HYB, &mut rsa_pub_pem, &mut passphrase).unwrap();
        hybrid_encryption(ENCRYPTED_FILE_PATH_HYB, DEST_DIR_PATH_HYB, &mut rsa_priv_pem, &mut passphrase).unwrap();

        let file_original = fs::read_to_string(SRC_FILE_PATH).unwrap();
        let file_decrypted = fs::read_to_string(DECRYPTED_FILE_PATH_HYB).unwrap();

        assert_eq!(file_original, file_decrypted);
    }

    #[test]
    fn hybrid_encrypt_file_test() {
        fs::create_dir_all(DEST_DIR_PATH_HYB).unwrap();
        let mut rsa_pub_pem = RSA_PUB_PEM.to_string();
        let mut passphrase = PASSPHRASE.to_string();
        hybrid_encryption(SRC_FILE_PATH, DEST_DIR_PATH_HYB, &mut rsa_pub_pem, &mut passphrase).unwrap();
    }

    #[test]
    fn hybrid_decrypt_file_test() {
        let mut rsa_priv_pem = RSA_PRIV_PEM.to_string();
        let mut passphrase = PASSPHRASE.to_string();
        hybrid_encryption(ENCRYPTED_FILE_PATH_HYB, DEST_DIR_PATH_HYB, &mut rsa_priv_pem, &mut passphrase).unwrap();
    }

    #[test]
    fn hybrid_encrypt_dir_test() {
        fs::create_dir_all(DEST_DIR_PATH_HYB).unwrap();
        let mut rsa_pub_pem = RSA_PUB_PEM.to_string();
        let mut passphrase = PASSPHRASE.to_string();
        hybrid_encryption(SRC_DIR_PATH, DEST_DIR_PATH_HYB, &mut rsa_pub_pem, &mut passphrase).unwrap();
    }

    #[test]
    fn hybrid_decrypt_dir_test() {
        fs::create_dir_all(DEST_DIR_PATH_HYB).unwrap();
        let mut rsa_priv_pem = RSA_PRIV_PEM.to_string();
        let mut passphrase = PASSPHRASE.to_string();
        hybrid_encryption(ENCRYPTED_DIR_PATH_HYB, DEST_DIR_PATH_HYB, &mut rsa_priv_pem, &mut passphrase).unwrap();
    }

    #[test]
    fn hybrid_generate_key_pair_test() {
        fs::create_dir_all(DEST_DIR_PATH_HYB).unwrap();
        let passphrase = "test";
        generate_asymmetric_key_pair(4096, passphrase, DEST_DIR_PATH_HYB).unwrap();
    }
}
