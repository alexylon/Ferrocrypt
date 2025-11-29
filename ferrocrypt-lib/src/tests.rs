#[cfg(test)]
mod ferrocrypt_tests {
    use std::fs;

    use secrecy::SecretString;

    use crate::{hybrid_encryption, symmetric_encryption};
    use crate::error::CryptoError;
    use crate::hybrid::generate_asymmetric_key_pair;

    const SRC_FILE_PATH: &str = "src/test_files/test-file.txt";
    const ENCRYPTED_FILE_PATH_SYM: &str = "src/dest/test-file.fcs";
    const ENCRYPTED_LARGE_FILE_PATH_SYM: &str = "src/dest_large/test-file.fcs";
    const DEST_DIR_PATH: &str = "src/dest/";
    const DEST_DIR_PATH_LARGE: &str = "src/dest_large/";
    const DEST_DIR_PATH_HYB: &str = "src/dest_hyb/";
    const SRC_DIR_PATH: &str = "src/test_files/test-folder";
    const ENCRYPTED_DIR_PATH_SYM: &str = "src/dest/test-folder.fcs";
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
        let passphrase = SecretString::from(PASSPHRASE.to_string());
        symmetric_encryption(SRC_FILE_PATH, DEST_DIR_PATH, &passphrase, false)?;
        Ok(())
    }

    #[test]
    fn symmetric_decrypt_file_test() -> Result<(), CryptoError> {
        let passphrase = SecretString::from(PASSPHRASE.to_string());
        symmetric_encryption(ENCRYPTED_FILE_PATH_SYM, DEST_DIR_PATH, &passphrase, false)?;
        Ok(())
    }

    #[test]
    fn symmetric_encrypt_large_file_test() -> Result<(), CryptoError> {
        fs::create_dir_all(DEST_DIR_PATH_LARGE)?;
        let passphrase = SecretString::from(PASSPHRASE.to_string());
        symmetric_encryption(SRC_FILE_PATH, DEST_DIR_PATH_LARGE, &passphrase, true)?;
        Ok(())
    }

    #[test]
    fn symmetric_decrypt_large_file_test() -> Result<(), CryptoError> {
        let passphrase = SecretString::from(PASSPHRASE.to_string());
        symmetric_encryption(ENCRYPTED_LARGE_FILE_PATH_SYM, DEST_DIR_PATH_LARGE, &passphrase, true)?;
        Ok(())
    }

    #[test]
    fn symmetric_encrypt_dir_test() -> Result<(), CryptoError> {
        fs::create_dir_all(DEST_DIR_PATH)?;
        let passphrase = SecretString::from(PASSPHRASE.to_string());
        symmetric_encryption(SRC_DIR_PATH, DEST_DIR_PATH, &passphrase, false)?;
        Ok(())
    }

    #[test]
    fn symmetric_decrypt_dir_test() -> Result<(), CryptoError> {
        let passphrase = SecretString::from(PASSPHRASE.to_string());
        symmetric_encryption(ENCRYPTED_DIR_PATH_SYM, DEST_DIR_PATH, &passphrase, false)?;
        Ok(())
    }

    #[test]
    fn hybrid_encrypt_decrypt_file_test() -> Result<(), CryptoError> {
        fs::create_dir_all(DEST_DIR_PATH_HYB)?;
        let mut rsa_priv_pem = RSA_PRIV_PEM.to_string();
        let mut rsa_pub_pem = RSA_PUB_PEM.to_string();
        let passphrase = SecretString::from(PASSPHRASE.to_string());
        hybrid_encryption(SRC_FILE_PATH, DEST_DIR_PATH_HYB, &mut rsa_pub_pem, &passphrase)?;
        hybrid_encryption(ENCRYPTED_FILE_PATH_HYB, DEST_DIR_PATH_HYB, &mut rsa_priv_pem, &passphrase)?;

        let file_original = fs::read_to_string(SRC_FILE_PATH)?;
        let file_decrypted = fs::read_to_string(DECRYPTED_FILE_PATH_HYB)?;

        assert_eq!(file_original, file_decrypted);
        Ok(())
    }

    #[test]
    fn hybrid_encrypt_file_test() -> Result<(), CryptoError> {
        fs::create_dir_all(DEST_DIR_PATH_HYB)?;
        let mut rsa_pub_pem = RSA_PUB_PEM.to_string();
        let passphrase = SecretString::from(PASSPHRASE.to_string());
        hybrid_encryption(SRC_FILE_PATH, DEST_DIR_PATH_HYB, &mut rsa_pub_pem, &passphrase)?;
        Ok(())
    }

    #[test]
    fn hybrid_decrypt_file_test() -> Result<(), CryptoError> {
        let mut rsa_priv_pem = RSA_PRIV_PEM.to_string();
        let passphrase = SecretString::from(PASSPHRASE.to_string());
        hybrid_encryption(ENCRYPTED_FILE_PATH_HYB, DEST_DIR_PATH_HYB, &mut rsa_priv_pem, &passphrase)?;
        Ok(())
    }

    #[test]
    fn hybrid_encrypt_dir_test() -> Result<(), CryptoError> {
        fs::create_dir_all(DEST_DIR_PATH_HYB)?;
        let mut rsa_pub_pem = RSA_PUB_PEM.to_string();
        let passphrase = SecretString::from(PASSPHRASE.to_string());
        hybrid_encryption(SRC_DIR_PATH, DEST_DIR_PATH_HYB, &mut rsa_pub_pem, &passphrase)?;
        Ok(())
    }

    #[test]
    fn hybrid_decrypt_dir_test() -> Result<(), CryptoError> {
        fs::create_dir_all(DEST_DIR_PATH_HYB)?;
        let mut rsa_priv_pem = RSA_PRIV_PEM.to_string();
        let passphrase = SecretString::from(PASSPHRASE.to_string());
        hybrid_encryption(ENCRYPTED_DIR_PATH_HYB, DEST_DIR_PATH_HYB, &mut rsa_priv_pem, &passphrase)?;
        Ok(())
    }

    #[test]
    fn hybrid_generate_key_pair_test() -> Result<(), CryptoError> {
        fs::create_dir_all(DEST_DIR_PATH_HYB)?;
        let passphrase = SecretString::from("test".to_string());
        generate_asymmetric_key_pair(4096, &passphrase, DEST_DIR_PATH_HYB)?;
        Ok(())
    }
}
