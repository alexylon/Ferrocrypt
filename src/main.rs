mod crypto;

const FILE_PATH: &str = "src/test_files/test1.txt";
/// RSA-4096 PKCS#1 public key encoded as PEM
const RSA_4096_PUB_PEM: &str = include_str!("key_examples/rsa4096-pub.pem");
/// RSA-4096 PKCS#1 private key encoded as PEM
const RSA_4096_PRIV_PEM: &str = include_str!("key_examples/rsa4096-priv.pem");
// let priv_key = RsaPrivateKey::from_pkcs1_der(RSA_4096_PRIV_DER).unwrap();
// let pub_key = RsaPublicKey::from_pkcs1_der(RSA_4096_PUB_DER).unwrap();

fn main() {
    crypto::encrypt_aes_gcm(FILE_PATH, RSA_4096_PUB_PEM);
    crypto::decrypt_aes_gcm(&format!("{}_encrypted", FILE_PATH), RSA_4096_PRIV_PEM);
}
