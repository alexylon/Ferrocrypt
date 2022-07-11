mod aes_gcm;
mod rsa;

const FILE_PATH: &str = "src/test_files/test1.txt";
/// RSA-4096 PKCS#1 public key encoded as PEM
const RSA_4096_PUB_PEM: &str = include_str!("key_examples/rsa4096-pub.pem");
/// RSA-4096 PKCS#1 private key encoded as PEM
const RSA_4096_PRIV_PEM: &str = include_str!("key_examples/rsa4096-priv.pem");

fn main() {
    aes_gcm::encrypt_aes_gcm(FILE_PATH, RSA_4096_PUB_PEM);
    aes_gcm::decrypt_aes_gcm(&format!("{}_encrypted", FILE_PATH), RSA_4096_PRIV_PEM);
}
