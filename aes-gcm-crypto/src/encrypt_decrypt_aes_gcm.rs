use aes_gcm::{Aes256Gcm, Key, Nonce};
// Or `Aes128Gcm`
use aes_gcm::aead::{Aead, NewAead};
use std::str;
use chrono::prelude::*;

pub fn encrypt_decrypt_aes_gcm() {
    let key_str = "an example very very secret key!"; // 256-bit
    let key = Key::from_slice(key_str.as_bytes());
    let cipher = Aes256Gcm::new(key);

    // Generate unique 96-bits nonce from current UTC time
    let utc: DateTime<Utc> = Utc::now();
    let utc_fmt = utc.format("%y%m%d%H%M%S").to_string(); // The string must be 32-bytes (96-bits)
    let nonce = Nonce::from_slice(utc_fmt.as_bytes()); // 96-bits; unique per message

    let message = "plaintext message";

    let ciphertext = cipher.encrypt(nonce, message.as_bytes())
        .expect("encryption failure!"); // NOTE: handle this error to avoid panics!

    let plaintext = cipher.decrypt(nonce, ciphertext.as_ref())
        .expect("decryption failure!"); // NOTE: handle this error to avoid panics!

    let my_str = str::from_utf8(&plaintext).unwrap();

    assert_eq!(&plaintext, b"plaintext message");

    println!("message: {}", message);
    println!("nonce: {:?}", nonce);
    println!("ciphertext: {:?}", ciphertext);
    println!("plaintext: {:?}", plaintext);
    println!("decrypted: {}", my_str);

    // The result of the encryption stored/sent is nonce, ciphertext, mac
    // In reality - for simpler applications very often we see the encryption output
    // composed as IV (nonce) || ciphertext || MAC (as concatenation) for AES.
    // AEAD mode, based on AES, such as AES-GCM or AES-GCM-SIV, does not need a MAC to verify ciphertext integrity
    // IV (nonce) and MAC are having fixed length,
    // so you can cut them out and use the parameters for decryption.

    // The nonce is an acronym for 'number used once'.
    // The crucial point is that one must **never use the (Key, nonce) pair again**.
    // We call it nonce-misuse. If it occurs, the confidentiality is lost
    // as the attacker can use the crib-dragging technique to reveal the two plaintexts

    // See rules and Java examples at https://gusto77.wordpress.com/2017/10/30/encryption-reference-project/

    // Rules to follow:
    // don’t invent your own crypto !!!!!!!
    // password is not key
    // cut one of your fingers for each time you reuse a nonce
    // treat unauthenticated ciphertext as nuclear waste
}