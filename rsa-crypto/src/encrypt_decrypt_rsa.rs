extern crate rsa;
extern crate hex;

use rsa::{pkcs1::{DecodeRsaPrivateKey, DecodeRsaPublicKey, EncodeRsaPrivateKey, EncodeRsaPublicKey},
          PublicKeyParts, RsaPrivateKey, RsaPublicKey, PaddingScheme, PublicKey};
use std::str;
use std::env;
// use num_bigint::{BigUint};
use num_traits::{One};
// use rsa::pkcs1::DecodeRsaPrivateKey;

pub fn encrypt_decrypt_rsa() {
    // /// RSA-4096 PKCS#1 private key encoded as ASN.1 DER
    // const RSA_4096_PRIV_DER: &[u8] = include_bytes!("key_examples/rsa4096-priv.der");
    // /// RSA-4096 PKCS#1 public key encoded as ASN.1 DER
    // const RSA_4096_PUB_DER: &[u8] = include_bytes!("key_examples/rsa4096-pub.der");

    /// RSA-4096 PKCS#1 private key encoded as PEM
    const RSA_4096_PRIV_PEM: &str = include_str!("key_examples/rsa4096-priv.pem");
    /// RSA-4096 PKCS#1 public key encoded as PEM
    const RSA_4096_PUB_PEM: &str = include_str!("key_examples/rsa4096-pub.pem");

    // // Generate keys
    // let mut bits = 2048;
    // let private_key = RsaPrivateKey::new(&mut rng, bits).expect("failed to generate a key");
    // let public_key = RsaPublicKey::from(&private_key);

    let mut rng = rand::thread_rng();
    let mut string = String::from("Hello world!");
    let args: Vec<String> = env::args().collect();
    if args.len() > 1 { string = args[1].clone(); }
    // if args.len() > 2 { bits = args[2].clone().parse::<usize>().unwrap(); }

    // let priv_key = RsaPrivateKey::from_pkcs1_der(RSA_4096_PRIV_DER).unwrap();
    // let pub_key = RsaPublicKey::from_pkcs1_der(RSA_4096_PUB_DER).unwrap();

    let priv_key = RsaPrivateKey::from_pkcs1_pem(RSA_4096_PRIV_PEM).unwrap();
    let pub_key = RsaPublicKey::from_pkcs1_pem(RSA_4096_PUB_PEM).unwrap();

    println!("Message:\t{}", string);
    // println!("Number of bits:\t{}", bits);
    let data = string.as_bytes();
    println!("\nN:\t{} (Hex: {:x})", priv_key.n(), priv_key.n());
    println!("E:\t{} (Hex: {:x})", priv_key.e(), priv_key.e());
    println!("D:\t{} (Hex: {:x})", priv_key.d(), priv_key.d());
    println!("\nPrimes (P and Q):");
    for prime in priv_key.primes() {
        println!("\t{} (Hex:{:x})", prime, prime);
    }
    let enc_data = pub_key.encrypt(&mut rng, PaddingScheme::new_pkcs1v15_encrypt(), &data[..]).expect("failed to encrypt");
    let hex_string = hex::encode(enc_data.clone());
    println!("\n\nEncrypted:\t{}", hex_string);
    let dec_data = priv_key.decrypt(PaddingScheme::new_pkcs1v15_encrypt(), &enc_data).expect("failed to decrypt");
    let my_str = str::from_utf8(&dec_data).unwrap();
    println!("\nDecrypted:\t{}", my_str);
// Final check for (d x e) mod (p-1)*(q-1)
    let p = priv_key.primes()[0].clone();
    let q = priv_key.primes()[1].clone();
    let val1: rsa::BigUint = One::one();
    let phi = (p - val1.clone()) * (q - val1.clone());
    let val = (priv_key.d() * priv_key.e()) % phi;
    println!("\n(d*e) mod (p-1)(q-1):\t{}", val);
}