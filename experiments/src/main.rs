use std::fs::{File, read};
use std::io::Write;
use std::path::Path;
use rand::RngCore;
use rand::rngs::OsRng;
use crate::reed_solomon::{DataShare, encode_data, reconstruct_data};
use std::str;

mod reed_solomon;


fn main() {
    // Write data =================================================================
    let mut salt_32 = [0u8; 32];
    OsRng.fill_bytes(&mut salt_32);
    println!("salt_32: {:?}", &salt_32);
    let mut nonce_24 = [0u8; 24];
    OsRng.fill_bytes(&mut nonce_24);
    println!("nonce_24: {:?}", &nonce_24);

    // let my_data: Vec<u8> = read(FILE_NAME).unwrap();

    let blocks = 6;
    // for blocks in 1..5_usize {
    let salt_encoded = encode_data(&salt_32, blocks as u8).unwrap();
    let nonce_encoded = encode_data(&nonce_24, blocks as u8).unwrap();

    // Serialize it to a JSON string.
    // let encoded_shares_to_file: Vec<u8> = serde_json::to_vec(&encoded_shares).unwrap();
    let salt_encoded_ser: Vec<u8> = serde_json::to_vec(&salt_encoded).unwrap();
    // println!("salt_encoded_vec1: {:?}", &salt_encoded_ser);
    let salt_encoded_ser_len = salt_encoded_ser.len();
    // println!("salt_encoded_ser_len: {}", &salt_encoded_ser_len);

    let nonce_encoded_ser: Vec<u8> = serde_json::to_vec(&nonce_encoded).unwrap();
    let nonce_encoded_ser_len = nonce_encoded_ser.len();
    // println!("nonce_encoded_ser_len: {}", &nonce_encoded_ser_len);

    // TODO: include original `salt` and `nonce` lengths in the header, instead of blocks
    let header = [blocks, salt_encoded_ser_len, nonce_encoded_ser_len];
    let header_ser: Vec<u8> = serde_json::to_vec(&header).unwrap();
    // println!("header_ser.len(): {}", &header_ser.len());

    let text = "Hello World!";

    const OUTPUT_FILE_NAME: &str = "test.txt";

    //write the file to new file to test the image
    let path = Path::new(OUTPUT_FILE_NAME);
    let mut file = match File::create(path) {
        Err(why) => panic!("couldn't open file: {}", why),
        Ok(file) => file,
    };

    file.write_all(&header_ser).expect("Cannot write to file!");
    file.write_all(&salt_encoded_ser).expect("Cannot write to file!");
    file.write_all(&nonce_encoded_ser).expect("Cannot write to file!");
    file.write_all(text.as_bytes()).expect("Cannot write to file!");


   // Read data =================================================================

    let encoded_from_file: Vec<u8> = read(OUTPUT_FILE_NAME).unwrap();
    let (header_bytes, rem) = encoded_from_file.split_at(11);
    let header: [usize; 3] = serde_json::from_slice(header_bytes).unwrap();
    println!("header: {}:{}:{}", header[0], header[1], header[2]);
    let (salt_enc_bytes, rem) = rem.split_at(header[1]);
    let (nonce_enc_bytes, text_bytes) = rem.split_at(header[2]);

    // let blocks = header[0];
    let salt_enc: Vec<DataShare> = serde_json::from_slice(salt_enc_bytes).unwrap();
    let nonce_enc: Vec<DataShare> = serde_json::from_slice(nonce_enc_bytes).unwrap();

    let salt = reconstruct_data(&salt_enc[0..]).unwrap();
    let nonce = reconstruct_data(&nonce_enc[0..]).unwrap();
    let text_str = str::from_utf8(text_bytes).unwrap();

    println!("salt    :{:?}", &salt[0..32]);
    println!("nonce    :{:?}", &nonce[0..24]);
    println!("text_str: {:?}", text_str);

}

fn _split_delimited<'a, T>(input: &'a [T], delim: &T) -> Vec<&'a [T]>
    where T: PartialEq<T> {
    let mut indices: Vec<usize> = input.iter().enumerate().filter(|(_, value)| *value == delim).map(|(i, _)| i).collect();
    if indices.first() != Some(&0) {
        indices.insert(0, 0);
    }
    let mut output = Vec::new();

    for pair in indices.windows(2) {
        output.push(&input[pair[0]..pair[1]]);
    }

    output.push(&input[*indices.last().unwrap()..]);

    output
}
