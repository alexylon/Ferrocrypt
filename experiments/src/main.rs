use std::fs::{File, read};
use std::io::Write;
use std::path::Path;
use rand::RngCore;
use rand::rngs::OsRng;
use crate::reed_solomon1::{DataShare, encode_data, encode_data_experiment, reconstruct_data, reconstruct_data_experiment};
use std::str;

mod reed_solomon1;
mod reed_solomon_32;

const SRC_FILE_PATH: &str = "src/test_files/test-file.txt";
const OUTPUT_FILE_NAME: &str = "test.txt";

fn main() {
    // Write data =================================================================
    let mut salt_32 = [0u8; 32];
    OsRng.fill_bytes(&mut salt_32);
    println!("salt_32: {:?}", &salt_32);
    let mut nonce_24 = [0u8; 24];
    OsRng.fill_bytes(&mut nonce_24);
    println!("nonce_24: {:?}", &nonce_24);

    // let my_data: Vec<u8> = read(FILE_NAME).unwrap();

    let blocks = 8;
    // for blocks in 1..5_usize {
    let salt_encoded = encode_data_experiment(&salt_32.to_vec(), blocks as u8).unwrap();
    println!("salt_encoded: {:?}", &salt_encoded);
    let nonce_encoded = encode_data_experiment(&nonce_24, blocks as u8).unwrap();
    println!("nonce_encoded: {:?}", &nonce_encoded);

    // Serialize it to a JSON string.
    // let encoded_shares_to_file: Vec<u8> = bincode::serialize(&encoded_shares).unwrap();
    let salt_encoded_ser: Vec<u8> = bincode::serialize(&salt_encoded).unwrap();
    // println!("salt_encoded_vec1: {:?}", &salt_encoded_ser);
    let salt_encoded_ser_len = salt_encoded_ser.len();
    println!("salt_encoded_ser_len: {}", &salt_encoded_ser_len);

    let nonce_encoded_ser: Vec<u8> = bincode::serialize(&nonce_encoded).unwrap();
    let nonce_encoded_ser_len = nonce_encoded_ser.len();
    println!("nonce_encoded_ser_len: {}", &nonce_encoded_ser_len);

    let file_bytes = read(SRC_FILE_PATH).unwrap();
    let file_bytes_len = file_bytes.len();

    // HEADER
    let header: [usize; 3] = [salt_encoded_ser_len, nonce_encoded_ser_len, file_bytes_len];
    let header_ser: Vec<u8> = bincode::serialize(&header).unwrap();
    println!("header_ser.len(): {}", &header_ser.len());


    //write the file to new file to test the image
    let path = Path::new(OUTPUT_FILE_NAME);
    let mut file = match File::create(path) {
        Err(why) => panic!("couldn't open file: {}", why),
        Ok(file) => file,
    };

    file.write_all(&header_ser).expect("Cannot write to file!");
    file.write_all(&salt_encoded_ser).expect("Cannot write to file!");
    file.write_all(&nonce_encoded_ser).expect("Cannot write to file!");
    file.write_all(&file_bytes).expect("Cannot write to file!");


   // Read data =================================================================

    let encoded_from_file: Vec<u8> = read(OUTPUT_FILE_NAME).unwrap();
    // Split file

    let (header_bytes, rem) = encoded_from_file.split_at(24);
    let header: [usize; 3] = bincode::deserialize(header_bytes).unwrap();
    println!("header: {}:{}:{}", header[0], header[1], header[2]);

    let (salt_enc_bytes, rem) = rem.split_at(header[0]);
    let (nonce_enc_bytes, text_bytes) = rem.split_at(header[1]);

    let mut salt_enc: Vec<DataShare> = bincode::deserialize(salt_enc_bytes).unwrap();
    let nonce_enc: Vec<DataShare> = bincode::deserialize(nonce_enc_bytes).unwrap();

    salt_enc[0].block[0] = 0;

    let salt = reconstruct_data_experiment(&salt_enc[0..]).unwrap();
    let nonce = reconstruct_data_experiment(&nonce_enc[0..]).unwrap();
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
