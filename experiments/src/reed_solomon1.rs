use reed_solomon_erasure::galois_8::ReedSolomon;
use serde::{Deserialize, Serialize};


#[derive(Serialize, Deserialize, Debug, Ord, PartialOrd, Eq, PartialEq)]
pub struct DataShare {
    pub index: u8,
    pub block: Vec<u8>,
}

#[derive(Debug)]
pub enum SplitDataError {
    NumBlocksIsZero,
    NumBlocksTooLarge,
    ReedSolomonInitFailed(reed_solomon_erasure::Error),
    ReedSolomonEncodeFailed(reed_solomon_erasure::Error),
}

const FILE_NAME: &str = "src/test_files/test-file.txt";

/// Split data to 2b - 1 blocks, where every b blocks can reconstruct the original data.
/// (2*b - 1) must be smaller or equal to 256.
pub fn encode_data_experiment(data: &[u8], blocks: u8) -> Result<Vec<DataShare>, SplitDataError> {
    let num_blocks = blocks as usize;

    if num_blocks == 0 {
        return Err(SplitDataError::NumBlocksIsZero);
    }

    if 2 * num_blocks - 1 > 256 {
        return Err(SplitDataError::NumBlocksTooLarge);
    }

    if num_blocks == 1 {
        return Ok(vec![DataShare {
            index: 0,
            block: data.to_vec(),
        }]);
    }

    let reed_solomon = ReedSolomon::new(num_blocks, num_blocks - 1).unwrap();

    // // Special case of just one block. We don't need to use reed-solomon encoder.
    // // Note that we will get an error if we try to use the
    // // reed solomon encoder with amount of parity shards = 0
    // let reed_solomon = match ReedSolomon::new(num_blocks, num_blocks - 1) {
    //     Ok(reed_solomon) => reed_solomon,
    //     Err(e) => return Err(SplitDataError::ReedSolomonInitFailed(e)),
    // };

    let block_size = (data.len() + (num_blocks - 1)) / num_blocks;

    // // Add zero padding in case block_size is not a divisor of data.len():
    // let padding_len = num_blocks * block_size - data.len();
    // debug_assert!(padding_len < block_size);

    // let mut cdata = data.to_vec();
    // for _ in 0..padding_len {
    //     cdata.push(0);
    // }

    let data_padded = pad_pkcs7(data.to_vec(), block_size);
    println!("data_padded: {:?}", data_padded);

    let mut shards: Vec<Box<[u8]>> = Vec::new();

    // let res_data_unpadded = if res_data.len() % num_blocks == 0 {
    //     res_data
    // } else {
    //     let padding_size = res_data.last().copied().unwrap() as usize;
    //     unpad_pkcs7(res_data, padding_size)
    // };
    // println!("res_data_unpadded: {:?}", &res_data_unpadded);

    for i in 0..num_blocks {
        let cur_shard = data_padded[i * block_size..(i + 1) * block_size].to_vec();
        // debug_assert!(cur_shard.len() == block_size);
        shards.push(cur_shard.into_boxed_slice());
    }

    // Add extra num_blocks - 1 empty shards to be used for encoding:
    for _ in 0..num_blocks - 1 {
        shards.push(vec![0u8; block_size].into_boxed_slice());
    }

    match reed_solomon.encode(&mut shards) {
        Ok(()) => {}
        Err(e) => return Err(SplitDataError::ReedSolomonEncodeFailed(e)),
    };

    Ok(shards
        .into_iter()
        .enumerate()
        .map(|(i, shard)| {
            DataShare {
                index: i as u8,
                block: shard.to_vec(),
            }
        }).collect::<Vec<DataShare>>())
}

#[derive(Debug)]
pub enum UniteDataError {
    NumBlocksIsZero,
    NumBlocksTooLarge,
    ReedSolomonInitFailed(reed_solomon_erasure::Error),
    ReedSolomonDecodeFailed(reed_solomon_erasure::Error),
}

/// Reconstruct original data using given block data shares
/// Reconstructed data might contain trailing zero padding bytes.
pub fn reconstruct_data_experiment(data_shares: &[DataShare]) -> Result<Vec<u8>, UniteDataError> {
    let num_blocks = data_shares.len();

    if num_blocks == 0 {
        return Err(UniteDataError::NumBlocksIsZero);
    }

    // Limit due to the amount of elements in the field.
    if (2 * num_blocks - 1) > 256 {
        return Err(UniteDataError::NumBlocksTooLarge);
    }

    // Special case of just one block. We don't need to use reed-solomon decoder.
    if num_blocks == 1 {
        return Ok(data_shares[0].block.clone());
    }

    let reed_solomon = match ReedSolomon::new(num_blocks, num_blocks - 1) {
        Ok(reed_solomon) => reed_solomon,
        Err(e) => return Err(UniteDataError::ReedSolomonInitFailed(e)),
    };

    // Convert data_shares into shards format:
    let mut option_shards: Vec<Option<Box<[u8]>>> = vec![None; 2 * num_blocks - 1];
    for data_share in data_shares {
        let cloned_share_data = data_share.block.clone();
        option_shards[data_share.index as usize] = Some(cloned_share_data.into_boxed_slice());
    }


    // option_shards[1].as_mut().unwrap()[2] = 0;
    // println!("option_shards: {:?}", option_shards);

    match reed_solomon.reconstruct(&mut option_shards) {
        Ok(()) => {}
        Err(e) => return Err(UniteDataError::ReedSolomonDecodeFailed(e)),
    };


    let shards: Vec<_> = option_shards.into_iter().flatten().collect();

    // Reconstruct original data (Possibly with trailing zero padding):
    let mut res_data = Vec::new();
    for i in 0..num_blocks {
        res_data.extend_from_slice(&shards[i]);
    }

    // let padding_size = res_data.last().copied().unwrap() as usize;
    // let res_data_unpadded = unpad_pkcs7(res_data, padding_size);

    Ok(res_data)
}

fn pad_pkcs7(mut byte_vec: Vec<u8>, block_size: usize) -> Vec<u8> {
    let padding_size = block_size - byte_vec.len() % block_size;
    let padding_char = padding_size as u8;
    // let mut padding = (0..padding_size).map(|_| padding_char).collect();

    for _ in 0..padding_size {
        byte_vec.push(padding_char);
    }

    byte_vec
}

fn unpad_pkcs7(mut byte_vec: Vec<u8>, padding_size: usize) -> Vec<u8> {
    // Use `saturating_sub` to handle the case where there aren't N elements in the vector
    let final_length = byte_vec.len().saturating_sub(padding_size);
    byte_vec.truncate(final_length);

    byte_vec
}

pub fn encode_data(data: Vec<u8>, block_size: usize) -> Result<Vec<Option<Vec<u8>>>, SplitDataError> {
    let mut data_shards: Vec<Vec<u8>> = vec![];
    data_shards.push(data);
    //add parity slices
    for _i in 0..2 {
        let mut parity_vec: Vec<u8> = Vec::new();
        for _j in 0..block_size {
            parity_vec.push(0);
        }
        data_shards.push(parity_vec);
    }
    println!("data_shards + parity_shards: {:?}", &data_shards);


    let reed_solomon = ReedSolomon::new(1, 2).unwrap();


    match reed_solomon.encode(&mut data_shards) {
        Ok(()) => {}
        Err(e) => return Err(SplitDataError::ReedSolomonEncodeFailed(e)),
    };

    let shards: Vec<_> = data_shards.iter().cloned().map(Some).collect();

    Ok(shards)
}

pub fn reconstruct_data(mut data_shards: Vec<Option<Vec<u8>>>) -> Result<Vec<u8>, UniteDataError> {

    let reed_solomon = ReedSolomon::new(1, 2).unwrap();

// Try to reconstruct missing shards
    reed_solomon.reconstruct(&mut data_shards).unwrap();

    // Convert back to normal shard arrangement
    let result: Vec<_> = data_shards.into_iter().flatten().collect();

    // Reconstruct original data (Possibly with trailing zero padding):
    let mut res_data = Vec::new();
    for i in 0..3 {
        res_data.extend_from_slice(&result[i]);
    }

    Ok(res_data)
}

#[cfg(test)]
mod tests {
    use std::fs::{File, read};
    use std::io::Write;
    use std::path::Path;
    use rand::RngCore;
    use rand::rngs::OsRng;
    use std::str;

    use super::*;
    // use tests::Bencher;

    const SRC_FILE_PATH: &str = "src/test_files/test-file.txt";
    const OUTPUT_FILE_NAME: &str = "test.txt";

    #[test]
    fn encode_reconstruct_fixed_data_test() {
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
        let salt_encoded: Vec<Option<Vec<u8>>> = encode_data(salt_32.to_vec(), salt_32.len()).unwrap();
        println!("salt_encoded: {:?}", &salt_encoded);
        let nonce_encoded: Vec<Option<Vec<u8>>> = encode_data(nonce_24.to_vec(), nonce_24.len()).unwrap();
        println!("nonce_encoded: {:?}", &nonce_encoded);

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
        let header: [usize; 4] = [salt_encoded_ser_len, nonce_encoded_ser_len, salt_encoded_ser_len, file_bytes_len];
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

        let mut salt_enc: Vec<Option<Vec<u8>>> = bincode::deserialize(salt_enc_bytes).unwrap();
        let mut nonce_enc: Vec<Option<Vec<u8>>> = bincode::deserialize(nonce_enc_bytes).unwrap();

        // We can remove up to 2 shards, which may be data or parity shards
        salt_enc[1] = None;
        nonce_enc[0] = None;

        let salt = reconstruct_data(salt_enc).unwrap();
        let nonce = reconstruct_data(nonce_enc).unwrap();
        let text_str = str::from_utf8(text_bytes).unwrap();

        println!("salt    :{:?}", &salt[0..32]);
        println!("nonce    :{:?}", &nonce[0..24]);
        println!("text_str: {:?}", text_str);
    }

    #[test]
    fn encode_reconstruct_fixed_data_test_simple() {
        let mut salt_32 = [0u8; 32];
        OsRng.fill_bytes(&mut salt_32);
        println!("{:?}", &salt_32);
        let mut nonce_24 = [0u8; 24];
        OsRng.fill_bytes(&mut nonce_24);

        let mut salt_32_encoded: Vec<Option<Vec<u8>>> = encode_data(salt_32.to_vec(), salt_32.len()).unwrap();
        let mut nonce_24_encoded: Vec<Option<Vec<u8>>> = encode_data(nonce_24.to_vec(), nonce_24.len()).unwrap();

        // We can remove up to 2 shards, which may be data or parity shards
        salt_32_encoded[1] = None;
        nonce_24_encoded[0] = None;

        let salt_32_reconstructed = reconstruct_data(salt_32_encoded).unwrap();
        let nonce_24_reconstructed = reconstruct_data(nonce_24_encoded).unwrap();

        println!("salt_32: {:?}", &salt_32);
        println!("salt_re: {:?}", &salt_32_reconstructed[0..32]);
        println!("salt_32: {:?}", &nonce_24);
        println!("salt_re: {:?}", &nonce_24_reconstructed[0..24]);
    }

    /*
    #[test]
    fn split_and_unite_block() {
        let orig_block: &[u8] = &[1,2,3,4,5,6,7];
        let shares = split_block(&orig_block).unwrap();
        let new_block = unite_block(&shares[0 .. orig_block.len()]).unwrap();
        assert_eq!(orig_block, &new_block[..]);
    }
    */

    #[test]
    fn encode_reconstruct_data_test() {
        // let my_data = &[1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20];

        let mut salt_32 = [0u8; 32];
        OsRng.fill_bytes(&mut salt_32);
        println!("{:?}", &salt_32);
        let mut nonce_24 = [0u8; 24];
        OsRng.fill_bytes(&mut nonce_24);

        // let my_data: Vec<u8> = fs::read(FILE_NAME).unwrap();

        let blocks = 2;
        // for blocks in 1..5_usize {
        let encoded_shares = encode_data_experiment(&salt_32, blocks as u8).unwrap();
        println!("data_shs1: {:?}", encoded_shares);

        // Serialize it to a JSON string.
        // let encoded_shares_to_file: Vec<u8> = serde_json::to_vec(&encoded_shares).unwrap();
        let encoded_shares_to_file: Vec<u8> = serde_json::to_vec(&encoded_shares).unwrap();
        println!("encoded_shares_to_file: {:?}", encoded_shares_to_file);
        println!("encoded_shares_to_file.len(): {:?}", &encoded_shares_to_file.len());

        const OUTPUT_FILE_NAME: &str = "salt_32.txt";

        //write the file to new file to test the image
        let path = Path::new(OUTPUT_FILE_NAME);
        let mut file = match File::create(path) {
            Err(why) => panic!("couldn't open file: {}", why),
            Ok(file) => file,
        };
        file.write_all(&encoded_shares_to_file).expect("TODO: panic message");

        let encoded_from_file: Vec<u8> = read(OUTPUT_FILE_NAME).unwrap();
        println!("org_data.len(): {:?}", &salt_32.len());
        println!("encoded_from_file.len(): {:?}", &encoded_from_file.len());
        let data_shs_2: Vec<DataShare> = serde_json::from_slice(&encoded_from_file).unwrap();
        println!("data_shs2: {:?}", &data_shs_2);

        let data_shs3: Vec<DataShare> = serde_json::from_slice(&encoded_shares_to_file).unwrap();
        println!("data_shs3: {:?}", data_shs3);

        // //remove 3 shards for reconstruction later
        // encoded_shares[0] = None;
        // shards[1] = None;
        // shards[2] = None;

        let mut reconstructed_data = reconstruct_data_experiment(&data_shs_2[0..blocks]).unwrap();
        assert_eq!(reconstructed_data.len(),
                   blocks * ((salt_32.len() + blocks - 1) / blocks));

        // Truncate resulting data, as it might contain some trailing padding zeroes.
        reconstructed_data.truncate(salt_32.len());
        println!("org_data: {:?}", salt_32);
        println!("rec_data: {:?}", &reconstructed_data[..]);
        assert_eq!(salt_32, &reconstructed_data[..]);
        // }

        // const OUTPUT_FILE_NAME: &str = "copy.zip";
        //
        // //write the file to new file to test the image
        // let path = Path::new(OUTPUT_FILE_NAME);
        // let mut file = match File::create(path) {
        //     Err(why) => panic!("couldn't open file: {}", why),
        //     Ok(file) => file,
        // };
        // file.write_all(&reconstructed_data).expect("Cannot write file!");
    }

    // #[bench]
    // fn bench_unite_data(bencher: &mut Bencher) {
    //     let seed: &[_] = &[1, 2, 3, 4, 5];
    //     let mut rng: StdRng = rand::SeedableRng::from_seed(seed);
    //     let mut my_data = vec![0; 2500];
    //     rng.fill_bytes(&mut my_data);
    //
    //     let b: usize = 5;
    //     let data_shares = split_data(&my_data, b as u8).unwrap();
    //
    //     bencher.iter(|| unite_data(&data_shares[0..b]).unwrap());
    // }
}
