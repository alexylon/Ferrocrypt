use std::fs;
use std::fs::File;
use std::io::Read;
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

#[cfg(test)]
mod tests {
    use std::fs::File;
    use std::io::Write;
    use std::path::Path;
    use rand::RngCore;
    use rand::rngs::OsRng;

    use super::*;
    // use tests::Bencher;

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

        // let my_data: Vec<u8> = get_file_as_byte_vec(FILE_NAME).unwrap();

        let blocks = 2;
        // for blocks in 1..5_usize {
        let encoded_shares = encode_data(&salt_32, blocks as u8).unwrap();
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

        let encoded_from_file: Vec<u8> = get_file_as_byte_vec(OUTPUT_FILE_NAME).unwrap();
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

        let mut reconstructed_data = reconstruct_data(&data_shs_2[0..blocks]).unwrap();
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


/// Split data to 2b - 1 blocks, where every b blocks can reconstruct the original data.
/// (2*b - 1) must be smaller or equal to 256.
pub fn encode_data(data: &[u8], blocks: u8) -> Result<Vec<DataShare>, SplitDataError> {
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

    // Add zero padding in case block_size is not a divisor of data.len():
    let padding_len = num_blocks * block_size - data.len();
    debug_assert!(padding_len < block_size);

    let mut cdata = data.to_vec();
    for _ in 0..padding_len {
        cdata.push(0);
    }

    let mut shards: Vec<Box<[u8]>> = Vec::new();

    for i in 0..num_blocks {
        let cur_shard = cdata[i * block_size..(i + 1) * block_size].to_vec();
        debug_assert!(cur_shard.len() == block_size);
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

/// Reconstruct original data using given b data shares
/// Reconstructed data might contain trailing zero padding bytes.
pub fn reconstruct_data(data_shares: &[DataShare]) -> Result<Vec<u8>, UniteDataError> {
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

    Ok(res_data)
}


fn get_file_as_byte_vec(filename: &str) -> std::io::Result<Vec<u8>> {
    let mut file = File::open(filename)?;
    let metadata = fs::metadata(filename)?;
    let mut buffer = vec![0; metadata.len() as usize];
    file.read_exact(&mut buffer)?;

    Ok(buffer)
}
