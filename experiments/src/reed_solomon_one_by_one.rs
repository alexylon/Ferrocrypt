use reed_solomon_erasure::galois_8::{ReedSolomon};
use crate::CryptoError;


#[cfg(test)]
mod tests {
    use chacha20poly1305::aead::OsRng;
    use chacha20poly1305::aead::rand_core::RngCore;
    use crate::reed_solomon::{rs_encode, rs_decode};

    #[test]
    fn encode_reconstruct_test() {
        // let mut salt_32 = [0u8; 32];
        // OsRng.fill_bytes(&mut salt_32);
        // println!("{:?}", &salt_32);

        let arr_32 = [1, 2, 3, 4, 5, 6, 7, 8, 9, 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 0, 1, 2];

        let mut encoded_salt_32 = rs_encode(&arr_32).unwrap();
        println!("encoded_salt_32.len(): {}", &encoded_salt_32.len());
        println!("encoded_salt_32: {:?}", &encoded_salt_32);

        // // Corrupt some data
        encoded_salt_32[0] = 0;
        // encoded_salt_32[5] = vec![];
        // encoded_salt_32[7] = vec![];
        // encoded_salt_32[10] = vec![];
        // encoded_salt_32[15] = vec![];
        // encoded_salt_32[20] = vec![];
        // encoded_salt_32[25] = vec![];
        // encoded_salt_32[30] = vec![];

        let decoded_salt_32 = rs_decode(&encoded_salt_32, 32).unwrap();
        println!("{:?}", &decoded_salt_32);

        // assert_eq!(&arr_32.to_vec(), &decoded_salt_32[..32]);
    }
}


pub fn rs_encode(data: &[u8]) -> Result<Vec<u8>, CryptoError> {
    let data_shards_number = data.len();
    let parity_shards_number = data_shards_number * 2;

    let mut data_shards: Vec<Vec<u8>> = vec![];

    for byte in data {
        data_shards.push([*byte].to_vec())
    }

    //add parity shards
    for _i in 0..parity_shards_number {
        data_shards.push(vec![0]);
    }

    let reed_solomon = ReedSolomon::new(data_shards_number, parity_shards_number).unwrap();

    // reed_solomon.encode(&mut data_shards)?;
    reed_solomon.encode(&mut data_shards).unwrap();

    let option_shards: Vec<_> = data_shards.iter().cloned().map(Some).collect();

    let mut recovered_shards: Vec<u8> = vec![];

    // Convert option_shards to normal
    for option_shard in option_shards {
        match option_shard {
            None => { return Err(CryptoError::Message("None shard found!".to_string())); }
            Some(shard) => {
                for byte in shard {
                    recovered_shards.push(byte);
                }
            }
        }
    }

    Ok(recovered_shards)
}

pub fn rs_decode(data: &[u8], block_size: usize) -> Result<Vec<u8>, CryptoError> {
    let mut data_shards: Vec<u8> = vec![];

    for byte in data {
        data_shards.push(*byte)
    }

    let data_shards_number = block_size;
    let parity_shards_number = data_shards_number * 2;
    let total_shards_number = data_shards_number + parity_shards_number;

    let reed_solomon = ReedSolomon::new(data_shards_number, parity_shards_number)?;

    let mut option_shards: Vec<Option<Vec<u8>>> = vec![None; total_shards_number];

    for i in 0..total_shards_number {
        if data_shards.get(i).is_none() {
            option_shards[i] = None;
            println!("A 'None' shard detected: {:?}", &option_shards[i]);
        } else {
            option_shards[i] = Some([data_shards[i]].to_vec());
        }
    }

    // Try to reconstruct missing shards
    reed_solomon.reconstruct(&mut option_shards)?;

    // Convert back to normal shard arrangement
    let result: Vec<_> = option_shards.into_iter().flatten().collect();

    // Reconstruct original data
    let mut res_data = Vec::new();
    for vec in result {
        res_data.extend_from_slice(&vec);
    }

    Ok(res_data)
}

