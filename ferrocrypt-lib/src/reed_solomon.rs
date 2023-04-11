use reed_solomon_erasure::galois_8::{ReedSolomon, ShardByShard};
use crate::CryptoError;


#[cfg(test)]
mod tests {
    use chacha20poly1305::aead::OsRng;
    use chacha20poly1305::aead::rand_core::RngCore;
    use crate::reed_solomon::{sr_encode_with_double_parity, sr_reconstruct_with_double_parity};

    #[test]
    fn encode_reconstruct_test() {
        let mut salt_32 = [0u8; 32];
        OsRng.fill_bytes(&mut salt_32);
        println!("{:?}", &salt_32);

        let mut encoded_salt_32 = sr_encode_with_double_parity(&salt_32).unwrap();

        encoded_salt_32[0] = vec![];
        println!("{:?}", &encoded_salt_32);

        let reconstructed_salt_32 = sr_reconstruct_with_double_parity(encoded_salt_32, 32).unwrap();
        println!("{:?}", &reconstructed_salt_32[..32]);
    }
}

pub fn sr_encode_with_double_parity(data: &[u8]) -> Result<Vec<Vec<u8>>, CryptoError> {
    let block_size = data.len();
    let mut data_shards: Vec<Vec<u8>> = vec![];
    data_shards.push(data.to_vec());

    //add parity shards
    for _i in 0..2 {
        let mut parity_vec: Vec<u8> = Vec::new();
        for _j in 0..block_size {
            parity_vec.push(0);
        }
        data_shards.push(parity_vec);
    }

    let reed_solomon = ReedSolomon::new(1, 2).unwrap();
    let mut sbs = ShardByShard::new(&reed_solomon);

    // reed_solomon.encode(&mut data_shards)?;
    sbs.encode(&mut data_shards).unwrap();

    let option_shards: Vec<_> = data_shards.iter().cloned().map(Some).collect();

    let mut recovered_shards: Vec<Vec<u8>> = vec![];

    // Convert option_shards to normal
    for option_shard in option_shards {
        match option_shard {
            None => { return Err(CryptoError::Message("None shard found!".to_string())); }
            Some(shard) => { recovered_shards.push(shard); }
        }
    }

    Ok(recovered_shards)
}

pub fn sr_reconstruct_with_double_parity(data_shards: Vec<Vec<u8>>, block_size: usize) -> Result<Vec<u8>, CryptoError> {
    let reed_solomon = ReedSolomon::new(1, 2)?;

    let mut option_shards: Vec<Option<Vec<u8>>> = vec![None; 3];
    // for data_shard in data_shards {
    //     let data_shard_cloned = data_shard.clone();
    //     option_shards.push(Some(data_shard_cloned));
    // }

    for i in 0..3 {
        if data_shards.get(i).is_none() || data_shards[i].len() != block_size {
            option_shards[i] = None;
        } else {
            option_shards[i] = Some(data_shards[i].clone());
        }
    }

    // Try to reconstruct missing shards
    reed_solomon.reconstruct(&mut option_shards)?;

    // Convert back to normal shard arrangement
    let result: Vec<_> = option_shards.into_iter().flatten().collect();

    // Reconstruct original data
    let mut res_data = Vec::new();
    for i in 0..3 {
        res_data.extend_from_slice(&result[i]);
    }

    Ok(res_data)
}
