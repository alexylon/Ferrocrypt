use reed_solomon_erasure::galois_8::ReedSolomon;
use crate::CryptoError;

pub fn encode_data(data: Vec<u8>, block_size: usize) -> Result<Vec<Option<Vec<u8>>>, CryptoError> {
    let mut data_shards: Vec<Vec<u8>> = vec![];
    data_shards.push(data);

    //add parity shards
    for _i in 0..2 {
        let mut parity_vec: Vec<u8> = Vec::new();
        for _j in 0..block_size {
            parity_vec.push(0);
        }
        data_shards.push(parity_vec);
    }

    let reed_solomon = ReedSolomon::new(1, 2).unwrap();

    reed_solomon.encode(&mut data_shards)?;

    let shards: Vec<_> = data_shards.iter().cloned().map(Some).collect();

    Ok(shards)
}

pub fn reconstruct_data(mut data_shards: Vec<Option<Vec<u8>>>) -> Result<Vec<u8>, CryptoError> {
    let reed_solomon = ReedSolomon::new(1, 2)?;

    // Try to reconstruct missing shards
    reed_solomon.reconstruct(&mut data_shards)?;

    // Convert back to normal shard arrangement
    let result: Vec<_> = data_shards.into_iter().flatten().collect();

    // Reconstruct original data
    let mut res_data = Vec::new();
    for i in 0..3 {
        res_data.extend_from_slice(&result[i]);
    }

    Ok(res_data)
}
