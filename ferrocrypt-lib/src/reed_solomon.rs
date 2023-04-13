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
        encoded_salt_32[35] = 0;
        encoded_salt_32[40] = 0;
        encoded_salt_32[65] = 0;
        encoded_salt_32[90] = 0;

        let decoded_salt_32 = rs_decode(&encoded_salt_32).unwrap();

        println!("{:?}", &arr_32);
        println!("{:?}", &decoded_salt_32);

        assert_eq!(&arr_32.to_vec(), &decoded_salt_32[..32]);
    }
}


pub fn rs_encode(data: &[u8]) -> Result<Vec<u8>, CryptoError> {
    let mut data_shards: Vec<Vec<u8>> = vec![];
    data_shards.push(data.to_vec());

    //add parity slices
    for _i in 0..2 {
        let mut parity_vec: Vec<u8> = Vec::new();
        for _j in 0..data.len() {
            parity_vec.push(0);
        }
        data_shards.push(parity_vec);
    }

    let reed_solomon = ReedSolomon::new(1, 2)?;

    // reed_solomon.encode(&mut data_shards)?;
    reed_solomon.encode(&mut data_shards)?;

    let option_shards: Vec<_> = data_shards.iter().cloned().map(Some).collect();

    let mut recovered_shards: Vec<u8> = vec![];

    // Convert option_shards to normal bytes
    for option_shard in option_shards {
        match option_shard {
            None => { return Err(CryptoError::Message("None shard found!".to_string())); }
            Some(shard) => {
                recovered_shards.extend_from_slice(shard.as_slice());
            }
        }
    }

    Ok(recovered_shards)
}

pub fn rs_decode(data: &[u8]) -> Result<Vec<u8>, CryptoError> {
    let block_size = data.len() / 3;
    let data_shards = split_vec_u8(data, block_size);

    let reed_solomon = ReedSolomon::new(1, 2)?;

    let mut option_shards: Vec<Option<Vec<u8>>> = vec![None; 3];

    // Covert shards to option_shards to be accepted by the crate
    for i in 0..3 {
        if data_shards.get(i).is_none() || data_shards[i].len() != block_size {
            option_shards[i] = None;
            println!("A 'None' shard detected: {:?}", &option_shards[i]);
        } else {
            option_shards[i] = Some(data_shards[i].clone());
        }
    }

    // Try to reconstruct missing shards
    reed_solomon.reconstruct(&mut option_shards)?;

    // Convert back to normal shard arrangement
    let vecs: Vec<_> = option_shards.into_iter().flatten().collect();

    // Compare each 3 elements with the same index in the three vectors and push to a new vector the element which occurs at least twice
    // If all three elements are different, insert the element from the first input vector to the new vector as a fallback option
    let mut result = vec![];

    for i in 0..vecs[0].len() {
        let mut freq = std::collections::HashMap::new();
        let elem_from_first_vec = vecs[0][i];
        let mut elem_with_most_freq = vecs[0][i];

        for vec in &vecs {
            let elem = vec[i];
            *freq.entry(elem).or_insert(0) += 1;
            if freq[&elem] > freq[&elem_with_most_freq] {
                elem_with_most_freq = elem;
            }
        }

        for elem in freq.keys() {
            if freq[elem] >= 2 {
                result.push(*elem);
            }
        }

        if freq[&elem_with_most_freq] < 2 {
            result.push(elem_from_first_vec);
        }
    }

    Ok(result)
}

fn split_vec_u8(data: &[u8], block_size: usize) -> Vec<Vec<u8>> {
    let vec = data.to_vec();
    let num_chunks = vec.len() / block_size;
    let mut chunks = vec.chunks(block_size).take(num_chunks).map(|chunk| chunk.to_vec()).collect::<Vec<Vec<u8>>>();

    let remaining = vec.len() % block_size;
    if remaining > 0 {
        let last_chunk = vec.iter().rev().take(remaining).rev().cloned().collect::<Vec<u8>>();
        chunks.push(last_chunk);
    }

    chunks
}

