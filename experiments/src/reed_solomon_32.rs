use reed_solomon_32::encode;
use reed_solomon_32::correct;

#[cfg(test)]
mod tests {
    use rand::RngCore;
    use rand::rngs::OsRng;
    use crate::reed_solomon_32::{rs_32_decode, rs_32_encode, split_vec_u8};

    // #[test]
    // fn encode_reconstruct_test() {
    //     let mut salt_32 = [0u8; 32];
    //     OsRng.fill_bytes(&mut salt_32);
    //     // println!("{:?}", &salt_32);
    //
    //     rs_32_encode(&salt_32);
    //     // println!("encoded_salt_32.len(): {}", &encoded_salt_32.len());
    //     // println!("encoded_salt_32: {:?}", &encoded_salt_32);
    //
    //     // // Corrupt some data
    //     // encoded_salt_32[0] = vec![];
    //     // encoded_salt_32[5] = vec![];
    //     // encoded_salt_32[7] = vec![];
    //     // encoded_salt_32[10] = vec![];
    //     // encoded_salt_32[15] = vec![];
    //     // encoded_salt_32[20] = vec![];
    //     // encoded_salt_32[25] = vec![];
    //     // encoded_salt_32[30] = vec![];
    //
    //     // let reconstructed_salt_32 = sr_reconstruct(&encoded_salt_32, 32).unwrap();
    //     // println!("{:?}", &reconstructed_salt_32[..32]);
    //     //
    //     // assert_eq!(&salt_32.to_vec(), &reconstructed_salt_32[..32]);
    // }

    #[test]
    fn rs_32_encode_recover_test() {
        let data = [0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 1, 2, 3, 4, 5, 6, 7, 8, 9, 1, 2];
        let mut data_enc = rs_32_encode(&data);
        println!("data_enc: {:?}", &data_enc);

        // Simulate some transmission errors
        for i in 0..4 {
            data_enc[i] = 0x0;
        }

        let data_rec = rs_32_decode(&data_enc);
        println!("data_org: {:?}", &data);
        println!("data_rec: {:?}", &data_rec);

        assert_eq!(&data, &data_rec.as_slice());
    }
}

fn rs_32_encode(data: &[u8]) -> Vec<u8> {
    let mut data_split = split_vec_u8(data, 10);
    let mut data_enc: Vec<u8> = vec![];

    // Encode data
    for part in data_split {
        println!("{}:{}", &part.len(), (part.len() * 2) as u8);
        let part_enc = encode(&part, (part.len() * 2) as u8).unwrap();
        data_enc.extend_from_slice(&part_enc);
    }

    data_enc
}

fn rs_32_decode(data: &[u8]) -> Vec<u8> {
    let data_split = split_vec_u8(data, 30);
    let mut data_rec: Vec<u8> = vec![];

    // Try to recover data
    for part in data_split {
        println!("d{}:e{}", &part.len(), (part.len() / 3 * 2));
        let part_rec = correct(&part, (part.len() / 3 * 2) as u8, Some(&[0])).unwrap();
        let chunk = part_rec.to_vec().iter().take(part.len() / 3).cloned().collect::<Vec<u8>>();
        data_rec.extend_from_slice(&chunk);
    }

    data_rec
}

fn split_vec_u8(data: &[u8], n: usize) -> Vec<Vec<u8>> {
    let vec = data.to_vec();
    let num_chunks = vec.len() / n;
    let mut chunks = vec.chunks(n).take(num_chunks).map(|chunk| chunk.to_vec()).collect::<Vec<Vec<u8>>>();

    let remaining = vec.len() % n;
    if remaining > 0 {
        let last_chunk = vec.iter().rev().take(remaining).rev().cloned().collect::<Vec<u8>>();
        chunks.push(last_chunk);
    }

    chunks
}
