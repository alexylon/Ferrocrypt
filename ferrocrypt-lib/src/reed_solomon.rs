use reed_solomon_simd::ReedSolomonEncoder;

use crate::CryptoError;

/// Calculates the size of encoded data for a given original data size.
/// The encoded format is: [padding_byte, original_shard, recovery_shard_0, recovery_shard_1]
/// where each shard must be even-length.
pub fn rs_encoded_size(original_size: usize) -> usize {
    let padded_size = if original_size % 2 != 0 {
        original_size + 1
    } else {
        original_size
    };

    1 + (padded_size * 3)
}

/// Encodes data using Reed-Solomon erasure coding for error correction.
pub fn rs_encode(data: &[u8]) -> Result<Vec<u8>, CryptoError> {
    // reed-solomon-simd requires even-length shards
    let mut data_vec = data.to_vec();
    let padding_byte = if data.len() % 2 != 0 {
        data_vec.push(0);
        1u8
    } else {
        0u8
    };

    let shard_bytes = data_vec.len();

    // Create encoder with 1 original shard and 2 recovery shards
    let mut encoder = ReedSolomonEncoder::new(1, 2, shard_bytes)?;

    // Add the original shard
    encoder.add_original_shard(&data_vec)?;

    // Encode to get recovery shards
    let result = encoder.encode()?;

    // Build output: [padding_byte, original_shard, recovery_shard_0, recovery_shard_1]
    let mut output = vec![padding_byte];
    output.extend_from_slice(&data_vec);

    // Get recovery shards - these are Option<&[u8]>, so we need to unwrap
    let recovery_0 = result.recovery(0).ok_or_else(|| CryptoError::Message("Missing recovery shard 0".to_string()))?;
    let recovery_1 = result.recovery(1).ok_or_else(|| CryptoError::Message("Missing recovery shard 1".to_string()))?;

    output.extend_from_slice(recovery_0);
    output.extend_from_slice(recovery_1);

    Ok(output)
}

/// Decodes data using Reed-Solomon erasure coding for error correction.
pub fn rs_decode(data: &[u8]) -> Result<Vec<u8>, CryptoError> {
    if data.is_empty() {
        return Err(CryptoError::Message("Empty data for decoding".to_string()));
    }

    // Extract padding byte
    let padding_byte = data[0];
    let remaining = &data[1..];

    // Check that remaining data is divisible by 3
    if remaining.len() % 3 != 0 {
        return Err(CryptoError::Message("Incorrect encoded bytes length".to_string()));
    }

    let shard_bytes = remaining.len() / 3;

    // Split into 3 shards: original, recovery_0, recovery_1
    let original_shard = &remaining[0..shard_bytes];
    let recovery_shard_0 = &remaining[shard_bytes..2 * shard_bytes];
    let recovery_shard_1 = &remaining[2 * shard_bytes..3 * shard_bytes];

    // Apply byte-by-byte voting across all 3 shards for error correction
    // The Reed-Solomon encoding ensures proper redundancy, and voting handles byte-level corruption
    let shards = vec![original_shard, recovery_shard_0, recovery_shard_1];
    let mut result = vec![];

    for i in 0..shard_bytes {
        let mut freq = std::collections::HashMap::new();

        // Count frequency of each byte value at position i across all shards
        for shard in &shards {
            let byte = shard[i];
            *freq.entry(byte).or_insert(0) += 1;
        }

        // Find the byte with highest frequency (at least 2 occurrences for majority)
        // If no majority, use the byte from the original shard as fallback
        let most_frequent = freq
            .iter()
            .filter(|(_, &count)| count >= 2)
            .max_by_key(|(_, &count)| count)
            .map(|(&byte, _)| byte)
            .unwrap_or(original_shard[i]);

        result.push(most_frequent);
    }

    // Remove padding if it was added during encoding
    if padding_byte == 1 && !result.is_empty() {
        result.pop();
    }

    Ok(result)
}


#[allow(dead_code)]
fn pad_pkcs7(data: &[u8], block_size: usize) -> Vec<u8> {
    let mut byte_vec = data.to_vec();
    let padding_size = block_size - byte_vec.len() % block_size;
    let padding_char = padding_size as u8;
    let padding: Vec<u8> = vec![padding_char; padding_size];
    byte_vec.extend_from_slice(&padding);

    byte_vec
}

#[allow(dead_code)]
fn unpad_pkcs7(data: &[u8]) -> Vec<u8> {
    let mut byte_vec = data.to_vec();
    let padding_size = byte_vec.last().copied().unwrap() as usize;
    // Use `saturating_sub` to handle the case where there aren't N elements in the vector
    let final_length = byte_vec.len().saturating_sub(padding_size);
    byte_vec.truncate(final_length);

    byte_vec
}

#[cfg(test)]
mod tests {
    use super::{pad_pkcs7, rs_decode, rs_encode, unpad_pkcs7};

    #[test]
    fn encode_reconstruct_test() {
        let arr_32_orig = [1, 2, 3, 4, 5, 6, 7, 8, 9, 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 0, 1, 2];

        let mut arr_32_enc = rs_encode(&arr_32_orig).unwrap();
        println!("encoded_salt_32.len(): {}", &arr_32_enc.len());
        println!("encoded_salt_32: {:?}", &arr_32_enc);

        // Corrupt some data
        arr_32_enc[0] = 0;
        arr_32_enc[35] = 0;
        arr_32_enc[40] = 0;
        arr_32_enc[65] = 0;
        arr_32_enc[90] = 0;

        let arr_32_dec = rs_decode(&arr_32_enc).unwrap();

        println!("{:?}", &arr_32_orig);
        println!("{:?}", &arr_32_dec);

        assert_eq!(&arr_32_orig.to_vec(), &arr_32_dec);
    }

    #[test]
    fn pkcs_padding_unpadding() {
        let arr_12_orig = [1, 2, 3, 4, 5, 6, 7, 8, 9, 0, 1, 2];
        let arr_16_orig = [1, 2, 3, 4, 5, 6, 7, 8, 9, 0, 1, 2, 3, 4, 5, 6];

        let arr_12_padded = pad_pkcs7(&arr_12_orig, 16);
        let arr_16_padded = pad_pkcs7(&arr_16_orig, 16);

        let arr_12_unpadded = unpad_pkcs7(&arr_12_padded);
        let arr_16_unpadded = unpad_pkcs7(&arr_16_padded);

        println!("{:?}", &arr_12_padded);
        println!("{:?}", &arr_12_orig);
        println!("{:?}", &arr_12_unpadded);
        println!();
        println!("{:?}", &arr_16_padded);
        println!("{:?}", &arr_16_orig);
        println!("{:?}", &arr_16_unpadded);

        assert_eq!(&arr_12_orig, &arr_12_unpadded.as_slice());
        assert_eq!(&arr_16_orig, &arr_16_unpadded.as_slice());
    }
}
