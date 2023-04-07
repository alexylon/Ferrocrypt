use std::fs::File;
use std::io::{Read, Write};
use std::path::Path;
use reed_solomon_erasure::galois_8::ReedSolomon;


#[cfg(test)]
mod tests {
    use crate::reed_solomon::reed_solomon_encode;

    const FILE_NAME: &str = "src/test_files/big_image.png";

    #[test]
    fn reed_solomon_encode_test() {
        reed_solomon_encode(FILE_NAME);
    }
}

const OUTPUT_FILE_NAME: &str = "copy.jpg";


pub fn reed_solomon_encode(file_name: &str) {
    let path = Path::new(file_name);
    let display = path.display();
    let file = match File::open(path) {
        Err(why) => panic!("couldn't open {}: {}", display, why),
        Ok(file) => file,
    };

    let file_length = &file.metadata().unwrap().len();
    // println!("file_length: {}", file_length);

    let shard_len = (file_length / 14) as usize;
    println!("shard_len: {}", shard_len);

    let len: usize = shard_len;

    let mut file_slices = match make_file_slices(file, len) {
        Ok(file_slices) => { file_slices }
        Err(e) => {
            panic!("Error: {:?}", e);
        }
    };
    println!("Vector size is {} lines.", file_slices.len());

    //add parity slices
    let parity = 6;
    for _i in 0..parity {
        let mut parity_vec: Vec<u8> = Vec::new();
        for _j in 0..len {
            parity_vec.push(0);
        }
        file_slices.push(parity_vec);
    }


    //print out some details
    /*for _i in 0..lines.len(){
        println!("row {} = {:?}", _i, lines[_i]);
    }*/
    println!("Matrix is of length {}", (file_slices.len()));
    println!("Vector size is {} lines plus {} lines of parity.", file_slices.len() - parity, parity);

    let r = ReedSolomon::new(file_slices.len() - parity, parity).unwrap();
    r.encode(&mut file_slices).unwrap();

    //create a copy of the encoded file to work with.
    let mut shards: Vec<_> = file_slices.iter().cloned().map(Some).collect();

    // //write the file to new file to test the image
    // let path = Path::new("shards");
    // let mut file = match File::create(path) {
    //     Err(why) => panic!("couldn't open {}: {}", display, why),
    //     Ok(file) => file,
    // };
    //
    // for shard in shards {
    //     file.write_all(&shard.unwrap()).expect("TODO: panic message");
    // }

    //remove 2 shards for reconstruction later
    shards[0] = None;
    shards[4] = None;
    shards[15] = None;

    // Try to reconstruct missing shards
    r.reconstruct(&mut shards).unwrap();

    // Convert back to normal shard arrangement
    let result: Vec<_> = shards.into_iter().flatten().collect();

    assert!(r.verify(&result).unwrap());
    assert_eq!(file_slices, result);

    /*for slice in result.iter(){
        println!("{:?}", slice);
    }*/
    println!("File reconstruction successful.");

    //write the file to new file to test the image
    let path = Path::new(OUTPUT_FILE_NAME);
    let mut file = match File::create(path) {
        Err(why) => panic!("couldn't open {}: {}", display, why),
        Ok(file) => file,
    };

    for i in 0..result.len() - parity {
        file.write_all(&result[i]).expect("TODO: panic message");
    }


//
//     /*for row in &result{
//         let data = row;
//         for i in data.iter(){
//             write!(f,"{}", i);
//         }
//     }*/
}

pub fn _reed_solomon_decode(_file_name: &str) {}

fn make_file_slices(
    mut file: File,
    chunk_length: usize,
) -> Result<Vec<Vec<u8>>, Box<dyn std::error::Error>> {
    let mut file_slices = Vec::new();
    let mut slice_buffer = vec![0_u8; chunk_length];
    let mut bytes_in_last_row = 0;

    loop {
        // read (may-be) incomplete chunk
        let bytes_read = file.read(&mut slice_buffer[bytes_in_last_row..])?;
        if bytes_read == 0 {
            break; // EOF
        }

        // the current chunk is complete
        bytes_in_last_row = 0;
        let mut tmp = vec![0_u8; chunk_length];
        std::mem::swap(&mut tmp, &mut slice_buffer);
        file_slices.push(tmp);
    }
    Ok(file_slices)
}
