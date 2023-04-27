use std::fs;
use std::io;
use std::io::prelude::*;
use std::io::{Write};
use std::iter::Iterator;
use zip::write::FileOptions;
use std::fs::File;
use std::path::{Path};
use walkdir::{WalkDir};
use zip::result::ZipError;
use crate::common::{get_file_stem_to_string, normalize_paths};
use crate::CryptoError;

#[cfg(test)]
mod tests {
    use crate::archiver::{archive, unarchive};

    const SRC_FILEPATH: &str = "src/test_files/test-file.txt";
    const SRC_DIRPATH: &str = "src/test_files/test-folder";
    const DEST_DIRPATH: &str = "src/dest/";
    const SRC_FILEPATH_ZIPPED: &str = "src/dest/test-file.zip";
    const SRC_DIRPATH_ZIPPED: &str = "src/dest/test-folder.zip";

    #[test]
    fn archive_file_test() {
        match archive(SRC_FILEPATH, DEST_DIRPATH) {
            Ok(_) => println!("Zipped {}", SRC_FILEPATH),
            Err(e) => println!("Error: {:?}", e),
        }
    }

    #[test]
    fn unarchive_file_test() {
        match unarchive(SRC_FILEPATH_ZIPPED, DEST_DIRPATH) {
            Ok(_) => println!("Unzipped: {}", SRC_FILEPATH_ZIPPED),
            Err(e) => println!("Error: {:?}", e),
        }
    }

    #[test]
    fn archive_dir_test() {
        match archive(SRC_DIRPATH, DEST_DIRPATH) {
            Ok(_) => println!("Zipped {}", SRC_DIRPATH),
            Err(e) => println!("Error: {:?}", e),
        }
    }

    #[test]
    fn unarchive_dir_test() {
        match unarchive(SRC_DIRPATH_ZIPPED, DEST_DIRPATH) {
            Ok(_) => println!("Unzipped: {}", SRC_DIRPATH_ZIPPED),
            Err(e) => println!("Error: {:?}", e),
        }
    }
}

pub fn archive(input_path: &str, output_dir: &str) -> Result<String, CryptoError> {
    if Path::new(input_path).is_file() {
        archive_file(input_path, output_dir)
    } else {
        archive_dir(input_path, output_dir)
    }
}

fn archive_file(input_path: &str, output_dir: &str) -> Result<String, CryptoError> {
    let file_name_extension = Path::new(&input_path)
        .file_name().ok_or(ZipError::InvalidArchive("Cannot get file name"))?
        .to_str().ok_or(ZipError::InvalidArchive("Cannot convert file name to &str"))?;

    let file_stem = &get_file_stem_to_string(file_name_extension)?;

    println!("Adding file {:?} as {}{}/{} ...", input_path, output_dir, file_stem, file_name_extension);

    let output_file = File::create(format!("{}{}.zip", output_dir, file_stem))?;
    let mut zip = zip::ZipWriter::new(output_file);

    let options = FileOptions::default()
        .compression_method(zip::CompressionMethod::Stored)
        .large_file(true)
        .unix_permissions(0o755); // sets options for the zip file

    let mut buffer = Vec::new();

    zip.start_file(file_name_extension, options)?;

    let mut f = File::open(input_path)?;

    f.read_to_end(&mut buffer)?;
    zip.write_all(&buffer)?;
    buffer.clear();

    zip.finish()?;

    Ok(file_stem.to_string())
}

fn archive_dir(mut input_path: &str, output_dir: &str) -> Result<String, CryptoError> {
    // If last char is '/', remove it
    if input_path.ends_with('/') {
        input_path = &input_path[0..input_path.len() - 1];
    }

    // Get dir name from path
    let dir_name = Path::new(&input_path)
        .file_name().ok_or(CryptoError::InputPath("Input file or folder missing!".to_string()))?
        .to_str().ok_or(ZipError::InvalidArchive("Cannot convert directory name to &str"))?;

    let output_zip_filename = format!("{}{}.zip", output_dir, dir_name);
    let output_zip_path = Path::new(&output_zip_filename);
    let file = File::create(output_zip_path)?;
    let mut zip = zip::ZipWriter::new(file);
    let options = FileOptions::default()
        .compression_method(zip::CompressionMethod::Stored)
        .large_file(true)
        .unix_permissions(0o755);
    let walkdir = WalkDir::new(input_path);
    let iterator = walkdir.into_iter().filter_map(|e| e.ok());
    let mut buffer = Vec::new();

    for entry in iterator {
        let path = entry.path();
        match path.strip_prefix(input_path) {
            Ok(name) => {
                let path_str = path.to_str().ok_or(ZipError::InvalidArchive("Cannot convert path to &str"))?;
                let normalized_path_str = &normalize_paths(path_str, "").0;
                let name_str = name.to_str().ok_or(ZipError::InvalidArchive("Cannot convert name to &str"))?;
                let output_path_str = format!("{}/{}", dir_name, name_str);
                let normalized_output_path_str = &normalize_paths(&output_path_str, "").0;
                // Write file or directory explicitly
                // Some unzip tools unzip files with directory paths correctly, some do not!
                if path.is_file() {
                    println!("Adding file {} as {} ...", normalized_path_str, normalized_output_path_str);
                    zip.start_file(&output_path_str, options)?;
                    let mut f = File::open(path)?;

                    f.read_to_end(&mut buffer)?;
                    zip.write_all(&buffer)?;
                    buffer.clear();
                } else if !&output_path_str.is_empty() {
                    // Only if not root! Avoids path spec / warning
                    // and map name conversion failed error on unzip
                    println!("Adding dir {} as {} ...", normalized_path_str, normalized_output_path_str);
                    zip.add_directory(&output_path_str, options)?;
                }
            }
            Err(err) => { println!("StripPrefixError: {:?}", err); }
        }
    }

    zip.finish()?;

    Ok(dir_name.to_string())
}

pub fn unarchive(input_path: &str, output_dir: &str) -> Result<String, CryptoError> {
    let file = File::open(Path::new(&input_path))?;
    let mut archive = zip::ZipArchive::new(file)?;
    let mut output_path = "".to_string();

    for i in 0..archive.len() {
        let mut file = archive.by_index(i)?;
        let outpath = match file.enclosed_name() {
            Some(path) => path,
            None => continue,
        };
        let outpath_str = outpath.to_str().ok_or(ZipError::InvalidArchive("Cannot convert path to &str"))?;
        let outpath_full_str = normalize_paths(&format!("{}{}", output_dir, outpath_str), "").0;
        if i == 0 {
            output_path = outpath_full_str.clone();
        }
        let outpath_full = Path::new(&outpath_full_str);

        {
            let comment = file.comment();
            if !comment.is_empty() {
                println!("File {} comment: {}", i, comment);
            }
        }

        if (*file.name()).ends_with('/') {
            println!("Extracting dir to \"{}\" ...", &outpath_full_str);
            fs::create_dir_all(outpath_full)?;
        } else {
            println!(
                "Extracting file to \"{}\" ({} bytes) ...",
                &outpath_full_str,
                file.size()
            );
            if let Some(p) = outpath_full.parent() {
                if !p.exists() {
                    fs::create_dir_all(p)?;
                }
            }
            let mut outfile = File::create(outpath_full)?;
            io::copy(&mut file, &mut outfile)?;
        }

        //// Get and Set permissions
        // #[cfg(unix)]
        // {
        //     use std::os::unix::fs::PermissionsExt;
        //
        //     if let Some(mode) = file.unix_mode() {
        //         fs::set_permissions(&outpath, fs::Permissions::from_mode(mode)).unwrap();
        //     }
        // }
    }

    Ok(output_path)
}
