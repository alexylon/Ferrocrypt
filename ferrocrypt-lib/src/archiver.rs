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
            Ok(_) => println!("Zipped {SRC_FILEPATH}"),
            Err(e) => println!("Error: {e:?}"),
        }
    }

    #[test]
    fn unarchive_file_test() {
        match unarchive(SRC_FILEPATH_ZIPPED, DEST_DIRPATH) {
            Ok(_) => println!("Unzipped: {SRC_FILEPATH_ZIPPED}"),
            Err(e) => println!("Error: {e:?}"),
        }
    }

    #[test]
    fn archive_dir_test() {
        match archive(SRC_DIRPATH, DEST_DIRPATH) {
            Ok(_) => println!("Zipped {SRC_DIRPATH}"),
            Err(e) => println!("Error: {e:?}"),
        }
    }

    #[test]
    fn unarchive_dir_test() {
        match unarchive(SRC_DIRPATH_ZIPPED, DEST_DIRPATH) {
            Ok(_) => println!("Unzipped: {SRC_DIRPATH_ZIPPED}"),
            Err(e) => println!("Error: {e:?}"),
        }
    }
}

pub fn archive(src_path: &str, dest_dir_path: &str) -> Result<String, CryptoError> {
    if Path::new(src_path).is_file() {
        archive_file(src_path, dest_dir_path)
    } else {
        archive_dir(src_path, dest_dir_path)
    }
}

fn archive_file(src_file_path: &str, dest_dir_path: &str) -> Result<String, CryptoError> {
    let file_name_ext = Path::new(&src_file_path)
        .file_name().ok_or(ZipError::InvalidArchive("Cannot get file name"))?
        .to_str().ok_or(ZipError::InvalidArchive("Cannot convert file name to &str"))?;
    let file_stem = &get_file_stem_to_string(file_name_ext)?;
    println!("Adding file {src_file_path:?} as {dest_dir_path}{file_stem}/{file_name_ext} ...");
    let path_dest = format!("{dest_dir_path}{file_stem}.zip");
    let file = File::create(path_dest)?;
    let mut zip = zip::ZipWriter::new(file);
    let options = FileOptions::default()
        .compression_method(zip::CompressionMethod::Stored)
        .unix_permissions(0o755);
    let mut buffer = Vec::new();

    #[allow(deprecated)]
    zip.start_file_from_path(Path::new(file_name_ext), options)?;
    let mut f = File::open(src_file_path)?;

    f.read_to_end(&mut buffer)?;
    zip.write_all(&buffer)?;
    buffer.clear();

    zip.finish()?;

    Ok(file_stem.to_string())
}

fn archive_dir(mut src_dir_path: &str, dest_dir_path: &str) -> Result<String, CryptoError> {
    // If last char is '/', remove it
    if src_dir_path.ends_with('/') {
        src_dir_path = &src_dir_path[0..src_dir_path.len() - 1];
    }

    // Get dir name from path
    let dir_name = Path::new(&src_dir_path)
        .file_name().ok_or(CryptoError::InputPath("Input file or folder missing!".to_string()))?
        .to_str().ok_or(ZipError::InvalidArchive("Cannot convert directory name to &str"))?;

    let path_dest_str = format!("{dest_dir_path}{dir_name}.zip");
    let path_dest = Path::new(&path_dest_str);
    let file = File::create(path_dest)?;
    let mut zip = zip::ZipWriter::new(file);
    let options = FileOptions::default()
        .compression_method(zip::CompressionMethod::Stored)
        .unix_permissions(0o755);
    let walkdir = WalkDir::new(src_dir_path);
    let it = walkdir.into_iter().filter_map(|e| e.ok());
    let mut buffer = Vec::new();

    for entry in it {
        let path = entry.path();
        match path.strip_prefix(src_dir_path) {
            Ok(name) => {
                let path_str = path.to_str().ok_or(ZipError::InvalidArchive("Cannot convert path to &str"))?;
                let path_str_norm = &normalize_paths(path_str, "").0;
                let name_str = name.to_str().ok_or(ZipError::InvalidArchive("Cannot convert name to &str"))?;
                let dest_path_str = format!("{dir_name}/{name_str}");
                let dest_path_str_norm = &normalize_paths(&dest_path_str, "").0;
                let dest_path = Path::new(&dest_path_str);
                // Write file or directory explicitly
                // Some unzip tools unzip files with directory paths correctly, some do not!
                if path.is_file() {
                    println!("Adding file {path_str_norm} as {dest_path_str_norm} ...");
                    #[allow(deprecated)]
                    zip.start_file_from_path(dest_path, options)?;
                    let mut f = File::open(path)?;

                    f.read_to_end(&mut buffer)?;
                    zip.write_all(&buffer)?;
                    buffer.clear();
                } else if !dest_path.as_os_str().is_empty() {
                    // Only if not root! Avoids path spec / warning
                    // and map name conversion failed error on unzip
                    println!("Adding dir {path_str_norm} as {dest_path_str_norm} ...");
                    #[allow(deprecated)]
                    zip.add_directory_from_path(dest_path, options)?;
                }
            }
            Err(err) => { println!("StripPrefixError: {err:?}"); }
        }
    }

    zip.finish()?;

    Ok(dir_name.to_string())
}

pub fn unarchive(src_file_path: &str, dest_dir_path: &str) -> Result<String, CryptoError> {
    let file = File::open(Path::new(&src_file_path))?;
    let file_stem = &get_file_stem_to_string(src_file_path)?;
    let mut archive = zip::ZipArchive::new(file)?;

    for i in 0..archive.len() {
        let mut file = archive.by_index(i)?;
        let outpath = match file.enclosed_name() {
            Some(path) => path,
            None => continue,
        };
        let outpath_str = outpath.to_str().ok_or(ZipError::InvalidArchive("Cannot convert path to &str"))?;
        let outpath_str_full = format!("{}{}", dest_dir_path, outpath_str);
        let outpath_str_full_norm = normalize_paths(&outpath_str_full, "").0;
        let outpath_full = Path::new(&outpath_str_full);

        {
            let comment = file.comment();
            if !comment.is_empty() {
                println!("File {i} comment: {comment}");
            }
        }

        if (*file.name()).ends_with('/') {
            println!("Extracting dir to \"{}\" ...", &outpath_str_full_norm);
            fs::create_dir_all(outpath_full)?;
        } else {
            println!(
                "Extracting file to \"{}\" ({} bytes) ...",
                &outpath_str_full_norm,
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

    Ok(file_stem.to_string())
}
