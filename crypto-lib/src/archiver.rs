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

#[cfg(test)]
mod tests {
    use crate::archiver::{archive, unarchive};

    const FILEPATH_SRC: &str = "src/test_files/test-file.txt";
    const DIRPATH_SRC: &str = "src/test_files/test-folder";
    const PATH_SRC_ZIPPED: &str = "test-file.zip";

    #[test]
    fn archive_file_test() {
        match archive(FILEPATH_SRC) {
            Ok(_) => println!("Zipped {FILEPATH_SRC}"),
            Err(e) => println!("Error: {e:?}"),
        }
    }

    #[test]
    fn archive_dir_test() {
        match archive(DIRPATH_SRC) {
            Ok(_) => println!("Zipped {DIRPATH_SRC}"),
            Err(e) => println!("Error: {e:?}"),
        }
    }

    #[test]
    fn unarchive_test() {
        match unarchive(PATH_SRC_ZIPPED) {
            Ok(_) => println!("Unzipped: {PATH_SRC_ZIPPED}"),
            Err(e) => println!("Error: {e:?}"),
        }
    }
}

pub fn archive(path: &str) -> zip::result::ZipResult<String> {
    let file_name;
    if Path::new(path).is_file() {
        file_name = archive_file(path)?;
    } else {
        file_name = archive_dir(path)?;
    }

    Ok(file_name)
}

fn archive_file(file_path: &str) -> zip::result::ZipResult<String> {
    let file_name_ext = Path::new(&file_path)
        .file_name().ok_or(ZipError::InvalidArchive("Cannot get file name"))?
        .to_str().ok_or(ZipError::InvalidArchive("Cannot convert file name to &str"))?;
    let file_stem = Path::new(&file_name_ext)
        .file_stem().ok_or(ZipError::InvalidArchive("Cannot get file stem"))?
        .to_str().ok_or(ZipError::InvalidArchive("Cannot convert file stem to &str"))?;
    println!("adding file {file_path:?} as {file_stem}/{file_name_ext} ...");
    let path_dest = format!("{file_stem}.zip");
    let file = File::create(&path_dest)?;
    let mut zip = zip::ZipWriter::new(file);
    let options = FileOptions::default()
        .compression_method(zip::CompressionMethod::Deflated)
        .unix_permissions(0o755);
    let mut buffer = Vec::new();

    #[allow(deprecated)]
    zip.start_file_from_path(Path::new(file_name_ext), options)?;
    let mut f = File::open(file_path)?;

    f.read_to_end(&mut buffer)?;
    zip.write_all(&buffer)?;
    buffer.clear();

    zip.finish()?;

    Ok(file_stem.to_string())
}

fn archive_dir(mut dir_path: &str) -> zip::result::ZipResult<String> {
    // If last char is '/' or '\', remove it
    let last_char = dir_path.chars().last().ok_or(ZipError::InvalidArchive("Cannot get last char"))?;
    if last_char == '/' || last_char == '\\' {
        dir_path = &dir_path[0..dir_path.len() - 1];
    }
    let dir_name;

    // Get dir name from path
    match dir_path.chars().rev().position(|c| c == '/') {
        None => { dir_name = dir_path }
        Some(slash_position) => {
            let dir_chars_number = dir_path.chars().count();
            let last_slash = dir_chars_number - slash_position;
            dir_name = &dir_path[last_slash..];
        }
    }

    let path_dest = format!("{dir_name}.zip");
    let path = Path::new(&path_dest);
    let file = File::create(path)?;
    let mut zip = zip::ZipWriter::new(file);
    let options = FileOptions::default()
        .compression_method(zip::CompressionMethod::Deflated)
        .unix_permissions(0o755);
    let walkdir = WalkDir::new(dir_path);
    let it = walkdir.into_iter().filter_map(|e| e.ok());
    let mut buffer = Vec::new();

    for entry in it {
        let path = entry.path();
        match path.strip_prefix(Path::new(dir_path)) {
            Ok(name) => {
                // Write file or directory explicitly
                // Some unzip tools unzip files with directory paths correctly, some do not!
                if path.is_file() {
                    println!("adding file {path:?} as {name:?} ...");
                    #[allow(deprecated)]
                    zip.start_file_from_path(name, options)?;
                    let mut f = File::open(path)?;

                    f.read_to_end(&mut buffer)?;
                    zip.write_all(&buffer)?;
                    buffer.clear();
                } else if !name.as_os_str().is_empty() {
                    // Only if not root! Avoids path spec / warning
                    // and map name conversion failed error on unzip
                    println!("adding dir {path:?} as {name:?} ...");
                    #[allow(deprecated)]
                    zip.add_directory_from_path(name, options)?;
                }
            }
            Err(err) => { println!("StripPrefixError: {err:?}"); }
        }
    }

    zip.finish()?;

    Ok(dir_name.to_string())
}

pub fn unarchive(file_path: &str) -> zip::result::ZipResult<String> {
    let file = File::open(Path::new(&file_path))?;
    let file_stem = Path::new(&file_path)
        .file_stem().ok_or(ZipError::InvalidArchive("Cannot get file stem"))?
        .to_str().ok_or(ZipError::InvalidArchive("Cannot convert file stem to &str"))?;
    let mut archive = zip::ZipArchive::new(file)?;

    for i in 0..archive.len() {
        let mut file = archive.by_index(i)?;
        let outpath = match file.enclosed_name() {
            Some(path) => path,
            None => continue,
        };
        let outpath_str = outpath.to_str().ok_or(ZipError::InvalidArchive("Cannot convert outpath to &str"))?;
        let outpath_str_full = format!("{file_stem}/{outpath_str}");
        let outpath_full = Path::new(&outpath_str_full);

        {
            let comment = file.comment();
            if !comment.is_empty() {
                println!("File {i} comment: {comment}");
            }
        }

        if (*file.name()).ends_with('/') {
            println!("extracting dir to \"{}\"...", outpath_full.display());
            fs::create_dir_all(&outpath_full)?;
        } else {
            println!(
                "extracting file to \"{}\" ({} bytes)...",
                outpath_full.display(),
                file.size()
            );
            if let Some(p) = outpath_full.parent() {
                if !p.exists() {
                    fs::create_dir_all(p)?;
                }
            }
            let mut outfile = File::create(&outpath_full)?;
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
