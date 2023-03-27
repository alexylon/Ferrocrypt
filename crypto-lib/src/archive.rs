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
    use crate::archive::{archive, unarchive};

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

fn archive_file(src_filename: &str) -> zip::result::ZipResult<String> {
    let file_name_ext = Path::new(&src_filename).file_name().unwrap().to_str().unwrap();
    let file_name = Path::new(&file_name_ext).file_stem().unwrap().to_str().unwrap();
    let path_dest = format!("{file_name}.zip");
    let file = File::create(&path_dest)?;
    let mut zip = zip::ZipWriter::new(file);
    let options = FileOptions::default()
        .compression_method(zip::CompressionMethod::Deflated)
        .unix_permissions(0o755);
    let mut buffer = Vec::new();

    #[allow(deprecated)]
    zip.start_file_from_path(Path::new(file_name_ext), options)?;
    let mut f = File::open(src_filename)?;

    f.read_to_end(&mut buffer)?;
    zip.write_all(&buffer)?;
    buffer.clear();

    zip.finish()?;
    Ok(file_name.to_string())
}

fn archive_dir(src_dir: &str) -> zip::result::ZipResult<String> {
    let dir_name;

    // Get dir name from path
    match src_dir.chars().rev().position(|c| c == '/') {
        None => { dir_name = src_dir }
        Some(slash_position) => {
            let dir_chars_number = src_dir.chars().count();
            let last_slash = dir_chars_number - slash_position;
            dir_name = &src_dir[last_slash..];
        }
    }

    let path_dest = format!("{dir_name}.zip");
    let path = Path::new(&path_dest);
    let file = File::create(path)?;
    let mut zip = zip::ZipWriter::new(file);
    let options = FileOptions::default()
        .compression_method(zip::CompressionMethod::Deflated)
        .unix_permissions(0o755);
    let walkdir = WalkDir::new(src_dir);
    let it = walkdir.into_iter().filter_map(|e| e.ok());
    let mut buffer = Vec::new();

    for entry in it {
        let path = entry.path();
        match path.strip_prefix(Path::new(src_dir)) {
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
                    // and mapname conversion failed error on unzip
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

pub fn unarchive(src_filename: &str) -> zip::result::ZipResult<String> {
    // let file_path = std::path::Path::new(&src_filename[0..src_filename.len() - 4]);
    let file_path = std::path::Path::new(&src_filename);
    let file = fs::File::open(file_path).unwrap();
    let file_name = Path::new(&src_filename).file_stem().unwrap().to_str().unwrap();
    let mut archive = zip::ZipArchive::new(file).unwrap();

    for i in 0..archive.len() {
        let mut file = archive.by_index(i).unwrap();
        let outpath = match file.enclosed_name() {
            Some(path) => path,
            None => continue,
        };
        let outpath_str = outpath.to_str().unwrap();
        let outpath_str_full = format!("{file_name}/{outpath_str}");
        let outpath_full = std::path::Path::new(&outpath_str_full);

        {
            let comment = file.comment();
            if !comment.is_empty() {
                println!("File {i} comment: {comment}");
            }
        }

        if (*file.name()).ends_with('/') {
            println!("Item {} extracted to \"{}\"", i + 1, outpath_full.display());
            fs::create_dir_all(&outpath_full).unwrap();
        } else {
            println!(
                "Item {} extracted to \"{}\" ({} bytes)",
                i + 1,
                outpath_full.display(),
                file.size()
            );
            if let Some(p) = outpath_full.parent() {
                if !p.exists() {
                    fs::create_dir_all(p).unwrap();
                }
            }
            let mut outfile = fs::File::create(&outpath_full).unwrap();
            io::copy(&mut file, &mut outfile).unwrap();
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

    Ok(file_name.to_string())
}
