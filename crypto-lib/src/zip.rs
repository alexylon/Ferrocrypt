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
    use crate::zip::{unzip, zip_file};
    use crate::zip::zip_dir;

    const FILEPATH_SRC: &str = "src/test_files/test1.txt";
    const PATH_SRC: &str = "/Users/alex/Downloads/Ubuntu_Mono";
    const PATH_SRC_ZIPPED: &str = "Ubuntu_Mono.zip";

    #[test]
    fn zip_file_test() {
        match zip_file(FILEPATH_SRC) {
            Ok(_) => println!("Zipped {FILEPATH_SRC}"),
            Err(e) => println!("Error: {e:?}"),
        }
    }

    #[test]
    fn zip_dir_test() {
        let path_dest = format!("{PATH_SRC}.zip");
        match zip_dir(PATH_SRC) {
            Ok(_) => println!("done: {PATH_SRC} written to {path_dest}"),
            Err(e) => println!("Error: {e:?}"),
        }
    }

    #[test]
    fn unzip_test() {
        match unzip(PATH_SRC_ZIPPED) {
            Ok(_) => println!("Unzipped {PATH_SRC_ZIPPED}"),
            Err(e) => println!("Error: {e:?}"),
        }
    }
}

pub fn zip() -> zip::result::ZipResult<()> {

}

pub fn zip_file(src_filename: &str) -> zip::result::ZipResult<()> {
    if !Path::new(src_filename).is_file() {
        return Err(ZipError::FileNotFound);
    }

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
    Ok(())
}

pub fn zip_dir(src_dir: &str) -> zip::result::ZipResult<()> {
    if !Path::new(src_dir).is_dir() {
        return Err(ZipError::FileNotFound);
    }

    let mut dir_name = "";

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
    Ok(())
}

pub fn unzip(src_filename: &str) -> zip::result::ZipResult<()> {
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

    Ok(())
}
