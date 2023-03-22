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
    use crate::zip::zip_file;
    use crate::zip::zip_dir;

    const FILEPATH_SRC: &str = "D:/test.md";
    const PATH_SRC: &str = "D:/test-folder";

    #[test]
    fn zip_file_test() {
        let path_dest = format!("{FILEPATH_SRC}.zip");
        match zip_file(FILEPATH_SRC) {
            Ok(_) => println!("done: {FILEPATH_SRC} written to {path_dest}"),
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
}

pub fn zip_file(src_filename: &str) -> zip::result::ZipResult<()> {
    if !Path::new(src_filename).is_file() {
        return Err(ZipError::FileNotFound);
    }

    let path_dest = format!("{src_filename}.zip");
    let path = Path::new(&path_dest);
    let file = File::create(&path)?;

    let mut zip = zip::ZipWriter::new(file);

    let options = FileOptions::default()
        .compression_method(zip::CompressionMethod::Deflated)
        .unix_permissions(0o755);

    let mut buffer = Vec::new();

    #[allow(deprecated)]
    zip.start_file_from_path(Path::new(src_filename), options)?;
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

    let path_dest = format!("{src_dir}.zip");
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
