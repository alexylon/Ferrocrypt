pub fn normalize_paths(src_file_path: &str, dest_dir_path: &str) -> (String, String) {
    let src_file_path_norm = src_file_path.replace('\\', "/");
    let mut dest_dir_path_norm = dest_dir_path.replace('\\', "/");

    if !dest_dir_path.ends_with('/') && !dest_dir_path.is_empty() {
        dest_dir_path_norm = format!("{dest_dir_path}/");
    }


    (src_file_path_norm, dest_dir_path_norm)
}