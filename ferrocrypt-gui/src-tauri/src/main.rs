// Prevents additional console window on Windows in release, DO NOT REMOVE!!
#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

use ferrocrypt::{hybrid_encryption, symmetric_encryption};

// Learn more about Tauri commands at https://tauri.app/v1/guides/features/command
#[tauri::command]
fn start(inpath: &str, outpath: &str, mut password: String, is_large_file: bool, mut keypath: String, symmetric_encryption_mode: bool) -> Result<String, String> {
    if symmetric_encryption_mode {
        match symmetric_encryption(inpath, outpath, password.as_mut_str(), is_large_file) {
            Ok(result) => {
                Ok(result)
            }
            Err(error) => {
                Err(error.to_string())
            }
        }
    } else {
        match hybrid_encryption(inpath, outpath, keypath.as_mut_str(), password.as_mut_str()) {
            Ok(result) => {
                Ok(result)
            }
            Err(error) => {
                Err(error.to_string())
            }
        }
    }

    // let result = symmetric_encryption(inpath, outpath, password.as_mut_str(), false)?;
    // //
    // Ok(result)
}

fn main() {
    tauri::Builder::default()
        .invoke_handler(tauri::generate_handler![start])
        .run(tauri::generate_context!())
        .expect("error while running tauri application");
}
