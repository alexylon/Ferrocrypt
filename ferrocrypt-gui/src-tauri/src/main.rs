// Prevents additional console window on Windows in release, DO NOT REMOVE!!
#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

use ferrocrypt::{
    CryptoError,
    symmetric_encryption,
};

// Learn more about Tauri commands at https://tauri.app/v1/guides/features/command
#[tauri::command]
fn encrypt(file: &str, mut password: String) -> Result<(), CryptoError> {
    symmetric_encryption(file, "/Users/alex/", password.as_mut_str(), false)?;

    Ok(())
}

fn main() {
    tauri::Builder::default()
        .invoke_handler(tauri::generate_handler![encrypt])
        .run(tauri::generate_context!())
        .expect("error while running tauri application");
}
