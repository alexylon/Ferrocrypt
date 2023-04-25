use thiserror::Error;


#[derive(Error, Debug)]
pub enum CryptoError {
    #[error(transparent)]
    Io(#[from] std::io::Error),
    #[error(transparent)]
    ChaCha20Poly1305Error(#[from] chacha20poly1305::Error),
    #[error(transparent)]
    Argon2Error(#[from] argon2::Error),
    #[error(transparent)]
    OpensslError(#[from] openssl::error::ErrorStack),
    #[error(transparent)]
    WalkDirError(#[from] walkdir::Error),
    #[error(transparent)]
    ZipError(#[from] zip::result::ZipError),
    #[error(transparent)]
    ReedSolomonError(#[from] reed_solomon_erasure::Error),
    #[error(transparent)]
    BinCodeError(#[from] Box<bincode::ErrorKind>),
    #[error(transparent)]
    TryFromSliceError(#[from] std::array::TryFromSliceError),
    #[error("{msg:?}")]
    EncryptionDecryptionError { msg: String },
    #[error("Input file or folder missing")]
    InputPath(String),
    #[error("Message Error")]
    Message(String),
    #[error("Unknown error!")]
    Unknown,
}

// We must manually implement serde::Serialize for `tauri`
impl serde::Serialize for CryptoError {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
        where
            S: serde::ser::Serializer,
    {
        serializer.serialize_str(self.to_string().as_ref())
    }
}