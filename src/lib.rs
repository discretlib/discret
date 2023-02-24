#![allow(dead_code)]

pub mod cryptography;
pub mod database;
pub mod message;
pub mod network;
pub mod security_policy;

use std::{fs, path::PathBuf};

use cryptography::*;

use thiserror::Error;
#[derive(Error, Debug)]
pub enum Error {
    #[error("Invalid account")]
    InvalidAccount,
    #[error("An account allready exists")]
    AccountExists,

    #[error(transparent)]
    CryptoError(#[from] crate::cryptography::Error),

    #[error(transparent)]
    DatabaseError(#[from] crate::database::Error),

    #[error(transparent)]
    JSONError(#[from] serde_json::Error),

    #[error("{0}")]
    InvalidNode(String),

    #[error(transparent)]
    IoError(#[from] std::io::Error),

    #[error(transparent)]
    NetworkError(#[from] crate::network::error::Error),

    #[error(transparent)]
    AsyncRecvError(#[from] tokio::sync::oneshot::error::RecvError),

    #[error("{0}")]
    TokioError(String),

    #[error("{0}")]
    Unknown(String),
}

static DATA_PATH: &str = "data/discret";

// lazy_static::lazy_static! {
//     pub static ref LOGGED_USERS: Arc<Mutex<HashMap<String, Arc<Mutex<Database>>>>> =
//     Arc::new(Mutex::new(HashMap::new()));
// }

pub fn is_inialized() -> bool {
    let path: PathBuf = DATA_PATH.into();
    path.exists()
}

pub fn new_account(login: String, pass_phrase: String) -> Result<String, Error> {
    let secret = derive_pass_phrase(login, pass_phrase);
    let file_name = database_file_name_for(&secret);
    let path = build_path(DATA_PATH, &file_name)?;
    if path.exists() {
        return Err(Error::AccountExists);
    }

    Ok(file_name)
}

pub fn login(login: String, pass_phrase: String) -> Result<String, Error> {
    let secret = derive_pass_phrase(login, pass_phrase);
    let file_name = database_file_name_for(&secret);

    let path = build_path(DATA_PATH, &file_name)?;
    if !path.exists() {
        return Err(Error::InvalidAccount);
    }

    Ok(file_name)
}

pub struct QueryResult {
    pub columns: Vec<String>,
    pub data: Vec<Vec<String>>,
}

fn database_file_name_for(secret: &[u8; 32]) -> String {
    base64_encode(&cryptography::hash(secret))
}

fn build_path(data_folder: impl Into<PathBuf>, file_name: &String) -> Result<PathBuf, Error> {
    let mut path: PathBuf = data_folder.into();
    let subfolder = &file_name[0..2];
    path.push(subfolder);
    fs::create_dir_all(&path)?;
    path.push(file_name);
    Ok(path)
}
