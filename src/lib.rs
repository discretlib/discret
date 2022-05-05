#![allow(dead_code)]

pub mod cryptography;
pub mod database;
pub mod error;
pub mod message;
pub mod network;

use std::{
    collections::HashMap,
    fs,
    path::PathBuf,
    sync::{Arc, Mutex},
};

use cryptography::*;
use database::Database;
static DATA_PATH: &str = "test/data/";

lazy_static::lazy_static! {
    pub static ref LOGGED_USERS: Arc<Mutex<HashMap<String, Database>>> =
    Arc::new(Mutex::new(HashMap::new()));
}

pub fn is_inialized() -> bool {
    let path: PathBuf = DATA_PATH.into();
    path.exists()
}

pub fn new_account(login: String, pass_phrase: String) -> Result<String, error::Error> {
    let secret = derive_pass_phrase(login, pass_phrase);
    let file_name = database_file_name_for(&secret);
    let path = build_path(DATA_PATH, &file_name)?;
    if path.exists() {
        return Err(error::Error::AccountExists);
    }
    let database = start_database(path, secret);
    {
        LOGGED_USERS
            .lock()
            .unwrap()
            .insert(file_name.clone(), database);
    }
    Ok(file_name)
}

pub fn login(login: String, pass_phrase: String) -> Result<String, error::Error> {
    let secret = derive_pass_phrase(login, pass_phrase);
    let file_name = database_file_name_for(&secret);
    {
        if LOGGED_USERS.lock().unwrap().get(&file_name).is_none() {
            return Ok(file_name);
        }
    }
    let path = build_path(DATA_PATH, &file_name)?;
    if !path.exists() {
        return Err(error::Error::InvalidAccount);
    }

    let database = start_database(path, secret);
    {
        LOGGED_USERS
            .lock()
            .unwrap()
            .insert(file_name.clone(), database);
    }
    Ok(file_name)
}

fn database_file_name_for(secret: &[u8; 32]) -> String {
    hex::encode(cryptography::hash(secret))
}

fn start_database(path: PathBuf, secret: [u8; 32]) -> Database {
    Database::new(path, secret)
}

fn build_path(
    data_folder: impl Into<PathBuf>,
    file_name: &String,
) -> Result<PathBuf, error::Error> {
    let mut path: PathBuf = data_folder.into();
    let subfolder = &file_name[0..2];
    path.push(subfolder);
    fs::create_dir_all(&path)?;
    path.push(file_name);
    Ok(path)
}
