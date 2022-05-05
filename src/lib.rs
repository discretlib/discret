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
static DATA_PATH: &str = "data/discret";

lazy_static::lazy_static! {
    pub static ref LOGGED_USERS: Arc<Mutex<HashMap<String, Arc<Mutex<Database>>>>> =
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
            .insert(file_name.clone(), Arc::new(Mutex::new(database)));
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
            .insert(file_name.clone(), Arc::new(Mutex::new(database)));
    }
    Ok(file_name)
}

pub struct QueryResult {
    columns: Vec<String>,
    data: Vec<Vec<String>>,
}

pub fn query(database: String, query: String) -> Result<QueryResult, error::Error> {
    let sdq = get_database(database);
    let db = sdq.unwrap();
    let db = db.lock().unwrap();
    let conn = db.get_connection()?;

    let mut stmt = conn.prepare(&query)?;
    let colu = stmt.column_names();
    let mut columns: Vec<String> = vec![];
    for s in colu.iter() {
        columns.push(s.to_string());
    }

    let row_iter = stmt.query_map([], |row| {
        let mut line: Vec<String> = vec![];
        for i in 0..columns.len() {
            line.push(row.get(i)?);
        }
        Ok(line)
    })?;

    let mut data: Vec<Vec<String>> = vec![];
    for row in row_iter {
        data.push(row?);
    }
    Ok(QueryResult { columns, data })
}

fn get_database(database: String) -> Result<Arc<Mutex<Database>>, error::Error> {
    let map = LOGGED_USERS.lock().unwrap();
    let db = map.get(&database);
    if db.is_none() {
        return Err(error::Error::Unknown("Invalid database name".to_string()));
    }
    Ok(db.unwrap().clone())
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
