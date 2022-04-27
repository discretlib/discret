#![allow(dead_code)]

mod cryptography;
mod database;
mod error;
mod network;
use cryptography::*;
use database::Database;

pub fn create(pass_phrase: String) -> Result<Database, error::Error> {
    let secret = derive_pass_phrase(pass_phrase);
    Ok(start_database(secret))
}

pub fn open(pass_phrase: String) -> Result<Database, error::Error> {
    let secret = derive_pass_phrase(pass_phrase);
    Ok(start_database(secret))
}

fn start_database(secret: [u8; 32]) -> Database {
    Database::new("./", secret)
}
