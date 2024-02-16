#![allow(dead_code)]

pub mod cryptography;
pub mod database;
pub mod message;
pub mod network;
pub mod synchronisation;

use std::{
    fs::{self, File},
    path::PathBuf,
};

use cryptography::*;

use database::{
    graph_database::GraphDatabase,
    query_language::{
        data_model::DataModel, deletion::Deletion, mutation::Mutation, parameter::Parameters,
        query::Query,
    },
};

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
    ParsingError(#[from] crate::database::query_language::Error),

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

// lazy_static::lazy_static! {
//     pub static ref LOGGED_USERS: Arc<Mutex<HashMap<String, Arc<Mutex<Database>>>>> =
//     Arc::new(Mutex::new(HashMap::new()));
// }

fn build_path(data_folder: impl Into<PathBuf>, file_name: &String) -> Result<PathBuf, Error> {
    let mut path: PathBuf = data_folder.into();
    let subfolder = &file_name[0..2];
    path.push(subfolder);
    fs::create_dir_all(&path)?;
    path.push(file_name);
    Ok(path)
}

pub struct Account {
    sign_key: Ed2519SigningKey,
    secret: [u8; 32],
}
impl Account {
    pub fn create(login: String, pass_phrase: String, data_folder: &str) -> Result<Account, Error> {
        let secret = derive_pass_phrase(login, pass_phrase);
        Self::create_from_secret(secret, data_folder)
    }

    pub fn create_from_secret(secret: [u8; 32], data_folder: &str) -> Result<Account, Error> {
        let file_name = Self::derive_account_file(&secret);
        let account_path = build_path(data_folder, &file_name)?;
        if account_path.exists() {
            return Err(Error::AccountExists);
        }
        File::create(account_path)?;
        let sign_key = Ed2519SigningKey::create_from(&secret);

        Ok(Self {
            sign_key,
            secret: Self::derive_secret(&secret),
        })
    }

    pub fn login(login: String, pass_phrase: String, data_folder: &str) -> Result<Account, Error> {
        let secret = derive_pass_phrase(login, pass_phrase);
        Self::login_from_secret(secret, data_folder)
    }

    pub fn login_from_secret(secret: [u8; 32], data_folder: &str) -> Result<Account, Error> {
        let file_name = Self::derive_account_file(&secret);
        let account_path = build_path(data_folder, &file_name)?;
        if !account_path.exists() {
            return Err(Error::InvalidAccount);
        }
        let sign_key = Ed2519SigningKey::create_from(&secret);

        Ok(Self {
            sign_key,
            secret: Self::derive_secret(&secret),
        })
    }

    fn derive_account_file(secret: &[u8; 32]) -> String {
        const DERIVE_ACCOUNT_FILE_SEED: &str = "DERIVE_ACCOUNT_FILE_SEED";
        base64_encode(&cryptography::derive_key(DERIVE_ACCOUNT_FILE_SEED, secret))
    }

    fn derive_secret(secret: &[u8; 32]) -> [u8; 32] {
        const DERIVE_SECRET_SEED: &str = "DERIVE_SECRET_SEED";
        cryptography::derive_key(DERIVE_SECRET_SEED, secret)
    }
}

struct Application {
    name: String,
    data_model: DataModel,
    graph_database: GraphDatabase,
    database_path: PathBuf,
    signing_key: Ed2519SigningKey,
}
impl Application {
    pub fn new(
        name: &str,
        secret: &[u8; 32],
        data_folder: PathBuf,
        data_model: &str,
    ) -> Result<Self, Error> {
        let database_secret = derive_key(name, secret);
        let database_name = derive_key("DATABASE_NAME", &database_secret);
        let signature_key = derive_key("SIGNING_KEY", secret);
        let signing_key = Ed2519SigningKey::create_from(&signature_key);

        let database_path = build_path(data_folder, &base64_encode(&database_name))?;

        let graph_database =
            GraphDatabase::new(&database_path, &database_secret, 8192, false, 4, 1000)?;

        let data_model = DataModel::parse(data_model)?;
        Ok(Self {
            name: name.to_string(),
            data_model,
            graph_database,
            database_path,
            signing_key,
        })
    }

    pub fn query(&self, query: &str, _params: Option<Parameters>) -> Result<String, Error> {
        let querytype = query.trim().split_once(' ');
        if let Some(e) = querytype {
            match e.0 {
                "query" | "subscription" => {
                    println!("query");
                    let _query = Query::parse(query, &self.data_model)?;
                }
                "mutation" => {
                    println!("mutation");
                    let _mutation = Mutation::parse(query, &self.data_model)?;
                }
                "deletion" => {
                    let _deletion = Deletion::parse(query, &self.data_model)?;
                    println!("deletion")
                }

                _ => {
                    return Err(Error::ParsingError(
                        crate::database::query_language::Error::InvalidQuery(format!(
                            "Invalid Query {}",
                            query
                        )),
                    ))
                }
            }
        } else {
            return Err(Error::ParsingError(
                crate::database::query_language::Error::InvalidQuery(format!(
                    "Invalid Query {}",
                    query
                )),
            ));
        }
        Ok("".to_string())
    }
}

#[cfg(test)]
mod tests {

    use super::*;
    const DATA_PATH: &str = "test/data/database/";

    #[tokio::test(flavor = "multi_thread")]
    async fn connect() {
        let secret = hash(b"not so secret");
        let data_model = "   
        Person {
            name : String,
            surname : String,
            parents : [Person],
            age : Integer,
            weight : Float,
            is_human : Boolean
        }";
        let app = Application::new("my_new_app", &secret, DATA_PATH.into(), data_model).unwrap();

        app.query("query", None).unwrap();
    }
}
