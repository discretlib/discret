#![allow(dead_code)]

mod database;
mod date_utils;
mod event_service;
mod log_service;
mod message;
mod network;
mod peer_connection_service;
mod security;
mod synchronisation;

pub type Result<T> = std::result::Result<T, Error>;
use thiserror::Error;

#[derive(Error, Debug)]
pub enum Error {
    #[error(transparent)]
    CryptoError(#[from] crate::security::Error),

    #[error(transparent)]
    DatabaseError(#[from] crate::database::Error),

    #[error(transparent)]
    ParsingError(#[from] crate::database::query_language::Error),

    #[error(transparent)]
    JSONError(#[from] serde_json::Error),

    #[error(transparent)]
    TokioJoinError(#[from] tokio::task::JoinError),

    #[error(transparent)]
    TimeoutElapsed(#[from] tokio::time::error::Elapsed),

    #[error(transparent)]
    SerialisationError(#[from] Box<bincode::ErrorKind>),

    #[error(transparent)]
    IoError(#[from] std::io::Error),

    #[error(transparent)]
    RecvError(#[from] tokio::sync::oneshot::error::RecvError),

    #[error(transparent)]
    SynchError(#[from] crate::synchronisation::Error),

    #[error("Invalid account")]
    InvalidAccount,
    #[error("An account allready exists")]
    AccountExists,

    #[error("Provider signer is not allowed to sign the datamodel")]
    InvalidSigner(),

    #[error("Application Template cannot be updated with a template with another id")]
    InvalidUpdateTemplate(),

    #[error("tokio send error")]
    SendError(String),

    #[error("{0}")]
    ChannelError(String),

    #[error("Timeout occured while sending {0}")]
    TimeOut(String),

    #[error("Remote Room did not sent back a room definition {0}")]
    RoomUnknow(String),

    #[error("An error occured while computing daily logs: {0}")]
    ComputeDailyLog(String),
}

// lazy_static::lazy_static! {
//     pub static ref LOGGED_USERS: Arc<Mutex<HashMap<String, Arc<Mutex<Database>>>>> =
//     Arc::new(Mutex::new(HashMap::new()));
// }

// fn build_path(data_folder: impl Into<PathBuf>, file_name: &String) -> Result<PathBuf> {
//     let mut path: PathBuf = data_folder.into();
//     let subfolder = &file_name[0..2];
//     path.push(subfolder);
//     fs::create_dir_all(&path)?;
//     path.push(file_name);
//     Ok(path)
// }

// pub struct Account {
//     sign_key: Ed25519SigningKey,
//     secret: [u8; 32],
// }
// impl Account {
//     pub fn create(login: String, pass_phrase: String, data_folder: &str) -> Result<Account> {
//         let secret = derive_pass_phrase(login, pass_phrase);
//         Self::create_from_secret(secret, data_folder)
//     }

//     pub fn create_from_secret(secret: [u8; 32], data_folder: &str) -> Result<Account> {
//         let file_name = Self::derive_account_file(&secret);
//         let account_path = build_path(data_folder, &file_name)?;
//         if account_path.exists() {
//             return Err(Error::AccountExists);
//         }
//         File::create(account_path)?;
//         let sign_key = Ed25519SigningKey::create_from(&secret);

//         Ok(Self {
//             sign_key,
//             secret: Self::derive_secret(&secret),
//         })
//     }

//     pub fn login(login: String, pass_phrase: String, data_folder: &str) -> Result<Account> {
//         let secret = derive_pass_phrase(login, pass_phrase);
//         Self::login_from_secret(secret, data_folder)
//     }

//     pub fn login_from_secret(secret: [u8; 32], data_folder: &str) -> Result<Account> {
//         let file_name = Self::derive_account_file(&secret);
//         let account_path = build_path(data_folder, &file_name)?;
//         if !account_path.exists() {
//             return Err(Error::InvalidAccount);
//         }
//         let sign_key = Ed25519SigningKey::create_from(&secret);

//         Ok(Self {
//             sign_key,
//             secret: Self::derive_secret(&secret),
//         })
//     }

//     fn derive_account_file(secret: &[u8; 32]) -> String {
//         const DERIVE_ACCOUNT_FILE_SEED: &str = "DERIVE_ACCOUNT_FILE_SEED";
//         base64_encode(&cryptography::derive_key(DERIVE_ACCOUNT_FILE_SEED, secret))
//     }

//     fn derive_secret(secret: &[u8; 32]) -> [u8; 32] {
//         const DERIVE_SECRET_SEED: &str = "DERIVE_SECRET_SEED";
//         cryptography::derive_key(DERIVE_SECRET_SEED, secret)
//     }
// }

// // struct Application<'a> {
// //     name: String,
// //     data_model: DataModel,
// //     graph_database: GraphDatabase<'a>,
// //     database_path: PathBuf,
// //     signing_key: Ed2519SigningKey,
// // }
// impl Application<'_> {
//     pub fn new(
//         name: &str,
//         secret: &[u8; 32],
//         data_folder: PathBuf,
//         data_model: &str,
//     ) -> Result<Self, Error> {
//         let database_secret = derive_key(name, secret);
//         let database_name = derive_key("DATABASE_NAME", &database_secret);
//         let signature_key = derive_key("SIGNING_KEY", secret);
//         let signing_key = Ed2519SigningKey::create_from(&signature_key);

//         let database_path = build_path(data_folder, &base64_encode(&database_name))?;

//         let data_model = DataModel::parse(data_model)?;
//         let graph_database = GraphDatabase::new(
//             &database_path,
//             &database_secret,
//             8192,
//             false,
//             4,
//             1000,
//             //   &data_model,
//         )?;

//         Ok(Self {
//             name: name.to_string(),
//             data_model,
//             graph_database,
//             database_path,
//             signing_key,
//         })
//     }

//     pub fn query(&self, query: &str, _params: Option<Parameters>) -> Result<String, Error> {
//         let querytype = query.trim().split_once(' ');
//         if let Some(e) = querytype {
//             match e.0 {
//                 "query" | "subscription" => {
//                     println!("query");
//                     let _query = Query::parse(query, &self.data_model)?;
//                 }
//                 "mutation" => {
//                     println!("mutation");
//                     let _mutation = Mutation::parse(query, &self.data_model)?;
//                 }
//                 "deletion" => {
//                     let _deletion = Deletion::parse(query, &self.data_model)?;
//                     println!("deletion")
//                 }

//                 _ => {
//                     return Err(Error::ParsingError(
//                         crate::database::query_language::Error::InvalidQuery(format!(
//                             "Invalid Query {}",
//                             query
//                         )),
//                     ))
//                 }
//             }
//         } else {
//             return Err(Error::ParsingError(
//                 crate::database::query_language::Error::InvalidQuery(format!(
//                     "Invalid Query {}",
//                     query
//                 )),
//             ));
//         }
//         Ok("".to_string())
//     }
// }

#[cfg(test)]
mod tests {

    const DATA_PATH: &str = "test/data/database/";

    #[tokio::test(flavor = "multi_thread")]
    async fn connect() {
        // let secret = hash(b"not so secret");
        // let data_model = "
        // Person {
        //     name : String,
        //     surname : String,
        //     parents : [Person],
        //     age : Integer,
        //     weight : Float,
        //     is_human : Boolean
        // }";
        //    let _app = Application::new("my_new_app", &secret, DATA_PATH.into(), data_model).unwrap();

        // app.query("query", None).unwrap();
    }
}
