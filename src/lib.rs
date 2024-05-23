#![allow(dead_code)]

mod configuration;
mod database;
mod date_utils;
mod event_service;
mod log_service;
mod message;
mod network;
mod peer_connection_service;
mod security;
mod signature_verification_service;
mod synchronisation;

use database::graph_database::GraphDatabaseService;
use event_service::EventService;
use log_service::LogService;
use peer_connection_service::PeerConnectionService;
use security::{derive_key, MeetingSecret};
use signature_verification_service::SignatureVerificationService;
use std::path::PathBuf;
use thiserror::Error;

pub type Result<T> = std::result::Result<T, Error>;
pub use configuration::Configuration;
pub use database::query_language::parameter::{Parameters, ParametersAdd};
pub use security::{
    base64_decode, base64_encode, derive_pass_phrase, new_uid, uid_decode, uid_encode, Uid,
};

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

pub struct Discret {
    db: GraphDatabaseService,
    peers: PeerConnectionService,
    log: LogService,
    verifying_key: Vec<u8>,
    system_room_id: Uid,
}
impl Discret {
    pub async fn new(
        app_key: &str,
        datamodel: &str,
        key_material: &[u8; 32],
        data_folder: PathBuf,
        configuration: Configuration,
    ) -> Result<Self> {
        let event_service = EventService::new();
        let (db, verifying_key, system_room_id) = GraphDatabaseService::start(
            app_key,
            datamodel,
            key_material,
            data_folder.clone(),
            &configuration,
            event_service.clone(),
        )
        .await?;

        let signature_service =
            SignatureVerificationService::start(configuration.signature_verification_parallelism);

        let meeting_secret_key =
            derive_key(&format!("{}{}", "MeetingSecret", app_key,), key_material);
        let meeting_secret = MeetingSecret::new(meeting_secret_key);
        //let public_key = bincode::serialize(&meeting_secret.public_key())?;

        let log = LogService::start();
        let peers = PeerConnectionService::start(
            meeting_secret,
            db.clone(),
            event_service.clone(),
            log.clone(),
            signature_service,
            10,
        );

        Ok(Self {
            db,
            peers,
            log,
            verifying_key,
            system_room_id,
        })
    }

    ///
    /// Deletion query
    ///
    pub async fn delete(&self, deletion: &str, param_opt: Option<Parameters>) -> Result<()> {
        match self.db.delete(deletion, param_opt).await {
            Ok(_) => Ok(()),
            Err(e) => Err(e.into()),
        }
    }

    ///
    /// mutate
    ///
    pub async fn mutate(&self, mutation: &str, param_opt: Option<Parameters>) -> Result<String> {
        Ok(self.db.mutate(mutation, param_opt).await?)
    }

    ///
    /// GraphQL query
    ///
    pub async fn query(&self, query: &str, param_opt: Option<Parameters>) -> Result<String> {
        Ok(self.db.query(query, param_opt).await?)
    }

    ///
    /// This is is your Public identity.
    ///
    /// It is derived from the provided key_material.
    ///
    /// Every data you create will be signed using the associated signing_key, and  
    /// other peers will use this verifying key to ensure the integrity of the data
    ///
    pub fn verifying_key(&self) -> &Vec<u8> {
        &self.verifying_key
    }

    ///
    /// This special room is used internally to store system data
    /// you can use it to query and update the sys.* entities
    ///
    pub fn system_room_id(&self) -> &Uid {
        &self.system_room_id
    }

    ///
    /// Update the existing data model definition with a new one  
    ///
    /// returns the JSON representation of the updated datamodel
    ///
    /// can be usefull to create a data model editor
    ///
    pub async fn update_data_model(&self, datamodel: &str) -> Result<String> {
        Ok(self.db.update_data_model(datamodel).await?)
    }

    ///
    /// Provide a JSON representation of the datamode  
    ///
    /// the JSON contains the model plain text along with the internal datamodel representation
    ///
    /// Can be usefull to create a data model editor
    ///
    pub async fn data_model(&self) -> Result<String> {
        Ok(self.db.datamodel().await?)
    }
}
