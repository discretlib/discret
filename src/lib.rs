//! Discret: Create local first, peer to peer application (P2P) using a GraphQL inspired API
//!
//!
//! Creating an application requires a few steps
//!  - Create a datamodel that contains the entity that will be synchronized
//!  - Create rooms to manage access rights to the data
//!  - Add data to the rooms
//!  - Create invitation to your rooms and manually send them to who you want via external application like email
//!  - Once the peer accept the invitaion it will start synchronising data it is allowed to access.
//!
//! Discret hides the complexity of peer to peer networks and reduces it to a database synchronisation problem.
//! Compared to traditional application, most of the new complexity resides in the Room rights managements.
//! Depending on the rights you choose, Rooms can have many different use cases.
//!
//! As data lives on your devices, Discret should only be used for applications with data generated by "real person", with hundreds of peers at most.
//! It is not suited for large scale application and communities with thousands of peoples.
//! It currenlty only support text data but support for external file synchronisation is planned.
//!
//! On local network, peer connection happens without requiring any server.
//! For peer to peer connection over the Internet, a discovery server is needed to allow peers to discover each others. The discret lib provides an implementation of the discovery server named Beacon.
//! Connection over the internet is not 100% guaranted to work, because certain types of enterprise firewalls will block the connection attempts.
//! The library support both IPv6 and IPv4
//!
//! The library provides strong security features out of the box:
//!     - data is encrypted at rest by using the SQLCipher database
//!     - encrypted communication using the QUIC protocol
//!     - data integrity: each rows is signed with the peer signing key, making it very hard to synchronise bad data
//!     - access control via Rooms
//!
//! Please, be warned that P2P connections leaks your IP adress and should only be used with trusted peer.
//! This leak exposes you to the following threats:
//!     - Distributed denial of service (DDOS)
//!     - Leak of your "Real World" location via geolocation services.
//!     - State sponsored surveillance: A state watching the network could determine which peer connect to which, giving a lot of knowledge about your social network.
//!
//!

#![allow(dead_code)]

mod configuration;
mod database;
mod date_utils;
mod event_service;
mod log_service;
mod network;

mod security;
mod signature_verification_service;
mod synchronisation;

use database::graph_database::GraphDatabaseService;
use event_service::EventService;
use log_service::LogService;
use network::peer_connection_service::PeerConnectionService;
use security::{derive_key, MeetingSecret};

use signature_verification_service::SignatureVerificationService;
use std::path::PathBuf;
use std::sync::{Arc, Mutex};
use thiserror::Error;
use tokio::{runtime::Runtime, sync::broadcast};

pub type Result<T> = std::result::Result<T, Error>;
pub use crate::configuration::Configuration;
pub use crate::database::{
    mutation_query::MutationResult,
    query_language::parameter::{Parameters, ParametersAdd},
    room::Room,
};
pub use crate::log_service::Log;
pub use crate::security::{base64_decode, base64_encode, derive_pass_phrase, Uid};

///
/// Defines every errors that can be by the discret lib
///
///
#[derive(Error, Debug)]
pub enum Error {
    #[error(transparent)]
    CryptoError(#[from] crate::security::Error),

    #[error(transparent)]
    DatabaseError(#[from] crate::database::Error),

    #[error(transparent)]
    NetworkError(#[from] crate::network::Error),

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

#[derive(Clone)]
pub struct Discret {
    db: GraphDatabaseService,
    peers: PeerConnectionService,
    log: LogService,
    verifying_key: Vec<u8>,
    system_room_id: Uid,
}
impl Discret {
    pub async fn new(
        datamodel: &str,
        app_key: &str,
        key_material: &[u8; 32],
        data_folder: PathBuf,
        configuration: Configuration,
    ) -> std::result::Result<Self, Error> {
        let meeting_secret_key =
            derive_key(&format!("{}{}", "MEETING_SECRET", app_key,), key_material);
        let meeting_secret = MeetingSecret::new(meeting_secret_key);

        let pub_key = meeting_secret.public_key();
        let public_key = pub_key.as_bytes();

        let event_service = EventService::new();
        let (db, verifying_key, system_room_id) = GraphDatabaseService::start(
            app_key,
            datamodel,
            key_material,
            public_key,
            data_folder.clone(),
            &configuration,
            event_service.clone(),
        )
        .await?;

        let signature_service =
            SignatureVerificationService::start(configuration.signature_verification_parallelism);

        let log = LogService::start();
        let peers = PeerConnectionService::start(
            verifying_key.clone(),
            meeting_secret,
            system_room_id,
            db.clone(),
            event_service.clone(),
            log.clone(),
            signature_service,
            10,
        )
        .await?;

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
    pub async fn delete(
        &self,
        deletion: &str,
        param_opt: Option<Parameters>,
    ) -> std::result::Result<(), Error> {
        match self.db.delete(deletion, param_opt).await {
            Ok(_) => Ok(()),
            Err(e) => Err(e.into()),
        }
    }

    ///
    /// mutate
    ///
    pub async fn mutate(
        &self,
        mutation: &str,
        param_opt: Option<Parameters>,
    ) -> std::result::Result<MutationResult, Error> {
        Ok(self.db.mutate(mutation, param_opt).await?)
    }

    ///
    /// GraphQL query
    ///
    pub async fn query(
        &self,
        query: &str,
        param_opt: Option<Parameters>,
    ) -> std::result::Result<String, Error> {
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
    pub async fn update_data_model(&self, datamodel: &str) -> std::result::Result<String, Error> {
        Ok(self.db.update_data_model(datamodel).await?)
    }

    ///
    /// Provide a JSON representation of the datamode  
    ///
    /// the JSON contains the model plain text along with the internal datamodel representation
    ///
    /// Can be usefull to create a data model editor
    ///
    pub async fn data_model(&self) -> std::result::Result<String, Error> {
        Ok(self.db.datamodel().await?)
    }

    pub async fn log_subscribe(&self) -> broadcast::Receiver<Log> {
        self.log.subcribe().await
    }
}

struct BlockingRuntime {
    rt: Option<Runtime>,
}
impl BlockingRuntime {
    pub fn new() -> Self {
        Self { rt: None }
    }
    pub fn rt(&mut self) -> std::result::Result<&Runtime, Error> {
        if self.rt.is_none() {
            self.rt = Some(
                tokio::runtime::Builder::new_multi_thread()
                    .enable_all()
                    .build()?,
            );
        }
        Ok(self.rt.as_ref().unwrap())
    }
}

lazy_static::lazy_static! {
    static ref TOKIO_BLOCKING: Arc<Mutex<BlockingRuntime>> =
    Arc::new(Mutex::new(BlockingRuntime::new()));
}
///
/// Provides a blocking API
///
///
#[derive(Clone)]
pub struct DiscretBlocking {
    discret: Discret,
}
impl DiscretBlocking {
    fn new(
        datamodel: &str,
        app_key: &str,
        key_material: &[u8; 32],
        data_folder: PathBuf,
        configuration: Configuration,
    ) -> std::result::Result<Self, Error> {
        let discret = TOKIO_BLOCKING.lock().unwrap().rt()?.block_on(Discret::new(
            datamodel,
            app_key,
            key_material,
            data_folder,
            configuration,
        ))?;

        Ok(Self { discret })
    }

    pub fn delete(
        &self,
        deletion: &str,
        param_opt: Option<Parameters>,
    ) -> std::result::Result<(), Error> {
        TOKIO_BLOCKING
            .lock()
            .unwrap()
            .rt()?
            .block_on(self.discret.delete(deletion, param_opt))
    }

    pub async fn mutate(
        &self,
        mutation: &str,
        param_opt: Option<Parameters>,
    ) -> std::result::Result<MutationResult, Error> {
        TOKIO_BLOCKING
            .lock()
            .unwrap()
            .rt()?
            .block_on(self.discret.mutate(mutation, param_opt))
    }

    pub async fn query(
        &self,
        query: &str,
        param_opt: Option<Parameters>,
    ) -> std::result::Result<String, Error> {
        TOKIO_BLOCKING
            .lock()
            .unwrap()
            .rt()?
            .block_on(self.discret.query(query, param_opt))
    }

    pub fn verifying_key(&self) -> &Vec<u8> {
        &self.discret.verifying_key
    }

    pub fn system_room_id(&self) -> &Uid {
        &self.discret.system_room_id
    }

    pub fn update_data_model(&self, datamodel: &str) -> std::result::Result<String, Error> {
        TOKIO_BLOCKING
            .lock()
            .unwrap()
            .rt()?
            .block_on(self.discret.update_data_model(datamodel))
    }

    pub fn data_model(&self) -> std::result::Result<String, Error> {
        TOKIO_BLOCKING
            .lock()
            .unwrap()
            .rt()?
            .block_on(self.discret.data_model())
    }

    pub fn log_subscribe(&self) -> std::result::Result<broadcast::Receiver<Log>, Error> {
        Ok(TOKIO_BLOCKING
            .lock()
            .unwrap()
            .rt()?
            .block_on(self.discret.log_subscribe()))
    }
}
