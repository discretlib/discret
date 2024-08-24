//! Discret: Create local first, peer to peer application (P2P) using a GraphQL inspired API
//!
//! *Discret* hides the complexity of peer to peer networks and reduces it to a data access problem.
//!
//! It provides the following features:
//! - A database layer based on sqlite that is managed using a GraphQL inspired API
//! - An authentication and authorization layer to define who can access data
//! - A Peer to Peer layer that allows you to invite Peers
//!
//! And *Discret* will automatically synchronize your data with other peers, based on the access right you have defined.
//!
//! More details and tutorials are available in the [documentation site](https://discretlib.github.io/doc/)
//!
//! # Example
//! The following example creates a very basic chat application. If you build and run this program on several different folder or local network devices
//! you should be able to chat with yourself.
//! ```ignore
//! use std::{io, path::PathBuf};
//! use discret::{
//!     derive_pass_phrase, zero_uid, Configuration, Discret,
//!     Parameters, ParametersAdd, ResultParser,
//! };
//! use serde::Deserialize;
//!
//! //the application unique identifier
//! const APPLICATION_KEY: &str = "github.com/discretlib/rust_example_simple_chat";
//!
//! #[tokio::main]
//! async fn main() {
//!     //define a datamodel
//!     let model = "chat {
//!         Message{
//!             content:String
//!         }
//!     }";
//!     //this struct is used to parse the query result
//!     #[derive(Deserialize)]
//!     struct Chat {
//!         pub id: String,
//!         pub mdate: i64,
//!         pub content: String,
//!     }
//!
//!     let path: PathBuf = "test_data".into(); //where data is stored
//!
//!     //used to derives all necessary secrets
//!     let key_material: [u8; 32] = derive_pass_phrase("my login", "my password");
//!
//!     //start the discret application
//!     let app: Discret = Discret::new(
//!         model,
//!         APPLICATION_KEY,
//!         &key_material,
//!         path,
//!         Configuration::default(),
//!     )
//!     .await
//!     .unwrap();
//!
//!     //listen for events
//!     let mut events = app.subscribe_for_events().await;
//!     let event_app: Discret = app.clone();
//!     tokio::spawn(async move {
//!         let mut last_date = 0;
//!         let mut last_id = zero_uid();
//!
//!         let private_room: String = event_app.private_room();
//!         while let Ok(event) = events.recv().await {
//!             match event {
//!                 //triggered when data is modified
//!                 discret::Event::DataChanged(_) => {
//!                     let mut param = Parameters::new();
//!                     param.add("mdate", last_date).unwrap();
//!                     param.add("id", last_id.clone()).unwrap();
//!                     param.add("room_id", private_room.clone()).unwrap();
//!
//!                     //get the latest data, the result is in the JSON format
//!                     let result: String = event_app
//!                         .query(
//!                             "query {
//!                                 res: chat.Message(
//!                                     order_by(mdate asc, id asc),
//!                                     after($mdate, $id),
//!                                     room_id = $room_id
//!                                 ) {
//!                                         id
//!                                         mdate
//!                                         content
//!                                 }
//!                             }",
//!                             Some(param),
//!                         )
//!                         .await
//!                         .unwrap();
//!                     let mut query_result = ResultParser::new(&result).unwrap();
//!                     let res: Vec<Chat> = query_result.take_array("res").unwrap();
//!                     for msg in res {
//!                         last_date = msg.mdate;
//!                         last_id = msg.id;
//!                         println!("you said: {}", msg.content);
//!                     }
//!                 }
//!                 _ => {} //ignores other events
//!             }
//!         }
//!     });
//!
//!     //data is inserted in your private room
//!     let private_room: String = app.private_room();
//!     let stdin = io::stdin();
//!     let mut line = String::new();
//!     println!("{}", "Write Something!");
//!     loop {
//!         stdin.read_line(&mut line).unwrap();
//!         if line.starts_with("/q") {
//!             break;
//!         }
//!         line.pop();
//!         let mut params = Parameters::new();
//!         params.add("message", line.clone()).unwrap();
//!         params.add("room_id", private_room.clone()).unwrap();
//!         app.mutate(
//!             "mutate {
//!                 chat.Message {
//!                     room_id:$room_id
//!                     content: $message
//!                 }
//!             }",
//!             Some(params),
//!         )
//!         .await
//!         .unwrap();
//!         line.clear();
//!     }
//! }
//! ```
//!
//! # Features
//! *Discret* provides a blocking (DiscretBlocking) and a non blocking (Discret) API.  
//!
//! On local network, peer connection happens without requiring any server.
//! For peer to peer connection over the Internet, a discovery server is needed to allow peers to discover each others.
//! The discret lib provides an implementation of the discovery server named Beacon.
//!
//! The library provides strong security features out of the box:
//! - data is encrypted at rest by using the SQLCipher database
//! - encrypted communication using the QUIC protocol
//! - data integrity: each rows is signed with the peer signing key, making it very hard to synchronize bad data
//! - access control via Rooms
//!
//! # Limitations
//! As data lives on your devices, Discret should only be used for applications with data generated by "real person", with hundreds of peers at most.
//! It is not suited for large scale applications and communities with thousands of peoples.
//!
//! It currently only supports text data but supports for file synchronization is planned.
//!
//! Connection over the internet is not 100% guaranteed to work, because certain types of enterprise firewalls will block the connection attempts.
//!
//! Please, be warned that P2P connections leaks your IP adress and should only be used with trusted peer.
//! This leak exposes you to the following threats:
//! - Distributed denial of service (DDOS)
//! - Leak of your "Real World" location via geolocation services.
//! - State sponsored surveillance: A state watching the network could determine which peer connect to which, giving a lot of knowledge about your social network.
//!
//! # Platform Support
//! - Linux: Tested
//! - Windows: Tested
//! - macOS: not tested, should work
//! - Android: works on arch64 architecture. Architectures i686 and x86_64 have some low level linker issues when working with Flutter.
//! - iOS: not tested
//!
#![forbid(unsafe_code)]
#[allow(clippy::too_many_arguments)]
//#![allow(dead_code)]
mod configuration;
mod database;
mod date_utils;
mod discret;
mod event_service;
mod network;
mod peer_connection_service;
mod security;
mod signature_verification_service;
mod synchronisation;

use thiserror::Error;

type Result<T> = std::result::Result<T, Error>;

pub use crate::{
    configuration::{BeaconConfig, Configuration},
    database::{
        query_language::parameter::{Parameters, ParametersAdd},
        room::Room,
        system_entities::DefaultRoom,
        DataModification, ResultParser,
    },
    discret::{database_exists, zero_uid, Discret, DiscretBlocking},
    event_service::Event,
    network::beacon::Beacon,
    security::{
        base64_decode, base64_encode, derive_pass_phrase, generate_x509_certificate, hash,
        random_domain_name,
    },
};

///
/// Defines every errors that can be triggered by the discret lib
///
#[derive(Error, Debug)]
pub enum Error {
    #[error(transparent)]
    Security(#[from] crate::security::Error),

    #[error(transparent)]
    Database(#[from] crate::database::Error),

    #[error(transparent)]
    Network(#[from] crate::network::Error),

    #[error(transparent)]
    Parsing(#[from] crate::database::query_language::Error),

    #[error(transparent)]
    JSON(#[from] serde_json::Error),

    #[error(transparent)]
    TokioJoin(#[from] tokio::task::JoinError),

    #[error(transparent)]
    Timeout(#[from] tokio::time::error::Elapsed),

    #[error(transparent)]
    Bincode(#[from] Box<bincode::ErrorKind>),

    #[error(transparent)]
    Io(#[from] std::io::Error),

    #[error(transparent)]
    OneshotRecv(#[from] tokio::sync::oneshot::error::RecvError),

    #[error(transparent)]
    Synch(#[from] crate::synchronisation::Error),

    #[error(transparent)]
    InvalidAdress(#[from] std::net::AddrParseError),

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

    #[error("{0} Edges where rejected during synchronisation of room: {1} at date: {2} ")]
    EdgeRejected(usize, String, i64),

    #[error("{0} Nodes where rejected during synchronisation of room: {1} at date: {2}")]
    NodeRejected(usize, String, i64),

    #[error("invalid certificate hash: '{0}'")]
    InvalidCertificateHash(String),

    #[error("Connection to Beacon {0} failed, reason: {1}")]
    BeaconConnectionFailed(String, String),

    #[error("{0}")]
    InvalidConnection(String),

    #[error("{0}")]
    SecurityViolation(String),

    #[error("{0}")]
    InvalidInvite(String),

    #[error("{0}")]
    Unsupported(String),
}

#[cfg(test)]
pub mod test {

    use log::{Level, Metadata, Record};
    struct SimpleLogger;

    impl log::Log for SimpleLogger {
        fn enabled(&self, metadata: &Metadata) -> bool {
            metadata.level() <= Level::Info
        }

        fn log(&self, record: &Record) {
            if self.enabled(record.metadata()) {
                println!("{} - {}", record.level(), record.args());
            }
        }

        fn flush(&self) {}
    }

    use log::LevelFilter;

    static LOGGER: SimpleLogger = SimpleLogger;

    pub fn init_log() {
        log::set_logger(&LOGGER)
            .map(|()| log::set_max_level(LevelFilter::Debug))
            .unwrap();
    }
}
