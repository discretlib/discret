//! Discret: Create local first, peer to peer application (P2P) using a GraphQL inspired API
//!
//! *Discret* hides the complexity of peer to peer networks and reduces it to a data access problem.
//!
//! The API allows you to:
//! - manage your data using a GraphQL syntax,
//! - add access right to your data (in graphQL too),
//! - create and accept invites from other peers.
//!
//! *Discret* will synchronize your data with other peers, depending on the access right you have given to those peers.
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

use std::path::PathBuf;
use std::sync::{Arc, Mutex};

use tokio::sync::{mpsc, oneshot};
use tokio::{runtime::Runtime, sync::broadcast};
type Result<T> = std::result::Result<T, Error>;

use crate::{
    configuration::Configuration,
    database::{
        graph_database::{GraphDatabaseService, MutateReceiver},
        query_language::parameter::Parameters,
        system_entities::DefaultRoom,
    },
    event_service::Event,
    event_service::EventService,
    peer_connection_service::{PeerConnectionMessage, PeerConnectionService},
    security::{
        base64_encode, default_uid, derive_key, uid_encode, HardwareFingerprint, MeetingSecret, Uid,
    },
    signature_verification_service::SignatureVerificationService,
    Error,
};

///
/// returns the zero filled uid in base bas64
///
/// uid are the unique identifiers used by the Discret internal database
///
pub fn zero_uid() -> String {
    uid_encode(&default_uid())
}
///
/// Verify that the Discret database defined by the parameters exists in the folder
///
pub fn database_exists(
    app_key: &str,
    key_material: &[u8; 32],
    data_folder: &PathBuf,
) -> std::result::Result<bool, Error> {
    GraphDatabaseService::database_exists(app_key, key_material, data_folder)
}

///
/// All the parameters available after Discret initialisation
///
#[derive(Clone)]
pub struct DiscretParams {
    pub app_key: String,
    pub verifying_key: Vec<u8>,
    pub private_room_id: Uid,
    pub hardware_fingerprint: HardwareFingerprint,
    pub configuration: Configuration,
}

///
/// All the discret services
///
#[derive(Clone)]
pub struct DiscretServices {
    pub events: EventService,
    pub database: GraphDatabaseService,
    pub signature_verification: SignatureVerificationService,
}

///
/// The main entry point for the Discret Library
///
#[derive(Clone)]
pub struct Discret {
    params: DiscretParams,
    services: DiscretServices,
    peers: PeerConnectionService,
}
impl Discret {
    /// Starts the Discret engine with the following parameters:
    ///- datamodel: define the data types that can be used by discret,
    ///- app_key: a unique identifier for the application that **cannot not** change once the application is in produciton
    ///- key_material: a master secret that will be used wit the app_key to derive all the secret required by discret
    ///- data_folder: where data is stored
    ///- configuration: the configuration stucture
    pub async fn new(
        datamodel: &str,
        app_key: &str,
        key_material: &[u8; 32],
        data_folder: PathBuf,
        configuration: Configuration,
    ) -> std::result::Result<Self, Error> {
        let mut hardware_file = data_folder.clone();
        hardware_file.push("hardware_fingerprint.bin");
        let hardware_fingerprint = HardwareFingerprint::get(&hardware_file).unwrap();
        let meeting_secret_key =
            derive_key(&format!("{}{}", "MEETING_SECRET", app_key,), key_material);
        let meeting_secret = MeetingSecret::new(meeting_secret_key);

        let pub_key = meeting_secret.public_key();
        let public_key = pub_key.as_bytes();

        let event_service: EventService = EventService::new();
        let (database_service, verifying_key, private_room_id) = GraphDatabaseService::start(
            app_key,
            datamodel,
            key_material,
            public_key,
            data_folder.clone(),
            &configuration,
            event_service.clone(),
        )
        .await?;

        let verify_service = SignatureVerificationService::start(configuration.parallelism);

        let params = DiscretParams {
            app_key: app_key.to_string(),
            verifying_key,
            private_room_id,
            hardware_fingerprint,
            configuration,
        };

        let services = DiscretServices {
            events: event_service,
            database: database_service,
            signature_verification: verify_service,
        };

        let peers = PeerConnectionService::start(&params, &services, meeting_secret).await?;

        Ok(Self {
            params,
            services,
            peers,
        })
    }

    ///
    /// Performs a Deletion query
    ///
    pub async fn delete(&self, d: &str, p: Option<Parameters>) -> std::result::Result<(), Error> {
        match self.services.database.delete(d, p).await {
            Ok(_) => Ok(()),
            Err(e) => Err(e.into()),
        }
    }

    ///
    /// Performs a mutation query and returns the inserted tuple in a JSON String
    ///
    pub async fn mutate(
        &self,
        m: &str,
        p: Option<Parameters>,
    ) -> std::result::Result<String, Error> {
        Ok(self.services.database.mutate(m, p).await?)
    }

    ///
    /// Allow to send a stream of mutation.
    ///
    /// Usefull for batch insertion as you do have to wait for the mutation to finished before sending another.
    ///
    /// The receiver retrieve an internal representation of the mutation query to avoid the performance cost of creating the JSON result, wich is probably unecessary when doing batch insert.
    /// To get the JSON, call the  MutationQuery.result() method
    ///
    pub fn mutation_stream(&self) -> (mpsc::Sender<(String, Option<Parameters>)>, MutateReceiver) {
        self.services.database.mutation_stream()
    }

    ///
    /// Perform a query to retrieve results from the database.
    /// returns the result in a JSON object
    ///
    pub async fn query(
        &self,
        q: &str,
        p: Option<Parameters>,
    ) -> std::result::Result<String, Error> {
        Ok(self.services.database.query(q, p).await?)
    }

    ///
    /// Create an invitation
    /// - default_room: once the inviation is accepted, the new Peer will be granted access to this room.
    ///
    /// The returned byte array have to be sent manually to another peer.
    ///
    pub async fn invite(&self, default_room: Option<DefaultRoom>) -> Result<Vec<u8>> {
        let (reply, receive) = oneshot::channel::<Result<Vec<u8>>>();
        let _ = self
            .peers
            .sender
            .send(PeerConnectionMessage::CreateInvite(default_room, reply))
            .await;
        receive.await?
    }

    ///
    /// Accept an invitation
    /// Once an invitation is accepted, the two peers will be able to discover themselves and start exchanging data
    ///   
    pub async fn accept_invite(&self, invitation: Vec<u8>) -> std::result::Result<(), Error> {
        let _ = self
            .peers
            .sender
            .send(PeerConnectionMessage::AcceptInvite(invitation))
            .await;

        Ok(())
    }

    ///
    /// This is is your Public identity.
    ///
    /// It is derived from the provided key_material and app_key.
    ///
    /// Every data you create will be signed using the associated signing_key, and  
    /// other peers will use this verifying key to ensure the integrity of the data
    ///
    pub fn verifying_key(&self) -> String {
        base64_encode(&self.params.verifying_key)
    }

    ///
    /// This special room is used internally to store system data.
    /// you are allowed to used it to store any kind of private data that will only be synchronized with your devices.
    ///
    pub fn private_room(&self) -> String {
        base64_encode(&self.params.private_room_id)
    }

    ///
    /// Subscribe for the event queue
    ///
    pub async fn subscribe_for_events(&self) -> broadcast::Receiver<Event> {
        self.services.events.subcribe().await
    }

    ///
    /// Update the existing data model definition with a new one.  
    ///
    /// returns the JSON representation of the updated datamodel.
    ///
    /// Can be usefull to create a data model editor.
    ///
    pub async fn update_data_model(&self, datamodel: &str) -> std::result::Result<String, Error> {
        Ok(self.services.database.update_data_model(datamodel).await?)
    }

    ///
    /// Provide a JSON representation of the datamodel  
    ///
    /// The JSON contains the model plain text along with the internal datamodel representation.
    ///
    /// Can be usefull to create a data model editor.
    ///
    pub async fn data_model(&self) -> std::result::Result<String, Error> {
        Ok(self.services.database.datamodel().await?)
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
/// The main entry point for the Discret Library, with a blocking API
/// Provides a blocking API
///
#[derive(Clone)]
pub struct DiscretBlocking {
    discret: Discret,
}
impl DiscretBlocking {
    /// Starts the Discret engine with the following parameters:
    ///- datamodel: define the data types that can be used by discret,
    ///- app_key: a unique identifier for the application that **cannot not** change once the application is in produciton
    ///- key_material: a master secret that will be used wit the app_key to derive all the secret required by discret
    ///- data_folder: where data is stored
    ///- configuration: the configuration stucture
    pub fn new(
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

    ///
    /// Performs a Deletion query
    ///
    pub fn delete(&self, d: &str, p: Option<Parameters>) -> std::result::Result<(), Error> {
        TOKIO_BLOCKING
            .lock()
            .unwrap()
            .rt()?
            .block_on(self.discret.delete(d, p))
    }

    ///
    /// Performs a mutation query and returns the inserted tuple in a JSON String
    ///
    pub fn mutate(&self, m: &str, p: Option<Parameters>) -> std::result::Result<String, Error> {
        TOKIO_BLOCKING
            .lock()
            .unwrap()
            .rt()?
            .block_on(self.discret.mutate(m, p))
    }

    ///
    /// Allow to send a stream of mutation.
    ///
    /// Usefull for batch insertion as you do have to wait for the mutation to finished before sending another.
    ///
    /// The receiver retrieve an internal representation of the mutation query to avoid the performance cost of creating the JSON result, wich is probably unecessary when doing batch insert.
    /// To get the JSON, call the  MutationQuery.result() method
    ///
    pub fn mutation_stream(&self) -> (mpsc::Sender<(String, Option<Parameters>)>, MutateReceiver) {
        self.discret.mutation_stream()
    }

    ///
    /// Perform a query to retrieve results from the database.
    /// returns the result in a JSON object
    ///
    pub fn query(&self, q: &str, p: Option<Parameters>) -> std::result::Result<String, Error> {
        TOKIO_BLOCKING
            .lock()
            .unwrap()
            .rt()?
            .block_on(self.discret.query(q, p))
    }

    ///
    /// Create an invitation
    /// - default_room: once the inviation is accepted, the new Peer will be granted access to this room.
    ///
    /// The returned byte array have to be sent manually to another peer.
    ///
    pub async fn invite(&self, default_room: Option<DefaultRoom>) -> Result<Vec<u8>> {
        TOKIO_BLOCKING
            .lock()
            .unwrap()
            .rt()?
            .block_on(self.discret.invite(default_room))
    }

    ///
    /// Accept an invitation
    /// Once an invitation is accepted, the two peers will be able to discover themselves and start exchanging data
    ///   
    pub async fn accept_invite(&self, invitation: Vec<u8>) -> std::result::Result<(), Error> {
        TOKIO_BLOCKING
            .lock()
            .unwrap()
            .rt()?
            .block_on(self.discret.accept_invite(invitation))
    }

    ///
    /// This is is your Public identity.
    ///
    /// It is derived from the provided key_material and app_key.
    ///
    /// Every data you create will be signed using the associated signing_key, and  
    /// other peers will use this verifying key to ensure the integrity of the data
    ///
    pub fn verifying_key(&self) -> String {
        self.discret.verifying_key()
    }
    ///
    /// This special room is used internally to store system data.
    /// you are allowed to used it to store any kind of private data that will only be synchronized with your devices.
    ///
    pub fn private_room(&self) -> String {
        self.discret.private_room()
    }

    ///
    /// Subscribe for the event queue
    ///
    pub fn subscribe_for_events(&self) -> broadcast::Receiver<Event> {
        TOKIO_BLOCKING
            .lock()
            .unwrap()
            .rt()
            .unwrap()
            .block_on(self.discret.subscribe_for_events())
    }

    ///
    /// Update the existing data model definition with a new one.  
    ///
    /// returns the JSON representation of the updated datamodel.
    ///
    /// Can be usefull to create a data model editor.
    ///
    pub fn update_data_model(&self, datamodel: &str) -> std::result::Result<String, Error> {
        TOKIO_BLOCKING
            .lock()
            .unwrap()
            .rt()?
            .block_on(self.discret.update_data_model(datamodel))
    }

    ///
    /// Provide a JSON representation of the datamodel  
    ///
    /// The JSON contains the model plain text along with the internal datamodel representation.
    ///
    /// Can be usefull to create a data model editor.
    ///
    pub fn data_model(&self) -> std::result::Result<String, Error> {
        TOKIO_BLOCKING
            .lock()
            .unwrap()
            .rt()?
            .block_on(self.discret.data_model())
    }
}
