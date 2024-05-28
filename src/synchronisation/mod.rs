use serde::{Deserialize, Serialize};

use crate::{
    database::room::Room,
    security::{self, Uid},
};
use thiserror::Error;
pub mod node_full;
pub mod peer_inbound_service;
pub mod peer_outbound_service;
pub mod room_locking_service;

/// Queries have 10 seconds to returns before closing connection
pub static NETWORK_TIMEOUT_SEC: u64 = 10;

#[derive(Serialize, Deserialize)]
pub enum Query {
    ProveIdentity(Vec<u8>),
    RoomList,
    RoomDefinition(Uid),
    RoomNode(Uid),
    RoomLog(Uid),
    RoomDailyNodes(Uid, i64),
    EdgeDeletionLog(Uid, i64),
    NodeDeletionLog(Uid, i64),
    FullNodes(Uid, Vec<Uid>),
    PeerNodes(Uid, Vec<Vec<u8>>),
}

#[derive(Serialize, Deserialize)]
pub struct QueryProtocol {
    id: u64,
    query: Query,
}

#[derive(Serialize, Deserialize)]
pub struct Answer {
    id: u64,
    success: bool,
    serialized: Vec<u8>,
}

#[derive(Serialize, Deserialize, Debug, Error)]
pub enum Error {
    #[error("Authorisation for Query {0}")]
    Authorisation(String),

    #[error("RemoteTechnical for Query {0}")]
    RemoteTechnical(String),

    #[error("TimeOut ")]
    TimeOut,

    #[error("Parsing")]
    Parsing,

    #[error("Technical")]
    Technical,
}

#[derive(Clone)]
pub enum LocalEvent {
    RoomDefinitionChanged(Room),
    RoomDataChanged(Vec<Uid>),
}

#[derive(Serialize, Deserialize)]
pub enum RemoteEvent {
    Ready, //indicate that this end of the connection is ready to synchronize
    RoomDefinitionChanged(Uid),
    RoomDataChanged(Uid),
}

#[derive(Serialize, Deserialize)]
pub struct ProveAnswer {
    pub verifying_key: Vec<u8>,
    pub invitation: Option<Vec<u8>>,
    pub chall_signature: Vec<u8>,
}
impl ProveAnswer {
    pub fn verify(&self, challenge: &Vec<u8>) -> Result<(), security::Error> {
        let pub_key = security::import_verifying_key(&self.verifying_key)?;
        pub_key.verify(challenge, &self.chall_signature)?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use std::{fs, path::PathBuf, time::Duration};

    use crate::{
        configuration::Configuration,
        database::{
            graph_database::GraphDatabaseService,
            query_language::parameter::{Parameters, ParametersAdd},
            sqlite_database::RowMappingFn,
        },
        event_service::{Event, EventService},
        log_service::LogService,
        peer_connection_service::{
            connect_peers, listen_for_event, EventFn, Log, LogFn, PeerConnectionService,
        },
        security::{base64_encode, random32, MeetingSecret, Uid},
        signature_verification_service::SignatureVerificationService,
    };

    const DATA_PATH: &str = "test_data/synchronisation/peer_service/";
    fn init_database_path() {
        let path: PathBuf = DATA_PATH.into();
        fs::create_dir_all(&path).unwrap();
    }

    struct Peer {
        event: EventService,
        log: LogService,
        db: GraphDatabaseService,
        peer_service: PeerConnectionService,
        verifying_key: Vec<u8>,
        system_room_id: Uid,
    }
    impl Peer {
        async fn new(path: PathBuf, model: &str) -> Self {
            let event = EventService::new();
            let (db, verifying_key, system_room_id) = GraphDatabaseService::start(
                "app",
                model,
                &random32(),
                &random32(),
                path.clone(),
                &Configuration::default(),
                event.clone(),
            )
            .await
            .unwrap();
            let log = LogService::start();
            let peer_service = PeerConnectionService::start(
                verifying_key.clone(),
                MeetingSecret::new(random32()),
                system_room_id,
                db.clone(),
                event.clone(),
                log.clone(),
                SignatureVerificationService::start(2),
                10,
            )
            .unwrap();
            Self {
                event,
                log,
                db,
                peer_service,
                verifying_key,
                system_room_id,
            }
        }
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn synchronise_room() {
        init_database_path();
        let path: PathBuf = DATA_PATH.into();
        let model = "{Person{name:String,}}";

        let first_peer = Peer::new(path.clone(), model).await;
        let second_peer = Peer::new(path, model).await;

        let first_user_id = base64_encode(&first_peer.verifying_key);
        let second_user_id = base64_encode(&second_peer.verifying_key);

        let mut param = Parameters::default();
        param.add("first_id", first_user_id.clone()).unwrap();
        param.add("second_id", second_user_id.clone()).unwrap();

        let room = first_peer
            .db
            .mutate_raw(
                r#"mutation mut {
                sys.Room{
                    admin: [{
                        verif_key:$first_id
                    }]

                    authorisations:[{
                        name:"admin"
                        rights:[{
                            entity:"Person"
                            mutate_self:true
                            mutate_all:false
                        }]
                        users: [{
                            verif_key:$second_id
                        }]
                    }]
                }

            }"#,
                Some(param),
            )
            .await
            .unwrap();

        let room_insert = &room.mutate_entities[0];

        let room_id = room_insert.node_to_mutate.id.clone();

        let first_key = first_peer.verifying_key.clone();

        let id = room_id;
        let event_fn: EventFn = Box::new(move |event| match event {
            Event::PeerConnected(id, _, _) => {
                assert_eq!(id, first_key);
                return false;
            }
            Event::RoomSynchronized(room) => {
                assert_eq!(room, id);
                return true;
            }

            _ => return false,
        });

        let log_fn: LogFn = Box::new(|log| match log {
            Log::Error(_, src, e) => Err(format!("src:{} Err:{} ", src, e)),
            Log::Info(_, _) => Ok(()),
        });

        //        tokio::time::sleep(Duration::from_millis(100)).await;

        connect_peers(&first_peer.peer_service, &second_peer.peer_service).await;

        tokio::time::timeout(
            Duration::from_secs(1),
            listen_for_event(
                second_peer.event.clone(),
                second_peer.log.clone(),
                first_peer.log.clone(),
                event_fn,
                log_fn,
            ),
        )
        .await
        .unwrap()
        .unwrap();

        let room_query = "query{ sys.Room{ id mdate }}";
        let first_res = first_peer.db.query(room_query, None).await.unwrap();
        let second_res = second_peer.db.query(room_query, None).await.unwrap();

        assert_eq!(second_res, first_res);

        let query = "SELECT mdate  FROM _room_changelog WHERE room_id=?";
        struct Changelog {
            mdate: i64,
        }
        let mapping: RowMappingFn<Changelog> = |row| Ok(Box::new(Changelog { mdate: row.get(0)? }));
        let res = first_peer
            .db
            .select(query.to_string(), vec![Box::new(room_id)], mapping)
            .await
            .unwrap();
        let room_first_date = res[0].mdate;

        let res = second_peer
            .db
            .select(query.to_string(), vec![Box::new(room_id)], mapping)
            .await
            .unwrap();

        assert_eq!(room_first_date, res[0].mdate);
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn synchronise_data() {
        init_database_path();
        let path: PathBuf = DATA_PATH.into();
        let model = "{Person{name:String,}}";

        let first_peer = Peer::new(path.clone(), model).await;
        let second_peer = Peer::new(path, model).await;

        let first_user_id = base64_encode(&first_peer.verifying_key);
        let second_user_id = base64_encode(&second_peer.verifying_key);

        let mut param = Parameters::default();
        param.add("first_id", first_user_id.clone()).unwrap();
        param.add("second_id", second_user_id.clone()).unwrap();

        let room = first_peer
            .db
            .mutate_raw(
                r#"mutation mut {
                sys.Room{
                    admin: [{
                        verif_key:$first_id
                    }]
                    authorisations:[{
                        name:"admin"
                        rights:[{
                            entity:"Person"
                            mutate_self:true
                            mutate_all:false
                        }]
                        users: [{
                            verif_key:$second_id
                        }]
                    }]
                }

            }"#,
                Some(param),
            )
            .await
            .unwrap();

        let room_insert = &room.mutate_entities[0];
        let room_id = room_insert.node_to_mutate.id.clone();

        let first_key = first_peer.verifying_key.clone();

        let mut param = Parameters::default();
        param.add("room_id", base64_encode(&room_id)).unwrap();

        first_peer
            .db
            .mutate_raw(
                r#"mutation mut {
                    Person{
                        room_id: $room_id
                        name: "someone"
                    }

                }"#,
                Some(param),
            )
            .await
            .unwrap();

        let mut param = Parameters::default();
        param.add("room_id", base64_encode(&room_id)).unwrap();
        first_peer
            .db
            .mutate_raw(
                r#"mutation mut {
                    Person{
                        room_id: $room_id
                        name: "another"
                    }

                }"#,
                Some(param),
            )
            .await
            .unwrap();

        let id = room_id;
        let event_fn: EventFn = Box::new(move |event| match event {
            Event::PeerConnected(id, _, _) => {
                assert_eq!(id, first_key);
                return false;
            }
            Event::RoomSynchronized(room) => {
                assert_eq!(room, id);
                return true;
            }

            _ => return false,
        });

        let log_fn: LogFn = Box::new(|log| match log {
            Log::Error(_, src, e) => Err(format!("src:{} Err:{} ", src, e)),
            Log::Info(_, _) => Ok(()),
        });

        //        tokio::time::sleep(Duration::from_millis(100)).await;

        connect_peers(&first_peer.peer_service, &second_peer.peer_service).await;

        tokio::time::timeout(
            Duration::from_secs(1),
            listen_for_event(
                second_peer.event.clone(),
                second_peer.log.clone(),
                first_peer.log.clone(),
                event_fn,
                log_fn,
            ),
        )
        .await
        .unwrap()
        .unwrap();

        let query = "query g { 
            Person(order_by(name desc)){ id room_id mdate cdate name } 
        }";
        let res1 = first_peer.db.query(query, None).await.unwrap();
        let res2 = second_peer.db.query(query, None).await.unwrap();

        assert_eq!(res1, res2);
    }
}
