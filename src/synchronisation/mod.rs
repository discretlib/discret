use serde::{Deserialize, Serialize};

use crate::{cryptography, database::room::Room};
use thiserror::Error;
pub mod local_peer;
pub mod node_full;
pub mod peer_service;
pub mod remote_peer;
mod room_locking_service;
pub mod room_node;

/// Queries have 10 seconds to returns before closing connection
pub static NETWORK_TIMEOUT_SEC: u64 = 10;

#[derive(Serialize, Deserialize)]
pub enum Query {
    ProveIdentity(Vec<u8>),
    RoomList,
    RoomDefinition(Vec<u8>),
    RoomNode(Vec<u8>),
    RoomLog(Vec<u8>),
    RoomDailyNodes(Vec<u8>, i64),
    EdgeDeletionLog(Vec<u8>, i64),
    NodeDeletionLog(Vec<u8>, i64),
    FullNodes(Vec<u8>, Vec<Vec<u8>>),
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
    #[error("Authorisation")]
    Authorisation,

    #[error("RemoteTechnical")]
    RemoteTechnical,

    #[error("TimeOut")]
    TimeOut,

    #[error("Parsing")]
    Parsing,

    #[error("Technical")]
    Technical,
}

#[derive(Clone)]
pub enum LocalEvent {
    RoomDefinitionChanged(Room),
    RoomDataChanged(Vec<u8>),
}

#[derive(Serialize, Deserialize)]
pub enum RemoteEvent {
    Ready, //indicate that this end of the connection is ready to synchronize
    RoomDefinitionChanged(Vec<u8>),
    RoomDataChanged(Vec<u8>),
}

#[derive(Serialize, Deserialize)]
pub struct ProveAnswer {
    pub verifying_key: Vec<u8>,
    pub invitation: Option<Vec<u8>>,
    pub chall_signature: Vec<u8>,
}
impl ProveAnswer {
    pub fn verify(&self, challenge: &Vec<u8>) -> Result<(), cryptography::Error> {
        let pub_key = cryptography::import_verifying_key(&self.verifying_key)?;
        pub_key.verify(challenge, &self.chall_signature)?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use std::{fs, path::PathBuf, time::Duration};

    use tests::peer_service::{connect_peers, listen_for_event, Event, EventFn, Log, LogFn};

    use crate::{
        cryptography::base64_encode,
        database::{
            configuration::Configuration,
            graph_database::GraphDatabaseService,
            query_language::parameter::{Parameters, ParametersAdd},
            sqlite_database::RowMappingFn,
        },
        event_service::EventService,
        log_service::LogService,
    };

    use self::{cryptography::random32, peer_service::PeerConnectionService};

    use super::*;

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
    }
    impl Peer {
        async fn new(path: PathBuf, model: &str) -> Self {
            let event = EventService::new();
            let db = GraphDatabaseService::start(
                "app",
                model,
                &random32(),
                path.clone(),
                Configuration::default(),
                event.clone(),
            )
            .await
            .unwrap();
            let log = LogService::start();
            let peer_service =
                PeerConnectionService::start(db.clone(), event.clone(), log.clone(), 10);
            Self {
                event,
                log,
                db,
                peer_service,
            }
        }
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn synchronise_room() {
        init_database_path();
        let path: PathBuf = DATA_PATH.into();
        let model = "Person{name:String,}";

        let first_peer = Peer::new(path.clone(), model).await;
        let second_peer = Peer::new(path, model).await;

        let first_user_id = base64_encode(first_peer.db.verifying_key());
        let second_user_id = base64_encode(second_peer.db.verifying_key());

        let mut param = Parameters::default();
        param.add("first_id", first_user_id.clone()).unwrap();
        param.add("second_id", second_user_id.clone()).unwrap();

        let room = first_peer
            .db
            .mutate_raw(
                r#"mutation mut {
                _Room{
                    admin: [{
                        verifying_key:$first_id
                    }]
                    user_admin: [{
                        verifying_key:$first_id
                    }]
                    authorisations:[{
                        name:"admin"
                        rights:[{
                            entity:"Person"
                            mutate_self:true
                            mutate_all:false
                        }]
                        users: [{
                            verifying_key:$first_id
                        },{
                            verifying_key:$second_id
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

        let first_key = first_peer.db.verifying_key().clone();

        let id = room_id.clone();
        let event_fn: EventFn = Box::new(move |event| match event {
            Event::PeerConnected(id, _, _) => {
                assert_eq!(id, first_key);
                return false;
            }
            Event::RoomSynchronized(room) => {
                assert_eq!(room, id.clone());
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

        let room_query = "query q{ _Room{ id mdate }}";
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
            .select(query.to_string(), vec![Box::new(room_id.clone())], mapping)
            .await
            .unwrap();
        let room_first_date = res[0].mdate;

        let res = second_peer
            .db
            .select(query.to_string(), vec![Box::new(room_id.clone())], mapping)
            .await
            .unwrap();

        assert_eq!(room_first_date, res[0].mdate);
    }
}
