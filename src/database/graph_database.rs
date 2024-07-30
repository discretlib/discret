use lru::LruCache;
use rusqlite::OptionalExtension;
use std::collections::{HashSet, VecDeque};
use std::{collections::HashMap, fs, num::NonZeroUsize, path::PathBuf, sync::Arc};
use tokio::sync::{mpsc, oneshot, oneshot::Sender};

use super::edge::Edge;
use super::node::NodeToInsert;
use super::query_language::data_model_parser::validate_json_for_entity;
use super::sqlite_database::WriteStmt;
use super::system_entities::{self, AllowedPeer, Peer, PeerNodes};
use super::{
    authorisation_service::{AuthorisationMessage, AuthorisationService, RoomAuthorisations},
    daily_log::DailyLogsUpdate,
    daily_log::{DailyLog, RoomDefinitionLog},
    deletion::DeletionQuery,
    edge::EdgeDeletionEntry,
    mutation_query::MutationQuery,
    node::{Node, NodeDeletionEntry, NodeIdentifier},
    query::{PreparedQueries, Query},
    query_language::{
        data_model_parser::DataModel, deletion_parser::DeletionParser,
        mutation_parser::MutationParser, parameter::Parameters, query_parser::QueryParser,
    },
    room_node::RoomNode,
    sqlite_database::{Database, WriteMessage, Writeable},
    system_entities::SYSTEM_DATA_MODEL,
    Error, Result,
};
use super::{DataModification, MESSAGE_OVERHEAD};

use crate::event_service::EventServiceMessage;
use crate::log_service::LogService;
use crate::security::{uid_encode, MeetingSecret, MeetingToken};
use crate::{
    configuration::Configuration,
    date_utils::now,
    event_service::EventService,
    security::{base64_encode, derive_key, derive_uid, Ed25519SigningKey, SigningKey, Uid},
};

const LRU_SIZE: usize = 128;

pub enum DbMessage {
    Query(String, Parameters, Sender<Result<String>>),
    Mutate(String, Parameters, Sender<Result<MutationQuery>>),
    MutateStream(String, Parameters, mpsc::Sender<Result<MutationQuery>>),
    Delete(String, Parameters, Sender<Result<DeletionQuery>>),
    DataModelUpdate(String, Sender<Result<String>>),
    DataModel(Sender<Result<String>>),
    AddNodes(Uid, Vec<NodeToInsert>, Sender<Result<Vec<Uid>>>),
    AddEdges(Uid, Vec<Edge>, Sender<Result<Vec<Uid>>>),
    DeleteEdges(Vec<EdgeDeletionEntry>, Sender<Result<()>>),
    DeleteNodes(Vec<NodeDeletionEntry>, Sender<Result<()>>),
    ComputeDailyLog(),
    DailyLogComputed(Result<DailyLogsUpdate>),
}
///
/// Entry Point for all databases interaction
///
///
#[derive(Clone)]
pub struct GraphDatabaseService {
    pub sender: mpsc::Sender<DbMessage>,
    //queue dedicated to user interaction
    //  interactive_sender: mpsc::Sender<Message>,
    pub auth: AuthorisationService,
    pub db: Database,
    pub buffer_size: usize,
}
impl GraphDatabaseService {
    pub fn database_exists(
        app_key: &str,
        key_material: &[u8; 32],
        data_folder: &PathBuf,
    ) -> std::result::Result<bool, crate::Error> {
        let signature_key = derive_key(&format!("{} SIGNING_KEY", app_key), key_material);
        let database_secret = derive_key("DATABASE_SECRET", &signature_key);
        let database_key = derive_key("DATABASE_NAME", &database_secret);
        let database_path = build_path(data_folder, &base64_encode(&database_key))?;
        let exist = database_path.exists();
        Ok(exist)
    }
    #[allow(clippy::too_many_arguments)]
    pub async fn start(
        app_key: &str,
        datamodel: &str,
        key_material: &[u8; 32],
        public_key: &[u8; 32],
        data_folder: PathBuf,
        configuration: &Configuration,
        event_service: EventService,
        log_service: LogService,
    ) -> Result<(Self, Vec<u8>, Uid)> {
        let (peer_sender, mut peer_receiver) =
            mpsc::channel::<DbMessage>(configuration.parallelism);
        //  let (interactive_sender, mut intereactive_receiver) = mpsc::channel::<Message>(128);
        let buffer_size = (configuration.write_buffer_length * 1024) - MESSAGE_OVERHEAD;
        let private_room_id = derive_uid(&format!("{}{}", app_key, "SYSTEM_ROOM"), key_material);

        let mut db = GraphDatabase::new(
            private_room_id,
            public_key,
            datamodel,
            app_key,
            key_material,
            data_folder,
            configuration,
            event_service,
        )
        .await?;

        let database = db.graph_database.clone();
        let auth = db.auth_service.clone();
        let verifying_key = db.verifying_key.clone();
        let sender = peer_sender.clone();
        tokio::spawn(async move {
            while let Some(msg) = peer_receiver.recv().await {
                match msg {
                    DbMessage::Query(query, parameters, reply) => {
                        let q = db.get_cached_query(&query);
                        match q {
                            Ok(cache) => {
                                db.query(cache.0, cache.1, parameters, reply).await;
                            }
                            Err(err) => {
                                let _ = reply.send(Err(err));
                            }
                        }
                    }
                    DbMessage::Mutate(mutation, parameters, reply) => {
                        let mutation = db.get_cached_mutation(&mutation);
                        match mutation {
                            Ok(cache) => {
                                db.mutate(cache, parameters, reply).await;
                            }
                            Err(err) => {
                                let _ = reply.send(Err(err));
                            }
                        }
                    }

                    DbMessage::MutateStream(mutation, parameters, reply) => {
                        let mutation = db.get_cached_mutation(&mutation);
                        match mutation {
                            Ok(cache) => {
                                db.mutate_stream(cache, parameters, reply).await;
                            }
                            Err(err) => {
                                let _ = reply.send(Err(err)).await;
                            }
                        }
                    }

                    DbMessage::Delete(deletion, parameters, reply) => {
                        let deletion = db.get_cached_deletion(&deletion);
                        match deletion {
                            Ok(cache) => {
                                db.delete(cache, parameters, reply).await;
                            }
                            Err(err) => {
                                let _ = reply.send(Err(err));
                            }
                        }
                    }

                    DbMessage::AddNodes(room_id, nodes, reply) => {
                        db.add_nodes(room_id, nodes, reply).await;
                    }

                    DbMessage::AddEdges(room_id, edges, reply) => {
                        db.add_edges(room_id, edges, reply).await;
                    }

                    DbMessage::DataModelUpdate(value, reply) => {
                        match db.update_data_model(&value).await {
                            Ok(model) => {
                                let _ = reply.send(Ok(model));
                            }
                            Err(err) => {
                                let _ = reply.send(Err(err));
                            }
                        }
                    }

                    DbMessage::DataModel(reply) => {
                        match serde_json::to_string_pretty(&db.data_model) {
                            Ok(model) => {
                                let _ = reply.send(Ok(model));
                            }
                            Err(err) => {
                                let _ = reply.send(Err(err.into()));
                            }
                        }
                    }
                    DbMessage::DeleteEdges(edges, reply) => {
                        db.delete_edges(edges, reply).await;
                    }
                    DbMessage::DeleteNodes(nodes, reply) => {
                        db.delete_nodes(nodes, reply).await;
                    }
                    DbMessage::ComputeDailyLog() => {
                        _ = db
                            .graph_database
                            .writer
                            .send(WriteMessage::ComputeDailyLog(
                                DailyLogsUpdate::default(),
                                sender.clone(),
                            ))
                            .await;
                    }

                    DbMessage::DailyLogComputed(update) => match update {
                        Ok(update) => {
                            let mut data_mod = DataModification {
                                rooms: HashMap::new(),
                            };
                            for room_entry in update.room_dates {
                                let room = room_entry.0;
                                for log in room_entry.1 {
                                    let entity = db.data_model.name_for(&log.entity);
                                    if let Some(entity) = entity {
                                        let date = log.date;
                                        data_mod.add(room, entity, date);
                                    }
                                }
                            }

                            let _ = db
                                .event_service
                                .sender
                                .send(EventServiceMessage::DataChanged(data_mod))
                                .await;
                        }
                        Err(e) => {
                            log_service
                                .error("ComputedDailyLog".to_string(), crate::Error::from(e));
                        }
                    },
                }
            }
        });

        //ensure that the logs are properly computed during startup  because the application can be closed during a synchronisation
        database
            .writer
            .send(WriteMessage::ComputeDailyLog(
                DailyLogsUpdate::default(),
                peer_sender.clone(),
            ))
            .await?;

        Ok((
            GraphDatabaseService {
                sender: peer_sender,
                auth,
                db: database,
                buffer_size,
            },
            verifying_key,
            private_room_id,
        ))
    }

    ///
    /// Deletion query
    ///
    pub async fn delete(
        &self,
        delete: &str,
        param_opt: Option<Parameters>,
    ) -> Result<DeletionQuery> {
        let (reply, receive) = oneshot::channel::<Result<DeletionQuery>>();
        let msg = DbMessage::Delete(delete.to_string(), param_opt.unwrap_or_default(), reply);
        let _ = self.sender.send(msg).await;
        let result = receive.await?;
        let _ = self.sender.send(DbMessage::ComputeDailyLog()).await;
        result
    }

    ///
    /// GraphQL mutation query
    /// returns and internal representation of the result
    /// should be only used by tests
    ///
    pub async fn mutate_raw(
        &self,
        mutate: &str,
        param_opt: Option<Parameters>,
    ) -> Result<MutationQuery> {
        let (reply, receive) = oneshot::channel::<Result<MutationQuery>>();

        let msg = DbMessage::Mutate(mutate.to_string(), param_opt.unwrap_or_default(), reply);
        let _ = self.sender.send(msg).await;

        let result = receive.await?;

        let _ = self.sender.send(DbMessage::ComputeDailyLog()).await;

        result
    }

    ///
    /// GraphQL mutation query
    /// returns a json string
    ///
    pub async fn mutate(&self, mutate: &str, param_opt: Option<Parameters>) -> Result<String> {
        let raw = self.mutate_raw(mutate, param_opt).await;
        match raw {
            Ok(query) => query.result(),
            Err(e) => Err(e),
        }
    }

    ///
    /// Allow to send a stream of mutation. Usefull for batch insertion as you do have to wait for the mutation to finished before sending another.
    ///
    /// The receiver retrieve an internal representation of the mutation query to avoid the JSON result creation, wich is probably unecessary when doing batch insert.
    /// To get the JSON, call the  MutationQuery.result() method
    ///
    pub fn mutation_stream(
        &self,
    ) -> (
        mpsc::Sender<(String, Option<Parameters>)>,
        mpsc::Receiver<Result<MutationQuery>>,
    ) {
        let (send, mut recv) = mpsc::channel::<(String, Option<Parameters>)>(2);
        let (send_res, recv_res) = mpsc::channel::<Result<MutationQuery>>(2);
        let dbsender = self.sender.clone();
        tokio::spawn(async move {
            while let Some((mutate, param_opt)) = recv.recv().await {
                let msg = DbMessage::MutateStream(
                    mutate,
                    param_opt.unwrap_or_default(),
                    send_res.clone(),
                );
                let _ = dbsender.send(msg).await;
            }
            let _ = dbsender.send(DbMessage::ComputeDailyLog()).await;
        });
        (send, recv_res)
    }

    ///
    /// GraphQL query
    ///
    pub async fn query(&self, query: &str, param_opt: Option<Parameters>) -> Result<String> {
        let (reply, receive) = oneshot::channel::<Result<String>>();
        let msg = DbMessage::Query(query.to_string(), param_opt.unwrap_or_default(), reply);
        let _ = self.sender.send(msg).await;
        receive.await?
    }

    //
    // Perform a SQL Selection query on the database
    // SQL mutation query are forbidden
    //
    #[cfg(test)]
    pub async fn select<T: Send + Sized + 'static>(
        &self,
        query: String,
        params: Vec<Box<dyn rusqlite::ToSql + Sync + Send>>,
        mapping: super::sqlite_database::RowMappingFn<T>,
    ) -> Result<Vec<T>> {
        let (reply, receive) = oneshot::channel::<Result<Vec<T>>>();

        self.db
            .reader
            .send_async(Box::new(move |conn| {
                let result =
                    super::sqlite_database::DatabaseReader::select(&query, &params, &mapping, conn)
                        .map_err(Error::from);
                let _ = reply.send(result);
            }))
            .await?;
        receive.await?
    }

    ///
    /// Update the existing data model definition with a new one  
    ///
    pub async fn update_data_model(&self, datamodel: &str) -> Result<String> {
        let (reply, receive) = oneshot::channel::<Result<String>>();
        let msg = DbMessage::DataModelUpdate(datamodel.to_string(), reply);
        let _ = self.sender.send(msg).await;
        let _ = receive.await?;

        self.datamodel().await
    }

    ///
    /// Update the existing data model definition with a new one  
    ///
    pub async fn datamodel(&self) -> Result<String> {
        let (reply, receive) = oneshot::channel::<Result<String>>();
        let msg = DbMessage::DataModel(reply);
        let _ = self.sender.send(msg).await;
        receive.await?
    }

    ///
    /// insert the node list
    /// returns the list of ids that where not inserted for any reasons (parsing error, authorisations)
    ///
    pub async fn add_nodes(&self, room_id: Uid, nodes: Vec<NodeToInsert>) -> Result<Vec<Uid>> {
        let (reply, receive) = oneshot::channel::<Result<Vec<Uid>>>();
        let msg = DbMessage::AddNodes(room_id, nodes, reply);
        let _ = self.sender.send(msg).await;
        receive.await?
    }

    ///
    /// insert the edge list
    /// returns the list of ids that where not inserted for any reasons (parsing error, authorisations)
    ///
    pub async fn add_edges(&self, room_id: Uid, edges: Vec<Edge>) -> Result<Vec<Uid>> {
        let (reply, receive) = oneshot::channel::<Result<Vec<Uid>>>();
        // let msg = Message::AddNodes(room_id, nodes, reply);
        let msg = DbMessage::AddEdges(room_id, edges, reply);
        let _ = self.sender.send(msg).await;
        receive.await?
    }

    ///
    /// Ask the database to compute daily log
    /// this is an expensive operation that should be used only after a large batch insert whenever possible
    /// This will send an event that will trigger the peer synchronisation
    ///
    pub async fn compute_daily_log(&self) {
        let _ = self.sender.send(DbMessage::ComputeDailyLog()).await;
    }

    ///
    /// sign a byte array
    /// returns  
    ///
    pub async fn sign(&self, data: Vec<u8>) -> (Vec<u8>, Vec<u8>) {
        let (reply, receive) = oneshot::channel::<(Vec<u8>, Vec<u8>)>();
        let _ = self
            .auth
            .send(AuthorisationMessage::Sign(data, reply))
            .await;
        receive.await.unwrap()
    }

    ///
    /// get a full database definition of a room
    ///
    pub async fn get_room_node(&self, room_id: Uid) -> Result<Option<RoomNode>> {
        let (reply, receive) = oneshot::channel::<Result<Option<RoomNode>>>();

        self.db
            .reader
            .send_async(Box::new(move |conn| {
                let room_node = RoomNode::read(conn, &room_id).map_err(Error::from);
                let _ = reply.send(room_node);
            }))
            .await?;
        receive.await?
    }

    ///
    /// add a room in the database format
    /// used for synchronisation
    ///
    pub async fn add_room_node(&self, room: RoomNode) -> Result<()> {
        let (reply, receive) = oneshot::channel::<Result<()>>();

        let auth_service = self.auth.clone();
        let _ = self
            .db
            .reader
            .send_async(Box::new(move |conn| {
                let room_id = &room.node.id;

                let room_node_res = RoomNode::read(conn, room_id).map_err(Error::from);
                match room_node_res {
                    Ok(old_room_node) => {
                        let msg = AuthorisationMessage::RoomNodeAdd(old_room_node, room, reply);
                        let _ = auth_service.send_blocking(msg);
                    }
                    Err(err) => {
                        let _ = reply.send(Err(err));
                    }
                }
            }))
            .await;

        receive.await?
    }

    ///
    /// get all room id ordered by last modification date
    ///
    pub async fn get_rooms_for_peer(
        &self,
        verifying_key: Vec<u8>,
    ) -> mpsc::Receiver<Result<VecDeque<Uid>>> {
        let (reply, receive) = oneshot::channel::<HashSet<Uid>>();
        let _ = self
            .auth
            .send(AuthorisationMessage::RoomsForPeer(
                verifying_key,
                now(),
                reply,
            ))
            .await;

        let res = receive.await;

        let (reply, receive) = mpsc::channel::<Result<VecDeque<Uid>>>(1);

        match res {
            Ok(room_ids) => {
                let creply = reply.clone();
                let buffer_size = self.buffer_size;
                let errors = self
                    .db
                    .reader
                    .send_async(Box::new(move |conn| {
                        let error = DailyLog::sort_rooms(&room_ids, buffer_size, &creply, conn)
                            .map_err(Error::from);
                        if let Err(error) = error {
                            let _ = creply.blocking_send(Err(error));
                        }
                    }))
                    .await;
                if let Err(error) = errors {
                    let _ = reply.send(Err(error)).await;
                }
            }
            Err(e) => {
                let _ = reply.send(Err(Error::ChannelSend(e.to_string()))).await;
            }
        }

        receive
    }

    ///
    /// get the most recent log and the last definition modification date
    ///
    pub async fn get_room_definition(&self, room_id: Uid) -> Result<Option<RoomDefinitionLog>> {
        let (reply, receive) = oneshot::channel::<Result<Option<RoomDefinitionLog>>>();
        self.db
            .reader
            .send_async(Box::new(move |conn| {
                let room_log = RoomDefinitionLog::get(&room_id, conn).map_err(Error::from);
                let _ = reply.send(room_log);
            }))
            .await?;
        receive.await?
    }

    ///
    /// get the complete dayly log for a specific room
    ///
    pub async fn get_room_log(&self, room_id: Uid) -> mpsc::Receiver<Result<Vec<DailyLog>>> {
        let (reply, receive) = mpsc::channel::<Result<Vec<DailyLog>>>(1);
        let creply = reply.clone();
        let buffer_size = self.buffer_size;
        let errors = self
            .db
            .reader
            .send_async(Box::new(move |conn| {
                let error = DailyLog::get_room_log(&room_id, buffer_size, &creply, conn)
                    .map_err(Error::from);
                if let Err(error) = error {
                    let _ = creply.blocking_send(Err(error));
                }
            }))
            .await;

        if let Err(error) = errors {
            let _ = reply.send(Err(error)).await;
        }
        receive
    }

    ///
    /// get the complete dayly log for a specific room
    ///
    pub async fn get_room_log_at(&self, room_id: Uid, date: i64) -> Result<Vec<DailyLog>> {
        let (reply, receive) = oneshot::channel::<Result<Vec<DailyLog>>>();
        self.db
            .reader
            .send_async(Box::new(move |conn| {
                let room_log = DailyLog::get_room_log_at(&room_id, date, conn).map_err(Error::from);
                let _ = reply.send(room_log);
            }))
            .await?;
        receive.await?
    }

    ///
    /// get node deletions for a room at a specific day
    ///
    pub async fn get_room_node_deletion_log(
        &self,
        room_id: Uid,
        entity: String,
        del_date: i64,
    ) -> mpsc::Receiver<Result<Vec<NodeDeletionEntry>>> {
        let (reply, receive) = mpsc::channel::<Result<Vec<NodeDeletionEntry>>>(1);
        let creply = reply.clone();
        let buffer_size = self.buffer_size;
        let errors = self
            .db
            .reader
            .send_async(Box::new(move |conn| {
                let error = NodeDeletionEntry::get_entries(
                    &room_id,
                    entity,
                    del_date,
                    buffer_size,
                    &creply,
                    conn,
                );
                if let Err(error) = error {
                    let _ = creply.blocking_send(Err(error));
                }
            }))
            .await;
        if let Err(error) = errors {
            let _ = reply.send(Err(error)).await;
        }
        receive
    }

    ///
    /// get node deletions for a room at a specific day
    ///
    pub async fn delete_nodes(&self, nodes: Vec<NodeDeletionEntry>) -> Result<()> {
        let (send_response, receive_response) = oneshot::channel::<Result<()>>();
        let msg = DbMessage::DeleteNodes(nodes, send_response);
        let _ = self.sender.send(msg).await;
        receive_response.await?
    }

    ///
    /// get edge deletions for a room at a specific day
    ///
    pub async fn get_room_edge_deletion_log(
        &self,
        room_id: Uid,
        entity: String,
        del_date: i64,
    ) -> mpsc::Receiver<Result<Vec<EdgeDeletionEntry>>> {
        let (reply, receive) = mpsc::channel::<Result<Vec<EdgeDeletionEntry>>>(1);
        let creply = reply.clone();
        let buffer_size = self.buffer_size;
        let errors = self
            .db
            .reader
            .send_async(Box::new(move |conn| {
                let error = EdgeDeletionEntry::get_entries(
                    &room_id,
                    entity,
                    del_date,
                    buffer_size,
                    &creply,
                    conn,
                );
                if let Err(error) = error {
                    let _ = creply.blocking_send(Err(error));
                }
            }))
            .await;
        if let Err(error) = errors {
            let _ = reply.send(Err(error)).await;
        }
        receive
    }

    ///
    /// get node deletions for a room at a specific day
    ///V
    pub async fn delete_edges(&self, edges: Vec<EdgeDeletionEntry>) -> Result<()> {
        let (reply, receive) = oneshot::channel::<Result<()>>();
        let msg = DbMessage::DeleteEdges(edges, reply);
        let _ = self.sender.send(msg).await;
        receive.await?
    }

    ///
    /// get all node id for a room at a specific day
    ///
    pub async fn get_room_daily_nodes(
        &self,
        room_id: Uid,
        entity: String,
        date: i64,
    ) -> mpsc::Receiver<Result<HashSet<NodeIdentifier>>> {
        let (reply, receive) = mpsc::channel::<Result<HashSet<NodeIdentifier>>>(1);
        let creply = reply.clone();
        let buffer_size = self.buffer_size;
        let errors = self
            .db
            .reader
            .send_async(Box::new(move |conn| {
                let error = Node::get_daily_nodes_for_room(
                    &room_id,
                    entity,
                    date,
                    buffer_size,
                    &creply,
                    conn,
                );
                if let Err(error) = error {
                    let _ = creply.blocking_send(Err(error));
                }
            }))
            .await;
        if let Err(error) = errors {
            let _ = reply.send(Err(error)).await;
        }
        receive
    }

    ///
    /// filter the nodes ids that exists at this specific date
    ///
    pub async fn filter_existing_node(
        &self,
        mut node_ids: HashSet<NodeIdentifier>,
    ) -> Result<Vec<NodeToInsert>> {
        let (reply, receive) = oneshot::channel::<Result<Vec<NodeToInsert>>>();
        self.db
            .reader
            .send_async(Box::new(move |conn| {
                match Node::filter_existing(&mut node_ids, conn).map_err(Error::from) {
                    Ok(v) => {
                        let _ = reply.send(Ok(v));
                    }
                    Err(e) => {
                        let _ = reply.send(Err(e));
                    }
                }
            }))
            .await?;
        receive.await?
    }

    ///
    /// get full node definition
    ///
    pub async fn get_nodes(
        &self,
        room_id: Uid,
        node_ids: Vec<Uid>,
    ) -> mpsc::Receiver<Result<Vec<Node>>> {
        let (reply, receive) = mpsc::channel::<Result<Vec<Node>>>(1);
        let creply = reply.clone();
        let buffer_size = self.buffer_size;

        let errors = self
            .db
            .reader
            .send_async(Box::new(move |conn| {
                let error = Node::filtered_by_room(&room_id, node_ids, buffer_size, &creply, conn);

                if let Err(error) = error {
                    let _ = creply.blocking_send(Err(error));
                }
            }))
            .await;
        if let Err(error) = errors {
            let _ = reply.send(Err(error)).await;
        }
        receive
    }

    ///
    /// get full node definition
    ///
    pub async fn get_edges(
        &self,
        room_id: Uid,
        node_ids: Vec<(Uid, i64)>,
    ) -> mpsc::Receiver<Result<Vec<Edge>>> {
        let (reply, receive) = mpsc::channel::<Result<Vec<Edge>>>(1);
        let creply = reply.clone();
        let buffer_size = self.buffer_size;

        let errors = self
            .db
            .reader
            .send_async(Box::new(move |conn| {
                let error = Edge::filtered_by_room(&room_id, node_ids, buffer_size, &creply, conn);

                if let Err(error) = error {
                    let _ = creply.blocking_send(Err(error));
                }
            }))
            .await;
        if let Err(error) = errors {
            let _ = reply.send(Err(error)).await;
        }
        receive
    }

    ///
    /// insert sys.Peer nodes
    ///
    pub async fn add_peer_nodes(&self, nodes: Vec<Node>) -> Result<()> {
        let (reply, receive) = oneshot::channel::<Result<WriteStmt>>();
        let nodes = PeerNodes { nodes };
        self.db
            .writer
            .send(WriteMessage::Write(Box::new(nodes), reply))
            .await?;

        match receive.await? {
            Ok(_) => Ok(()),
            Err(e) => Err(e),
        }
    }

    ///
    /// get sys.Peer node
    ///
    pub async fn get_peer_node(&self, verifying_key: Vec<u8>) -> Result<Option<Node>> {
        let (reply, receive) = oneshot::channel::<Result<Option<Node>>>();

        self.db
            .reader
            .send_async(Box::new(move |conn| {
                let result = Peer::get_node(verifying_key, conn).map_err(Error::from);
                let _ = reply.send(result);
            }))
            .await?;
        receive.await?
    }

    ///
    /// retrieve users for a room
    ///
    pub async fn peers_for_room(&self, room_id: Uid) -> mpsc::Receiver<Result<Vec<Node>>> {
        let (u_reply, u_receive) = oneshot::channel::<Result<HashSet<Vec<u8>>>>();
        let _ = self
            .auth
            .send(AuthorisationMessage::UserForRoom(room_id, u_reply))
            .await;

        let (reply, receive) = mpsc::channel::<Result<Vec<Node>>>(1);
        let creply = reply.clone();
        let buffer_size = self.buffer_size;

        match u_receive.await {
            Ok(r) => match r {
                Ok(keys) => {
                    let _ = self
                        .db
                        .reader
                        .send_async(Box::new(move |conn| {
                            let error = Peer::get_peers(keys, buffer_size, &creply, conn);
                            if let Err(error) = error {
                                let _ = creply.blocking_send(Err(error));
                            }
                        }))
                        .await;
                }
                Err(e) => {
                    let _ = reply.send(Err(e)).await;
                }
            },
            Err(e) => {
                let _ = reply.send(Err(Error::from(e))).await;
            }
        }

        receive
    }

    ///
    /// retrieve id of users defined in room users but not in the sys.Peer entity
    ///
    pub async fn get_allowed_peers(
        &self,
        room_id: Uid,
    ) -> std::result::Result<Vec<AllowedPeer>, crate::Error> {
        AllowedPeer::get(uid_encode(&room_id), system_entities::Status::Enabled, self).await
    }
}

struct GraphDatabase {
    data_model: DataModel,
    auth_service: AuthorisationService,
    graph_database: Database,
    event_service: EventService,
    mutation_cache: LruCache<String, Arc<MutationParser>>,
    query_cache: LruCache<String, QueryCacheEntry>,
    deletion_cache: LruCache<String, Arc<DeletionParser>>,
    verifying_key: Vec<u8>,
}
impl GraphDatabase {
    pub async fn new(
        private_room_id: Uid,
        public_key: &[u8; 32],
        model: &str,
        app_key: &str,
        key_material: &[u8; 32],
        data_folder: PathBuf,
        config: &Configuration,
        event_service: EventService,
    ) -> Result<Self> {
        let signature_key = derive_key(&format!("{} SIGNING_KEY", app_key), key_material);

        let database_secret = derive_key("DATABASE_SECRET", &signature_key);

        let database_key = derive_key("DATABASE_NAME", &database_secret);

        let signing_key = Ed25519SigningKey::create_from(&signature_key);
        let verifying_key = signing_key.export_verifying_key();
        let database_path = build_path(data_folder, &base64_encode(&database_key))?;

        let graph_database = Database::start(
            &database_path,
            &database_secret,
            config.read_cache_size_in_kb,
            config.parallelism,
            config.write_cache_size_in_kb,
            config.write_buffer_length,
            config.enable_database_memory_security,
        )?;

        let mutation_cache = LruCache::new(NonZeroUsize::new(LRU_SIZE).unwrap());
        let query_cache = LruCache::new(NonZeroUsize::new(LRU_SIZE).unwrap());
        let deletion_cache = LruCache::new(NonZeroUsize::new(LRU_SIZE).unwrap());

        let data_model = DataModel::new();

        let peer_uid = derive_uid("PEER_UID", &database_key);
        let allowed_uid = derive_uid("ALLOWED_PEER_UID", &database_key);
        let token: MeetingToken = MeetingSecret::derive_token("MEETING_TOKEN", &database_key);

        system_entities::init_allowed_peers(
            &graph_database,
            peer_uid,
            public_key,
            allowed_uid,
            private_room_id,
            token,
            &signing_key,
        )
        .await?;
        // let allowed_peer_uid = derive_uid("ALLOWED_PEER_UID", &public_key);
        // let peer_node = Peer::create(peer_uid, meeting_pub_key);

        let mut auth = RoomAuthorisations {
            signing_key,
            rooms: HashMap::new(),
            max_node_size: config.max_object_size_in_kb * 1024,
        };

        // create the system room associated the user
        auth.create_system_room(private_room_id, &graph_database.writer)
            .await?;

        let auth_service =
            AuthorisationService::start(auth, graph_database.writer.clone(), event_service.clone());

        let mut database = Self {
            data_model,
            auth_service,
            graph_database,
            event_service,
            mutation_cache,
            query_cache,
            deletion_cache,
            verifying_key,
        };

        database.update_data_model(model).await?;
        database.initialise_authorisations().await?;

        Ok(database)
    }

    pub async fn update_data_model(&mut self, model: &str) -> Result<String> {
        let (send, recieve) = oneshot::channel::<Result<Option<String>>>();

        //load from database
        self.graph_database
            .reader
            .send_async(Box::new(move |conn| {
                let query = "SELECT value FROM _configuration WHERE key='Data Model'";
                let res: std::result::Result<Option<String>, rusqlite::Error> =
                    conn.query_row(query, [], |row| row.get(0)).optional();
                match res {
                    Ok(datamodel) => {
                        let _ = send.send(Ok(datamodel));
                    }
                    Err(err) => {
                        let _ = send.send(Err(Error::Database(err)));
                    }
                }
            }))
            .await?;

        let res = recieve.await??;
        if let Some(serialized_dm) = res {
            let dam: DataModel = serde_json::from_str(&serialized_dm)?;
            self.data_model = dam;
        }

        self.data_model.update_system(SYSTEM_DATA_MODEL)?;
        self.data_model.update(model)?;

        let str = serde_json::to_string(&self.data_model)?;

        struct Serialized(String, DataModel);
        impl Writeable for Serialized {
            fn write(
                &mut self,
                conn: &rusqlite::Connection,
            ) -> std::result::Result<(), rusqlite::Error> {
                let query =
                    "INSERT OR REPLACE INTO _configuration(key, value) VALUES ('Data Model', ?)";
                conn.execute(query, [&self.0])?;

                let mut index_exists_stmt = conn.prepare_cached(
                    "SELECT 1 FROM sqlite_master WHERE type= 'index' AND name = ? ",
                )?;
                let datamodel = &self.1;
                for ns in datamodel.namespaces() {
                    for entity in ns.1 {
                        for to_delete in &entity.1.indexes_to_remove {
                            let name = to_delete.0;
                            let node: Option<i64> = index_exists_stmt
                                .query_row([name], |row| row.get(0))
                                .optional()?;
                            if node.is_some() {
                                conn.execute(&format!("DROP INDEX {}", name), [])?;
                            }
                        }
                        for to_insert in &entity.1.indexes {
                            let name = to_insert.0;
                            let node: Option<i64> = index_exists_stmt
                                .query_row([name], |row| row.get(0))
                                .optional()?;
                            if node.is_none() {
                                conn.execute(&to_insert.1.create_query(), [])?;
                            }
                        }
                    }
                }
                Ok(())
            }
        }

        self.graph_database
            .writer
            .write(Box::new(Serialized(str.clone(), self.data_model.clone())))
            .await?;

        Ok(str)
    }

    pub async fn initialise_authorisations(&mut self) -> Result<()> {
        let (send, recieve) = oneshot::channel::<Result<String>>();
        let cache = self.get_cached_query(RoomAuthorisations::LOAD_QUERY)?;
        let parameters = Parameters::default();
        self.query(cache.0, cache.1, parameters, send).await;
        let result = recieve.await??;

        let (send, recieve) = oneshot::channel::<Result<()>>();
        let msg = AuthorisationMessage::Load(result, send);
        self.auth_service.send(msg).await?;

        recieve.await??;
        Ok(())
    }

    pub fn get_cached_mutation(&mut self, mutation: &str) -> Result<Arc<MutationParser>> {
        let muts = match self.mutation_cache.get(mutation) {
            Some(e) => e.clone(),
            None => {
                let muts = Arc::new(MutationParser::parse(mutation, &self.data_model)?);
                self.mutation_cache
                    .push(String::from(mutation), muts.clone());
                muts
            }
        };
        Ok(muts)
    }

    pub async fn mutate(
        &mut self,
        mutation: Arc<MutationParser>,
        mut parameters: Parameters,
        reply: Sender<Result<MutationQuery>>,
    ) {
        let auth_service = self.auth_service.clone();
        let _ = self
            .graph_database
            .reader
            .send_async(Box::new(move |conn| {
                let mutation_query =
                    MutationQuery::execute(&mut parameters, mutation.clone(), conn);

                match mutation_query {
                    Ok(muta) => {
                        let msg = AuthorisationMessage::Mutation(muta, reply);
                        let _ = auth_service.send_blocking(msg);
                    }
                    Err(e) => {
                        let _ = reply.send(Err(e));
                    }
                }
            }))
            .await;
    }

    pub async fn mutate_stream(
        &mut self,
        mutation: Arc<MutationParser>,
        mut parameters: Parameters,
        reply: mpsc::Sender<Result<MutationQuery>>,
    ) {
        let auth_service = self.auth_service.clone();
        let _ = self
            .graph_database
            .reader
            .send_async(Box::new(move |conn| {
                let mutation_query =
                    MutationQuery::execute(&mut parameters, mutation.clone(), conn);

                match mutation_query {
                    Ok(muta) => {
                        let msg = AuthorisationMessage::MutationStream(muta, reply);
                        let _ = auth_service.send_blocking(msg);
                    }
                    Err(e) => {
                        let _ = reply.blocking_send(Err(e));
                    }
                }
            }))
            .await;
    }

    pub fn get_cached_query(
        &mut self,
        query: &str,
    ) -> Result<(Arc<QueryParser>, Arc<PreparedQueries>)> {
        if self.query_cache.get(query).is_none() {
            let parser = QueryParser::parse(query, &self.data_model)?;
            let prepared_query = Arc::new(PreparedQueries::build(&parser)?);
            let entry = QueryCacheEntry {
                parser: Arc::new(parser),
                prepared_query,
            };

            self.query_cache.push(String::from(query), entry);
        }
        let query = self.query_cache.get(query).unwrap();
        Ok((query.parser.clone(), query.prepared_query.clone()))
    }

    async fn query(
        &mut self,
        parser: Arc<QueryParser>,
        sql_queries: Arc<PreparedQueries>,
        parameters: Parameters,
        reply: Sender<Result<String>>,
    ) {
        let mut sql = Query {
            parameters,
            parser,
            sql_queries,
        };

        let _ = self
            .graph_database
            .reader
            .send_async(Box::new(move |conn| {
                let res = sql.read(conn).map_err(Error::from);
                let _ = reply.send(res);
            }))
            .await;
    }

    pub fn get_cached_deletion(&mut self, deletion: &str) -> Result<Arc<DeletionParser>> {
        let deletion = match self.deletion_cache.get(deletion) {
            Some(e) => e.clone(),
            None => {
                let dels = Arc::new(DeletionParser::parse(deletion, &self.data_model)?);
                self.deletion_cache
                    .push(String::from(deletion), dels.clone());
                dels
            }
        };
        Ok(deletion)
    }

    pub async fn delete(
        &mut self,
        deletion: Arc<DeletionParser>,
        mut parameters: Parameters,
        reply: Sender<Result<DeletionQuery>>,
    ) {
        let auth_service = self.auth_service.clone();
        let _ = self
            .graph_database
            .reader
            .send_async(Box::new(move |conn| {
                let deletion_query = DeletionQuery::build(&mut parameters, deletion, conn);
                match deletion_query {
                    Ok(del) => {
                        let query = AuthorisationMessage::Deletion(del, reply);
                        let _ = auth_service.send_blocking(query);
                    }
                    Err(e) => {
                        let _ = reply.send(Err(e));
                    }
                }
            }))
            .await;
    }

    pub async fn add_nodes(
        &self,
        room_id: Uid,
        nodes: Vec<NodeToInsert>,
        reply: Sender<Result<Vec<Uid>>>,
    ) {
        let mut invalid_nodes = Vec::new();
        let mut valid_nodes = Vec::new();

        for mut node_to_insert in nodes {
            let node = match node_to_insert.node.as_ref() {
                Some(node) => node,
                None => {
                    invalid_nodes.push(node_to_insert.id);
                    continue;
                }
            };

            match &node.room_id {
                Some(r) => {
                    if !room_id.eq(r) {
                        invalid_nodes.push(node_to_insert.id);
                        continue;
                    }
                }
                None => {
                    invalid_nodes.push(node_to_insert.id);
                    continue;
                }
            }

            let name = match self.data_model.name_for(&node._entity) {
                Some(e) => e,
                None => {
                    invalid_nodes.push(node_to_insert.id);
                    continue;
                }
            };

            let entity = match self.data_model.get_entity(&name) {
                Ok(e) => e,
                Err(_) => {
                    invalid_nodes.push(node_to_insert.id);
                    continue;
                }
            };

            match validate_json_for_entity(entity, &node._json) {
                Ok(_) => {
                    node_to_insert.entity_name = Some(name);
                    valid_nodes.push(node_to_insert)
                }
                Err(_e) => {
                    // println!("{}", e);
                    //silent error. will just indicate peer that some node is erroneous
                    invalid_nodes.push(node_to_insert.id)
                }
            }
        }

        let msg = AuthorisationMessage::AddNodes(valid_nodes, invalid_nodes, reply);
        let _ = self.auth_service.send(msg).await;
    }

    pub async fn add_edges(&self, room_id: Uid, edges: Vec<Edge>, reply: Sender<Result<Vec<Uid>>>) {
        let mut invalid_edges = Vec::new();
        let mut valid_edges = Vec::new();

        for edge in edges {
            let name = match self.data_model.name_for(&edge.src_entity) {
                Some(e) => e,
                None => {
                    invalid_edges.push(edge.src);
                    continue;
                }
            };
            valid_edges.push((edge, name));
        }

        let msg = AuthorisationMessage::AddEdges(room_id, valid_edges, invalid_edges, reply);
        let _ = self.auth_service.send(msg).await;
    }

    pub async fn delete_edges(&self, mut edges: Vec<EdgeDeletionEntry>, reply: Sender<Result<()>>) {
        for edge in &mut edges {
            let entity_name = self.data_model.name_for(&edge.src_entity);
            edge.entity_name = entity_name;
        }
        let auth_service = self.auth_service.clone();
        let _ = self
            .graph_database
            .reader
            .send_async(Box::new(move |conn| {
                let edges =
                    EdgeDeletionEntry::with_source_authors(edges, conn).map_err(Error::from);
                match edges {
                    Ok(edges) => {
                        let msg = AuthorisationMessage::DeleteEdges(edges, reply);
                        let _ = auth_service.send_blocking(msg);
                    }
                    Err(e) => {
                        let _ = reply.send(Err(e));
                    }
                }
            }))
            .await;
    }

    pub async fn delete_nodes(&self, mut nodes: Vec<NodeDeletionEntry>, reply: Sender<Result<()>>) {
        for node in &mut nodes {
            let entity_name = self.data_model.name_for(&node.entity);
            node.entity_name = entity_name;
        }
        let auth_service = self.auth_service.clone();
        let _ = self
            .graph_database
            .reader
            .send_async(Box::new(move |conn| {
                let nodes =
                    NodeDeletionEntry::with_previous_authors(nodes, conn).map_err(Error::from);
                match nodes {
                    Ok(nodes) => {
                        let msg = AuthorisationMessage::DeleteNodes(nodes, reply);
                        let _ = auth_service.send_blocking(msg);
                    }
                    Err(e) => {
                        let _ = reply.send(Err(e));
                    }
                }
            }))
            .await;
    }
}

struct QueryCacheEntry {
    parser: Arc<QueryParser>,
    prepared_query: Arc<PreparedQueries>,
}

fn build_path(data_folder: impl Into<PathBuf>, file_name: &String) -> Result<PathBuf> {
    let mut path: PathBuf = data_folder.into();
    let subfolder = &file_name[0..2];
    path.push(subfolder);
    fs::create_dir_all(&path)?;
    path.push(file_name);
    Ok(path)
}
#[cfg(test)]
mod tests {

    const DATA_PATH: &str = "test_data/database/graph_database/";
    fn init_database_path() {
        let path: PathBuf = DATA_PATH.into();
        fs::create_dir_all(&path).unwrap();
    }

    use serde::Deserialize;

    use crate::{
        database::query_language::parameter::ParametersAdd,
        security::{random32, uid_encode},
        ResultParser,
    };

    use super::*;
    #[tokio::test(flavor = "multi_thread")]
    async fn selection() {
        init_database_path();

        let data_model = "{Person{ name:String }}";

        let secret = random32();
        let path: PathBuf = DATA_PATH.into();
        let (app, _, _) = GraphDatabaseService::start(
            "selection app",
            &data_model,
            &secret,
            &random32(),
            path,
            &Configuration::default(),
            EventService::new(),
            LogService::start(),
        )
        .await
        .unwrap();

        app.mutate_raw(
            r#"
        mutate mutmut {
            P2: Person { name:"Alice"  }
            P3: Person { name:"Bob"  }
        } "#,
            None,
        )
        .await
        .unwrap();

        let result = app
            .query(
                "query q {
            Person (order_by(name asc)){
                name
            }
        }",
                None,
            )
            .await
            .unwrap();

        let expected = "{\n\"Person\":[{\"name\":\"Alice\"},{\"name\":\"Bob\"}]\n}";
        assert_eq!(result, expected);
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn delete() {
        init_database_path();

        let data_model = "{Person{ name:String }}";

        let secret = random32();
        let path: PathBuf = DATA_PATH.into();
        let (app, _, _) = GraphDatabaseService::start(
            "delete app",
            &data_model,
            &secret,
            &random32(),
            path,
            &Configuration::default(),
            EventService::new(),
            LogService::start(),
        )
        .await
        .unwrap();

        let res = app
            .mutate_raw(
                r#"
        mutate mutmut {
            P2: Person { name:"Alice"  }
            P3: Person { name:"Bob"  }
        } "#,
                None,
            )
            .await
            .unwrap();

        let e = &res.mutate_entities[0].node_to_mutate.id;

        let mut param = Parameters::new();
        param.add("id", base64_encode(e)).unwrap();
        app.delete("delete {Person{$id}}", Some(param))
            .await
            .unwrap();

        let result = app
            .query(
                "query q {
            Person{
                name
            }
        }",
                None,
            )
            .await
            .unwrap();
        let expected = "{\n\"Person\":[{\"name\":\"Bob\"}]\n}";
        assert_eq!(result, expected);
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn load_data_model() {
        init_database_path();
        let secret = random32();
        //create a first instance
        {
            let data_model = "
            ns {
                Person{ 
                    name:String,
                    index(name)
                }
            }";
            let path: PathBuf = DATA_PATH.into();
            GraphDatabaseService::start(
                "load data_model app",
                &data_model,
                &secret,
                &random32(),
                path,
                &Configuration::default(),
                EventService::new(),
                LogService::start(),
            )
            .await
            .unwrap();
        }

        {
            let data_model = "
            ns {
                Person{ 
                    surname: String,
                    name:String 
                }
            }";
            let path: PathBuf = DATA_PATH.into();
            let is_error = GraphDatabaseService::start(
                "load data_model app",
                &data_model,
                &secret,
                &random32(),
                path,
                &Configuration::default(),
                EventService::new(),
                LogService::start(),
            )
            .await
            .is_err();
            assert!(is_error);
        }

        {
            let data_model = "
            ns {
                Person{ 
                    name:String ,
                    surname: String nullable,
                }
            }";
            let path: PathBuf = DATA_PATH.into();
            GraphDatabaseService::start(
                "load data_model app",
                &data_model,
                &secret,
                &random32(),
                path,
                &Configuration::default(),
                EventService::new(),
                LogService::start(),
            )
            .await
            .unwrap();
        }
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn init_room_id() {
        init_database_path();
        let secret = random32();

        let uid1 = {
            let data_model = "
                ns {
                    Person{ 
                        name:String,
                        index(name)
                    }
                }";
            let path: PathBuf = DATA_PATH.into();
            let (_, _, system_room_id) = GraphDatabaseService::start(
                "app",
                &data_model,
                &secret,
                &random32(),
                path,
                &Configuration::default(),
                EventService::new(),
                LogService::start(),
            )
            .await
            .unwrap();
            system_room_id
        };

        let uid2 = {
            let data_model = "
                ns {
                    Person{ 
                        name:String,
                        index(name)
                    }
                }";
            let path: PathBuf = DATA_PATH.into();
            let (_, _, system_room_id) = GraphDatabaseService::start(
                "app",
                &data_model,
                &secret,
                &random32(),
                path,
                &Configuration::default(),
                EventService::new(),
                LogService::start(),
            )
            .await
            .unwrap();
            system_room_id
        };
        assert_eq!(uid1, uid2);

        let uid3 = {
            let data_model = "
                ns {
                    Person{ 
                        name:String,
                        index(name)
                    }
                }";
            let path: PathBuf = DATA_PATH.into();
            let (_, _, system_room_id) = GraphDatabaseService::start(
                "another app",
                &data_model,
                &secret,
                &random32(),
                path,
                &Configuration::default(),
                EventService::new(),
                LogService::start(),
            )
            .await
            .unwrap();
            system_room_id
        };

        //the system_room_id depends on the app_key
        assert_ne!(uid1, uid3);
        let uid4 = {
            let data_model = "
                ns {
                    Person{ 
                        name:String,
                        index(name)
                    }
                }";
            let path: PathBuf = DATA_PATH.into();
            let (_, _, system_room_id) = GraphDatabaseService::start(
                "another app",
                &data_model,
                &random32(),
                &random32(),
                path,
                &Configuration::default(),
                EventService::new(),
                LogService::start(),
            )
            .await
            .unwrap();
            system_room_id
        };

        //the system_room_id depends on the key_material
        assert_ne!(uid3, uid4);
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn insert_system_room() {
        init_database_path();
        let secret = random32();

        let data_model = "
                ns {
                    Person{ 
                        name:String,
                        index(name)
                    }
                }";
        let path: PathBuf = DATA_PATH.into();
        let (app, _, system_room_id) = GraphDatabaseService::start(
            "app",
            &data_model,
            &secret,
            &random32(),
            path,
            &Configuration::default(),
            EventService::new(),
            LogService::start(),
        )
        .await
        .unwrap();
        let room_id = system_room_id;
        let mut param = Parameters::new();
        param.add("room_id", uid_encode(&room_id)).unwrap();

        app.mutate(
            r#"mutate{
                ns.Person{
                    room_id : $room_id
                    name : "test"
                }
            }"#,
            Some(param),
        )
        .await
        .expect("wildcard auth");
    }

    //
    // issue occured when updating entity sys.Peer to set a name.
    // this performs some deletion on the  _node_fts index that did not exits, causing an horrible:'database disk image is malformed'
    //
    #[tokio::test(flavor = "multi_thread")]
    async fn update_peer_with_empty_fts() {
        init_database_path();
        let secret = random32();

        let data_model = "";
        let path: PathBuf = DATA_PATH.into();
        let (app, verifying_key, system_room_id) = GraphDatabaseService::start(
            "app",
            &data_model,
            &secret,
            &random32(),
            path,
            &Configuration::default(),
            EventService::new(),
            LogService::start(),
        )
        .await
        .unwrap();
        let room_id = system_room_id;

        let mut param = Parameters::new();
        param.add("room_id", uid_encode(&room_id)).unwrap();

        let query = "query{
            res: sys.Peer(verifying_key=$verifyingKey){
              id
              name
            }
          }";

        let verifying_key = base64_encode(&verifying_key);
        let mut param = Parameters::new();
        param.add("verifyingKey", verifying_key).unwrap();

        let res = app.query(query, Some(param)).await.unwrap();
        println!("{}", res);
        #[derive(Deserialize)]
        struct PeerId {
            pub id: String,
        }

        let mut query_result = ResultParser::new(&res).unwrap();
        let peer_id: Vec<PeerId> = query_result.take_array("res").unwrap();

        let my_id: String = peer_id[0].id.clone();
        let mutate = r#"mutate {
            sys.Peer{
              id:$id
              name:$name
            }
          }"#;

        let mut param = Parameters::new();
        param.add("id", my_id).unwrap();
        param.add("name", "hello world".to_string()).unwrap();
        app.mutate(mutate, Some(param)).await.unwrap();
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn result_parser() {
        init_database_path();
        let secret = random32();

        let data_model = "{
            AllFieldType{
                a_string: String,
                a_float: Float,
                a_int: Integer,
                a_bool: Boolean,
            }
        }";
        #[derive(Deserialize)]
        struct AllFieldType {
            a_string: String,
            a_float: f64,
            a_int: i64,
            a_bool: bool,
        }

        let path: PathBuf = DATA_PATH.into();
        let (app, _, _) = GraphDatabaseService::start(
            "app",
            &data_model,
            &secret,
            &random32(),
            path,
            &Configuration::default(),
            EventService::new(),
            LogService::start(),
        )
        .await
        .unwrap();

        let mutate = r#"mutate {
            AllFieldType {
                a_string: $a_string
                a_float: $a_float
                a_int: $a_int
                a_bool: $a_bool
            }
          }"#;
        let a_string = "Some String";
        let a_float: f64 = 1.2;
        let a_int: i64 = 45;
        let a_bool = false;
        let mut param = Parameters::new();
        param.add("a_string", a_string.to_string()).unwrap();
        param.add("a_float", a_float).unwrap();
        param.add("a_int", a_int).unwrap();
        param.add("a_bool", a_bool).unwrap();

        let result = app.mutate(mutate, Some(param)).await.unwrap();

        let mut query_result = ResultParser::new(&result).unwrap();
        let all: AllFieldType = query_result.take_object("AllFieldType").unwrap();
        assert_eq!(all.a_string, a_string);
        assert_eq!(all.a_float, a_float);
        assert_eq!(all.a_int, a_int);
        assert_eq!(all.a_bool, a_bool);

        let query = r#"query {
            AllFieldType {
                a_string
                a_float
                a_int
                a_bool
            }
          }"#;

        let result = app.query(query, None).await.unwrap();
        // println!("{}", result);

        let mut query_result = ResultParser::new(&result).unwrap();
        let all_list: Vec<AllFieldType> = query_result.take_array("AllFieldType").unwrap();
        let all = &all_list[0];
        assert_eq!(all.a_string, a_string);
        assert_eq!(all.a_float, a_float);
        assert_eq!(all.a_int, a_int);
        assert_eq!(all.a_bool, a_bool);
    }
}
