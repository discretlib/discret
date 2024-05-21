use lru::LruCache;
use rusqlite::{OptionalExtension, ToSql};
use std::collections::{HashSet, VecDeque};
use std::{collections::HashMap, fs, num::NonZeroUsize, path::PathBuf, sync::Arc};
use tokio::sync::{mpsc, oneshot, oneshot::Sender};

use super::sqlite_database::WriteStmt;
use super::system_entities::{self, Peer, PeerNodes};
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
    sqlite_database::{Database, DatabaseReader, RowMappingFn, WriteMessage, Writeable},
    system_entities::SYSTEM_DATA_MODEL,
    Error, Result,
};

use crate::{
    configuration::Configuration,
    date_utils::now,
    event_service::EventService,
    security::{base64_encode, derive_key, derive_uid, Ed25519SigningKey, SigningKey, Uid},
    synchronisation::node_full::FullNode,
};

const LRU_SIZE: usize = 128;

enum Message {
    Query(String, Parameters, Sender<Result<String>>),
    Mutate(String, Parameters, Sender<Result<MutationQuery>>),
    Delete(String, Parameters, Sender<Result<DeletionQuery>>),
    UpdateModel(String, Sender<Result<String>>),
    FullNodeAdd(Uid, Vec<FullNode>, Sender<Result<Vec<Uid>>>),
    DeleteEdges(Vec<EdgeDeletionEntry>, Sender<Result<()>>),
    DeleteNodes(Vec<NodeDeletionEntry>, Sender<Result<()>>),
    ComputeDailyLog(),
}
///
/// Entry Point for all databases interaction
///
///
#[derive(Clone)]
pub struct GraphDatabaseService {
    sender: mpsc::Sender<Message>,
    auth: AuthorisationService,
    db: Database,
    verifying_key: Vec<u8>,
    system_room_id: Uid,
}
impl GraphDatabaseService {
    pub async fn start(
        name: &str,
        model: &str,
        key_material: &[u8; 32],
        data_folder: PathBuf,
        config: Configuration,
        event_service: EventService,
    ) -> Result<Self> {
        let (sender, mut receiver) = mpsc::channel::<Message>(100);
        let system_room_id = derive_uid(&format!("{}{}", name, "SYSTEM_ROOM"), key_material);

        let mut db = GraphDatabase::new(
            system_room_id,
            model,
            name,
            key_material,
            data_folder,
            config,
            event_service,
        )
        .await?;

        let database = db.graph_database.clone();
        let auth = db.auth_service.clone();
        let verifying_key = db.verifying_key.clone();
        tokio::spawn(async move {
            while let Some(msg) = receiver.recv().await {
                match msg {
                    Message::Query(query, parameters, reply) => {
                        let q = db.get_cached_query(&query);
                        match q {
                            Ok(cache) => {
                                //     println!("{}", &cache.1.sql_queries[0].sql_query);
                                db.query(cache.0, cache.1, parameters, reply).await;
                            }
                            Err(err) => {
                                let _ = reply.send(Err(err));
                            }
                        }
                    }
                    Message::Mutate(mutation, parameters, reply) => {
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
                    Message::Delete(deletion, parameters, reply) => {
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

                    Message::FullNodeAdd(room_id, nodes, reply) => {
                        db.add_full_nodes(room_id, nodes, reply).await;
                    }

                    Message::UpdateModel(value, reply) => {
                        match db.update_data_model(&value).await {
                            Ok(model) => {
                                let _ = reply.send(Ok(model));
                            }
                            Err(err) => {
                                let _ = reply.send(Err(err));
                            }
                        }
                    }
                    Message::ComputeDailyLog() => {
                        _ = db
                            .graph_database
                            .writer
                            .send(WriteMessage::ComputeDailyLog(
                                DailyLogsUpdate::default(),
                                db.event_service.sender.clone(),
                            ))
                            .await;
                    }

                    Message::DeleteEdges(edges, reply) => {
                        db.delete_edges(edges, reply).await;
                    }
                    Message::DeleteNodes(nodes, reply) => {
                        db.delete_nodes(nodes, reply).await;
                    }
                }
            }
        });

        Ok(GraphDatabaseService {
            sender,
            auth,
            db: database,
            verifying_key,
            system_room_id,
        })
    }

    ///
    /// Get the verifying key derived from the key material
    /// The assiociated signing key is used internaly to sign every change
    ///
    pub fn verifying_key(&self) -> &Vec<u8> {
        &self.verifying_key
    }

    ///
    /// Get the verifying key derived from the key material
    /// The assiociated signing key is used internaly to sign every change
    ///
    pub fn system_room_id(&self) -> &Uid {
        &self.system_room_id
    }

    ///
    /// Deletion query
    ///
    pub async fn delete(
        &self,
        deletion: &str,
        param_opt: Option<Parameters>,
    ) -> Result<DeletionQuery> {
        let (reply, receive) = oneshot::channel::<Result<DeletionQuery>>();
        let msg = Message::Delete(deletion.to_string(), param_opt.unwrap_or_default(), reply);
        let _ = self.sender.send(msg).await;
        let result = receive.await?;
        let _ = self.sender.send(Message::ComputeDailyLog()).await;
        result
    }

    ///
    /// GraphQL mutation query
    /// returns and internal representation of the result
    /// should be only used by tests
    ///
    pub async fn mutate_raw(
        &self,
        mutation: &str,
        param_opt: Option<Parameters>,
    ) -> Result<MutationQuery> {
        let (reply, receive) = oneshot::channel::<Result<MutationQuery>>();

        let msg = Message::Mutate(mutation.to_string(), param_opt.unwrap_or_default(), reply);
        let _ = self.sender.send(msg).await;

        let result = receive.await?;

        let _ = self.sender.send(Message::ComputeDailyLog()).await;

        result
    }

    ///
    /// GraphQL mutation query
    /// returns a json string
    ///
    pub async fn mutate(&self, mutation: &str, param_opt: Option<Parameters>) -> Result<String> {
        let raw = self.mutate_raw(mutation, param_opt).await;
        match raw {
            Ok(query) => match query.to_json() {
                Ok(value) => serde_json::to_string(&value).map_err(Error::from),
                Err(e) => Err(e),
            },
            Err(e) => Err(e),
        }
    }

    ///
    /// GraphQL query
    ///
    pub async fn query(&self, query: &str, param_opt: Option<Parameters>) -> Result<String> {
        let (reply, receive) = oneshot::channel::<Result<String>>();
        let msg = Message::Query(query.to_string(), param_opt.unwrap_or_default(), reply);
        let _ = self.sender.send(msg).await;
        receive.await?
    }

    ///
    /// Perform a SQL Selection query on the database
    /// SQL mutation query are forbidden
    ///
    pub async fn select<T: Send + Sized + 'static>(
        &self,
        query: String,
        params: Vec<Box<dyn ToSql + Sync + Send>>,
        mapping: RowMappingFn<T>,
    ) -> Result<Vec<T>> {
        let (reply, receive) = oneshot::channel::<Result<Vec<T>>>();

        self.db
            .reader
            .send_async(Box::new(move |conn| {
                let result =
                    DatabaseReader::select(&query, &params, &mapping, conn).map_err(Error::from);
                let _ = reply.send(result);
            }))
            .await?;
        receive.await?
    }

    ///
    /// Update the existing data model definition with a new one  
    ///
    pub async fn update_data_model(&self, query: &str) -> Result<String> {
        let (reply, receive) = oneshot::channel::<Result<String>>();
        let msg = Message::UpdateModel(query.to_string(), reply);
        let _ = self.sender.send(msg).await;
        receive.await?
    }

    ///
    /// insert the full node list
    /// returns the list of ids that where not inserted for any reasons (parsing error, authorisations)
    ///
    pub async fn add_full_nodes(&self, room_id: Uid, nodes: Vec<FullNode>) -> Result<Vec<Uid>> {
        let (reply, receive) = oneshot::channel::<Result<Vec<Uid>>>();
        let msg = Message::FullNodeAdd(room_id, nodes, reply);
        let _ = self.sender.send(msg).await;
        receive.await?
    }

    ///
    /// Ask the database to compute daily log
    /// this is an expensive operation that should be used only after a large batch insert whenever possible
    /// This will send an event that will trigger the peer synchronisation
    ///
    pub async fn compute_daily_log(&self) {
        let _ = self.sender.send(Message::ComputeDailyLog()).await;
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
    pub async fn get_rooms_for_user(&self, verifying_key: Vec<u8>) -> Result<VecDeque<Uid>> {
        let (reply, receive) = oneshot::channel::<HashSet<Uid>>();
        let _ = self
            .auth
            .send(AuthorisationMessage::RoomForUser(
                verifying_key,
                now(),
                reply,
            ))
            .await;

        let res = receive.await;
        let (reply, receive) = oneshot::channel::<Result<VecDeque<Uid>>>();

        match res {
            Ok(room_ids) => {
                let _ = self
                    .db
                    .reader
                    .send_async(Box::new(move |conn| {
                        let log = DailyLog::sort_rooms(&room_ids, conn).map_err(Error::from);
                        let _ = reply.send(log);
                    }))
                    .await;
            }
            Err(e) => {
                let _ = reply.send(Err(Error::ChannelSend(e.to_string())));
            }
        }
        receive.await?
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
    pub async fn get_room_log(&self, room_id: Uid) -> Result<Vec<DailyLog>> {
        let (reply, receive) = oneshot::channel::<Result<Vec<DailyLog>>>();
        self.db
            .reader
            .send_async(Box::new(move |conn| {
                let room_log = DailyLog::get_room_log(&room_id, conn).map_err(Error::from);
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
        del_date: i64,
    ) -> Result<Vec<NodeDeletionEntry>> {
        let (send_response, receive_response) =
            oneshot::channel::<Result<Vec<NodeDeletionEntry>>>();
        self.db
            .reader
            .send_async(Box::new(move |conn| {
                let deteletions =
                    NodeDeletionEntry::get_entries(&room_id, del_date, conn).map_err(Error::from);
                let _ = send_response.send(deteletions);
            }))
            .await?;
        receive_response.await?
    }

    ///
    /// get node deletions for a room at a specific day
    ///V
    pub async fn delete_nodes(&self, nodes: Vec<NodeDeletionEntry>) -> Result<()> {
        let (send_response, receive_response) = oneshot::channel::<Result<()>>();
        let msg = Message::DeleteNodes(nodes, send_response);
        let _ = self.sender.send(msg).await;
        receive_response.await?
    }

    ///
    /// get edge deletions for a room at a specific day
    ///
    pub async fn get_room_edge_deletion_log(
        &self,
        room_id: Uid,
        del_date: i64,
    ) -> Result<Vec<EdgeDeletionEntry>> {
        let (reply, receive) = oneshot::channel::<Result<Vec<EdgeDeletionEntry>>>();
        self.db
            .reader
            .send_async(Box::new(move |conn| {
                let deteletions =
                    EdgeDeletionEntry::get_entries(&room_id, del_date, conn).map_err(Error::from);
                let _ = reply.send(deteletions);
            }))
            .await?;
        receive.await?
    }

    ///
    /// get node deletions for a room at a specific day
    ///V
    pub async fn delete_edges(&self, edges: Vec<EdgeDeletionEntry>) -> Result<()> {
        let (reply, receive) = oneshot::channel::<Result<()>>();
        let msg = Message::DeleteEdges(edges, reply);
        let _ = self.sender.send(msg).await;
        receive.await?
    }

    ///
    /// get all node id for a room at a specific day
    ///
    pub async fn get_room_daily_nodes(
        &self,
        room_id: Uid,
        date: i64,
    ) -> Result<HashSet<NodeIdentifier>> {
        let (reply, receive) = oneshot::channel::<Result<HashSet<NodeIdentifier>>>();
        self.db
            .reader
            .send_async(Box::new(move |conn| {
                let room_node = Node::get_daily_nodes_for_room(&room_id, date, conn);
                let _ = reply.send(room_node);
            }))
            .await?;
        receive.await?
    }

    ///
    /// filter the nodes ids that exists at this specific date
    ///
    pub async fn filter_existing_node(
        &self,
        mut node_ids: HashSet<NodeIdentifier>,
        date: i64,
    ) -> Result<HashSet<NodeIdentifier>> {
        let (reply, receive) = oneshot::channel::<Result<HashSet<NodeIdentifier>>>();
        self.db
            .reader
            .send_async(Box::new(move |conn| {
                match Node::retain_missing_id(&mut node_ids, date, conn).map_err(Error::from) {
                    Ok(_) => {
                        let _ = reply.send(Ok(node_ids));
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
    pub async fn get_full_nodes(&self, room_id: Uid, node_ids: Vec<Uid>) -> Result<Vec<FullNode>> {
        let (reply, receive) = oneshot::channel::<Result<Vec<FullNode>>>();
        self.db
            .reader
            .send_async(Box::new(move |conn| {
                let room_node = FullNode::get_nodes_filtered_by_room(&room_id, node_ids, conn);
                let _ = reply.send(room_node);
            }))
            .await?;
        receive.await?
    }

    ///
    /// retrieve sys.Peer node
    ///
    pub async fn get_peer_nodes(&self, room_id: Uid, keys: Vec<Vec<u8>>) -> Result<Vec<Node>> {
        let (reply, receive) = oneshot::channel::<Result<Vec<Vec<u8>>>>();
        let _ = self
            .auth
            .send(AuthorisationMessage::ValidatePeerNodesRequest(
                room_id, keys, reply,
            ))
            .await;
        let valid_rs = receive.await;
        if let Err(e) = valid_rs {
            return Err(e.into());
        }

        let (reply, receive) = oneshot::channel::<Result<Vec<Node>>>();

        match valid_rs.unwrap() {
            Ok(list) => {
                let _ = self
                    .db
                    .reader
                    .send_async(Box::new(move |conn| {
                        let nodes_rs = Peer::get(list, conn);
                        let _ = reply.send(nodes_rs);
                    }))
                    .await;
            }
            Err(e) => {
                let _ = reply.send(Err(e.into()));
            }
        }
        receive.await?
    }

    ///
    /// insert sys.Peer nodes
    ///
    pub async fn add_peer_nodes(&self, nodes: Vec<Node>) -> Result<()> {
        let (reply, receive) = oneshot::channel::<Result<WriteStmt>>();
        for node in &nodes {
            node.verify()?;
        }
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
    /// retrieve users for a room
    ///
    pub async fn users_for_room(&self, room_id: Uid) -> Result<HashSet<Vec<u8>>> {
        let (reply, receive) = oneshot::channel::<Result<HashSet<Vec<u8>>>>();
        let _ = self
            .auth
            .send(AuthorisationMessage::UserForRoom(room_id, reply))
            .await;
        receive.await?
    }

    ///
    /// retrieve id of users defined in room users but not in the sys.Peer entity
    ///
    pub async fn missing_peers(&self, peers: HashSet<Vec<u8>>) -> Result<HashSet<Vec<u8>>> {
        let (reply, receive) = oneshot::channel::<Result<HashSet<Vec<u8>>>>();
        self.db
            .reader
            .send_async(Box::new(move |conn| {
                let room_node = Peer::get_missing(peers, conn);
                let _ = reply.send(room_node);
            }))
            .await?;
        receive.await?
    }
}

struct GraphDatabase {
    data_model: DataModel,
    auth_service: AuthorisationService,
    graph_database: Database,
    event_service: EventService,
    database_path: PathBuf,
    mutation_cache: LruCache<String, Arc<MutationParser>>,
    query_cache: LruCache<String, QueryCacheEntry>,
    deletion_cache: LruCache<String, Arc<DeletionParser>>,
    verifying_key: Vec<u8>,
}
impl GraphDatabase {
    pub async fn new(
        system_room_id: Uid,
        model: &str,
        name: &str,
        key_material: &[u8; 32],
        data_folder: PathBuf,
        config: Configuration,
        event_service: EventService,
    ) -> Result<Self> {
        let database_secret = derive_key(&name, key_material);

        let database_name = derive_key("DATABASE_NAME", &database_secret);

        let signature_key = derive_key("SIGNING_KEY", key_material);

        let signing_key = Ed25519SigningKey::create_from(&signature_key);
        let verifying_key = signing_key.export_verifying_key();
        let database_path = build_path(data_folder, &base64_encode(&database_name))?;

        let graph_database = Database::start(
            &database_path,
            &database_secret,
            config.read_cache_size_in_kb,
            config.read_parallelism,
            config.write_cache_size_in_kb,
            config.write_buffer_size,
            config.enable_database_memory_security,
        )?;

        let mutation_cache = LruCache::new(NonZeroUsize::new(LRU_SIZE).unwrap());
        let query_cache = LruCache::new(NonZeroUsize::new(LRU_SIZE).unwrap());
        let deletion_cache = LruCache::new(NonZeroUsize::new(LRU_SIZE).unwrap());

        let data_model = DataModel::new();

        let mut auth = RoomAuthorisations {
            signing_key,
            rooms: HashMap::new(),
        };

        // create the system room associated the user
        auth.create_system_room(
            system_room_id,
            system_entities::sys_room_entities(),
            &graph_database.writer,
        )
        .await?;

        let auth_service =
            AuthorisationService::start(auth, graph_database.writer.clone(), event_service.clone());

        let mut database = Self {
            data_model,
            auth_service,
            graph_database,
            event_service,
            database_path,
            mutation_cache,
            query_cache,
            deletion_cache,
            verifying_key,
        };

        database.update_data_model(model).await?;
        database.initialise_authorisations().await?;
        //ensure that the logs are properly computed during startup  because the application can be closed during a synchronisation
        database
            .graph_database
            .writer
            .send(WriteMessage::ComputeDailyLog(
                DailyLogsUpdate::default(),
                database.event_service.sender.clone(),
            ))
            .await?;

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
        parameters: Parameters,
        reply: Sender<Result<MutationQuery>>,
    ) {
        let auth_service = self.auth_service.clone();
        let _ = self
            .graph_database
            .reader
            .send_async(Box::new(move |conn| {
                let mutation_query = MutationQuery::execute(&parameters, mutation.clone(), conn);

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
        let sql = Query {
            parameters,
            parser,
            sql_queries,
        };

        let _ = self
            .graph_database
            .reader
            .send_async(Box::new(move |conn| {
                // let result = Self::select(&query, &params, &mapping, conn).map_err(Error::from);
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
        parameters: Parameters,
        reply: Sender<Result<DeletionQuery>>,
    ) {
        let auth_service = self.auth_service.clone();
        let _ = self
            .graph_database
            .reader
            .send_async(Box::new(move |conn| {
                let deletion_query = DeletionQuery::build(&parameters, deletion, conn);
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

    pub async fn add_full_nodes(
        &self,
        room_id: Uid,
        nodes: Vec<FullNode>,
        reply: Sender<Result<Vec<Uid>>>,
    ) {
        let mut invalid_nodes = Vec::new();
        let mut valid_nodes = Vec::new();

        for mut node in nodes {
            let entity_name = self.data_model.name_for(&node.node._entity);
            match entity_name {
                Some(name) => {
                    match self.data_model.get_entity(&name) {
                        Ok(ent) => {
                            match node.entity_validation(ent) {
                                Ok(_) => valid_nodes.push(node),
                                Err(_e) => {
                                    // println!("{}", e);
                                    //silent error. will just indicate peer that some node is erroneous
                                    invalid_nodes.push(node.node.id)
                                }
                            }
                        }
                        Err(_e) => {
                            //println!("{}", e);
                            //silent error. will just indicate peer that some node is erroneous
                            invalid_nodes.push(node.node.id);
                        }
                    }
                }
                None => {
                    // println!("missing entity");
                    //silent error. will just indicate peer that some node is erroneous
                    invalid_nodes.push(node.node.id);
                }
            }
        }
        let auth_service = self.auth_service.clone();
        let _ = self
            .graph_database
            .reader
            .send_async(Box::new(move |conn| {
                let val_nodes =
                    FullNode::prepare_for_insert(&room_id, valid_nodes, conn).map_err(Error::from);
                match val_nodes {
                    Ok(val_nodes) => {
                        let msg =
                            AuthorisationMessage::AddFullNode(val_nodes, invalid_nodes, reply);
                        let _ = auth_service.send_blocking(msg);
                    }
                    Err(e) => {
                        let _ = reply.send(Err(e));
                    }
                }
            }))
            .await;
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
        // let paths = fs::read_dir(path).unwrap();

        // for path in paths {
        //     let dir = path.unwrap().path();
        //     let paths = fs::read_dir(dir).unwrap();
        //     for file in paths {
        //         let files = file.unwrap().path();
        //         // println!("Name: {}", files.display());
        //         //let _ = fs::remove_file(&files);
        //     }
        // }
    }

    use crate::{
        database::query_language::parameter::ParametersAdd,
        security::{random32, uid_encode},
    };

    use super::*;
    #[tokio::test(flavor = "multi_thread")]
    async fn selection() {
        init_database_path();

        let data_model = "{Person{ name:String }}";

        let secret = random32();
        let path: PathBuf = DATA_PATH.into();
        let app = GraphDatabaseService::start(
            "selection app",
            &data_model,
            &secret,
            path,
            Configuration::default(),
            EventService::new(),
        )
        .await
        .unwrap();

        app.mutate_raw(
            r#"
        mutation mutmut {
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
        let app = GraphDatabaseService::start(
            "delete app",
            &data_model,
            &secret,
            path,
            Configuration::default(),
            EventService::new(),
        )
        .await
        .unwrap();

        let res = app
            .mutate_raw(
                r#"
        mutation mutmut {
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
        app.delete("deletion del {Person{$id}}", Some(param))
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
                path,
                Configuration::default(),
                EventService::new(),
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
                path,
                Configuration::default(),
                EventService::new(),
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
                path,
                Configuration::default(),
                EventService::new(),
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
            let app = GraphDatabaseService::start(
                "app",
                &data_model,
                &secret,
                path,
                Configuration::default(),
                EventService::new(),
            )
            .await
            .unwrap();
            app.system_room_id
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
            let app = GraphDatabaseService::start(
                "app",
                &data_model,
                &secret,
                path,
                Configuration::default(),
                EventService::new(),
            )
            .await
            .unwrap();
            app.system_room_id
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
            let app = GraphDatabaseService::start(
                "another app",
                &data_model,
                &secret,
                path,
                Configuration::default(),
                EventService::new(),
            )
            .await
            .unwrap();
            app.system_room_id
        };

        //the system_room_id depends on the name
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
            let app = GraphDatabaseService::start(
                "another app",
                &data_model,
                &random32(),
                path,
                Configuration::default(),
                EventService::new(),
            )
            .await
            .unwrap();
            app.system_room_id
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
        let app = GraphDatabaseService::start(
            "app",
            &data_model,
            &secret,
            path,
            Configuration::default(),
            EventService::new(),
        )
        .await
        .unwrap();
        let room_id = app.system_room_id;
        let mut param = Parameters::new();
        param.add("room_id", uid_encode(&room_id)).unwrap();

        app.mutate(
            r#"mutation{
                ns.Person{
                    room_id : $room_id
                    name : "test"
                }
            }"#,
            Some(param),
        )
        .await
        .expect_err("AuthorisationRejected");

        let mut param = Parameters::new();
        param.add("room_id", uid_encode(&room_id)).unwrap();
        app.mutate(
            r#"mutation{
                sys.Beacon{
                        room_id : $room_id
                        address : "test"
                }
            }"#,
            Some(param),
        )
        .await
        .expect("sys.Beacon can be inserted");
    }
}
