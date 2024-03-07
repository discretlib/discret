use lru::LruCache;
use std::collections::HashMap;
use std::{fs, num::NonZeroUsize, path::PathBuf, sync::Arc};
use tokio::sync::oneshot::Sender;
use tokio::sync::{mpsc, oneshot};

use super::authorisation::{AuthorisationMessage, AuthorisationService, RoomAuthorisations};
use super::configuration;
use super::deletion::DeletionQuery;
use super::query_language::deletion_parser::DeletionParser;
use super::{
    configuration::Configuration,
    mutation_query::MutationQuery,
    query::{PreparedQueries, Query},
    query_language::{
        data_model_parser::DataModel, mutation_parser::MutationParser, parameter::Parameters,
        query_parser::QueryParser,
    },
    sqlite_database::Database,
    Error, Result,
};
use crate::cryptography::{base64_encode, derive_key, Ed25519SigningKey, SigningKey};

const LRU_SIZE: usize = 128;

enum Message {
    Query(String, Parameters, Sender<Result<String>>),
    Mutate(String, Parameters, Sender<Result<MutationQuery>>),
    Delete(String, Parameters, Sender<Result<DeletionQuery>>),
}

#[derive(Clone)]
pub struct GraphDatabaseService {
    sender: mpsc::Sender<Message>,
    verifying_key: Vec<u8>,
}
impl GraphDatabaseService {
    pub async fn start(
        name: &str,
        model: &str,
        key_material: &[u8; 32],
        data_folder: PathBuf,
        config: Configuration,
    ) -> Result<Self> {
        let (sender, mut receiver) = mpsc::channel::<Message>(100);

        let mut service = GraphDatabase::open(name, model, key_material, data_folder, config)?;
        service.initialise_authorisations().await?;

        let verifying_key = service.verifying_key.clone();
        tokio::spawn(async move {
            while let Some(msg) = receiver.recv().await {
                match msg {
                    Message::Query(query, parameters, reply) => {
                        let q = service.get_cached_query(&query);
                        match q {
                            Ok(cache) => {
                                //     println!("{}", &cache.1.sql_queries[0].sql_query);
                                service.query(cache.0, cache.1, parameters, reply).await;
                            }
                            Err(err) => {
                                let _ = reply.send(Err(err));
                            }
                        }
                    }
                    Message::Mutate(mutation, parameters, reply) => {
                        let mutation = service.get_cached_mutation(&mutation);
                        match mutation {
                            Ok(cache) => {
                                service.mutate(cache, parameters, reply).await;
                            }
                            Err(err) => {
                                let _ = reply.send(Err(err));
                            }
                        }
                    }
                    Message::Delete(deletion, parameters, reply) => {
                        let deletion = service.get_cached_deletion(&deletion);
                        match deletion {
                            Ok(cache) => {
                                service.delete(cache, parameters, reply).await;
                            }
                            Err(err) => {
                                let _ = reply.send(Err(err));
                            }
                        }
                    }
                }
            }
        });

        Ok(GraphDatabaseService {
            sender,
            verifying_key,
        })
    }

    pub fn verifying_key(&self) -> &Vec<u8> {
        &self.verifying_key
    }

    pub async fn delete(
        &self,
        deletion: &str,
        parameters: Option<Parameters>,
    ) -> Result<DeletionQuery> {
        let (send, recieve) = oneshot::channel::<Result<DeletionQuery>>();

        let msg = Message::Delete(deletion.to_string(), parameters.unwrap_or_default(), send);
        let _ = self.sender.send(msg).await;

        recieve.await?
    }

    pub async fn mutate(
        &self,
        mutation: &str,
        parameters: Option<Parameters>,
    ) -> Result<MutationQuery> {
        let (send, recieve) = oneshot::channel::<Result<MutationQuery>>();

        let msg = Message::Mutate(mutation.to_string(), parameters.unwrap_or_default(), send);
        let _ = self.sender.send(msg).await;

        recieve.await?
    }

    pub async fn query(&self, query: &str, parameters: Option<Parameters>) -> Result<String> {
        let (send, recieve) = oneshot::channel::<Result<String>>();
        let msg = Message::Query(query.to_string(), parameters.unwrap_or_default(), send);
        let _ = self.sender.send(msg).await;
        recieve.await?
    }
}

struct GraphDatabase {
    data_model: DataModel,
    auth_service: AuthorisationService,
    graph_database: Database,
    database_path: PathBuf,
    mutation_cache: LruCache<String, Arc<MutationParser>>,
    query_cache: LruCache<String, QueryCacheEntry>,
    deletion_cache: LruCache<String, Arc<DeletionParser>>,
    verifying_key: Vec<u8>,
}
impl GraphDatabase {
    pub fn open(
        name: &str,
        model: &str,
        key_material: &[u8; 32],
        data_folder: PathBuf,
        config: Configuration,
    ) -> Result<Self> {
        let database_secret = derive_key(&base64_encode(name.as_bytes()), key_material);

        let database_name = derive_key("DATABASE_NAME", &database_secret);

        let signature_key = derive_key("SIGNING_KEY", key_material);

        let signing_key = Ed25519SigningKey::create_from(&signature_key);
        let verifying_key = signing_key.export_verifying_key();
        let database_path = build_path(data_folder, &base64_encode(&database_name))?;

        let graph_database = Database::new(
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

        //
        //TODO load from database
        //
        let mut data_model = DataModel::new();
        data_model.update_system(configuration::SYSTEM_DATA_MODEL)?;

        data_model.update(model)?;

        let auth = RoomAuthorisations {
            signing_key,
            rooms: HashMap::new(),
        };

        let auth_service = AuthorisationService::start(auth);

        let database = Self {
            data_model,
            auth_service,
            graph_database,
            database_path,
            mutation_cache,
            query_cache,
            deletion_cache,
            verifying_key,
        };
        Ok(database)
    }

    pub async fn update_data_model(&mut self, model: &str) -> Result<()> {
        self.data_model.update(model)?;
        Ok(())
    }

    pub async fn initialise_authorisations(&mut self) -> Result<()> {
        let (send, recieve) = oneshot::channel::<Result<String>>();
        let cache = self.get_cached_query(&RoomAuthorisations::LOAD_QUERY)?;
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
        let writer = self.graph_database.writer.clone();

        let _ = self
            .graph_database
            .reader
            .send_async(Box::new(move |conn| {
                let mutation_query = MutationQuery::build(&parameters, mutation, conn);

                match mutation_query {
                    Ok(muta) => {
                        let msg = AuthorisationMessage::MutationQuery(muta, writer, reply);
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

    pub async fn query(
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
        let writer = self.graph_database.writer.clone();

        let _ = self
            .graph_database
            .reader
            .send_async(Box::new(move |conn| {
                let deletion_query = DeletionQuery::build(&parameters, deletion, conn);
                match deletion_query {
                    Ok(del) => {
                        let query = AuthorisationMessage::DeletionQuery(del, writer, reply);
                        let _ = auth_service.send_blocking(query);
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

    const DATA_PATH: &str = "test/data/database/graph_database/";
    fn init_database_path() {
        let path: PathBuf = DATA_PATH.into();
        fs::create_dir_all(&path).unwrap();
        let paths = fs::read_dir(path).unwrap();

        for path in paths {
            let dir = path.unwrap().path();
            let paths = fs::read_dir(dir).unwrap();
            for file in paths {
                let files = file.unwrap().path();
                // println!("Name: {}", files.display());
                let _ = fs::remove_file(&files);
            }
        }
    }

    use crate::{cryptography::random_secret, database::query_language::parameter::ParametersAdd};

    use super::*;
    #[tokio::test(flavor = "multi_thread")]
    async fn selection() {
        init_database_path();

        let data_model = "Person{ name:String }";

        let secret = random_secret();
        let path: PathBuf = DATA_PATH.into();
        let app = GraphDatabaseService::start(
            "selection app",
            data_model,
            &secret,
            path,
            Configuration::default(),
        )
        .await
        .unwrap();

        app.mutate(
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

        let data_model = "Person{ name:String }";

        let secret = random_secret();
        let path: PathBuf = DATA_PATH.into();
        let app = GraphDatabaseService::start(
            "delete app",
            data_model,
            &secret,
            path,
            Configuration::default(),
        )
        .await
        .unwrap();

        let res = app
            .mutate(
                r#"
        mutation mutmut {
            P2: Person { name:"Alice"  }
            P3: Person { name:"Bob"  }
        } "#,
                None,
            )
            .await
            .unwrap();

        let e = &res.insert_entities[0].node_insert.id;

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
}
