use rusqlite::{functions::FunctionFlags, Connection, OptionalExtension, Row, ToSql};

use std::{path::PathBuf, thread, time, usize};
use tokio::sync::{
    mpsc,
    oneshot::{self, Sender},
};

use crate::security::{base64_decode, base64_encode, Uid};

use super::{
    authorisation_service::{
        AuthorisationMessage, RoomMutationStreamWriteQuery, RoomMutationWriteQuery,
        RoomNodeWriteQuery,
    },
    daily_log::{DailyLog, DailyLogsUpdate, DailyMutations},
    deletion::DeletionQuery,
    edge::{Edge, EdgeDeletionEntry},
    graph_database::DbMessage,
    mutation_query::MutationQuery,
    node::{Node, NodeDeletionEntry, NodeToInsert},
    system_entities, Error, Result,
};

pub type RowMappingFn<T> = fn(&Row) -> std::result::Result<Box<T>, rusqlite::Error>;
pub type QueryFn = Box<dyn FnOnce(&Connection) + Send + 'static>;

//Create a sqlcipher database connection
//
//path: database file path
//
//secret: the encryption key
//
//cache_size:
//  for example: 8Mb for the DatabaseReader's connection and 1Mb for the DatabaseWriter's to get a relatively low memory usage,
//  but the more you have the better. Large values will increase performances by reducing number of disk read.
//
//enable_memory_security: Prevents memory to be written into swap and zeroise memory after free
//  Can be disabled because of a huge performance impact (about 50%),
//  When this feature is disabled, locking/unlocking of the memory address only occur for the internal SQLCipher
//  data structures used to store key material, and cryptographic structures.
//  source: https://discuss.zetetic.net/t/what-is-the-purpose-of-pragma-cipher-memory-security/3953
//
pub fn create_connection(
    path: &PathBuf,
    secret: &[u8; 32],
    cache_size_in_kb: usize,
    enable_memory_security: bool,
) -> Result<Connection> {
    let mut flags = rusqlite::OpenFlags::empty();
    flags.insert(rusqlite::OpenFlags::SQLITE_OPEN_CREATE);
    flags.insert(rusqlite::OpenFlags::SQLITE_OPEN_READ_WRITE);

    //Don't follow unix symbolic link
    // flags.insert(rusqlite::OpenFlags::SQLITE_OPEN_NOFOLLOW);

    //Disable mutex so a single connection can only be used by one thread.
    //
    //safe to use because of the rust strong concurency model
    //
    flags.insert(rusqlite::OpenFlags::SQLITE_OPEN_NO_MUTEX);
    let conn = rusqlite::Connection::open_with_flags(path, flags)?;

    //set cache capacity to 128 (from default 16)
    conn.set_prepared_statement_cache_capacity(128);

    //Encrypt the database.
    //
    //The "x'key'"" format means that no additional key derivation is done by sqlcipher
    let sqlcipher_key = format!("\"x'{}'\"", hex::encode(secret));
    set_pragma("key", &sqlcipher_key, &conn)?;

    //
    // Increase page size as JSON data can be quite large
    //
    let page_size = "8192";
    set_pragma("cipher_page_size", page_size, &conn)?;
    set_pragma("page_size", page_size, &conn)?;

    //Enable/disable memory security.
    if enable_memory_security {
        set_pragma("cipher_memory_security", "1", &conn)?;
    } else {
        set_pragma("cipher_memory_security", "0", &conn)?;
    }

    //Temp files are stored in memory.
    //any other values would break sqlciper security
    set_pragma("temp_store", "2", &conn)?;

    //Enable mmap for increased performance,
    //
    //Value is the one recommended in the doc: 256 Mb
    //  - Is it ok on phones?
    //  - Disabled because it hides the real RAM usage on linux, which is anoying for a desktop applications
    //set_pragma("mmap_size", "268435456", &conn)?;

    //
    //larger cache size can greatly increase performances by reducing disk access
    //
    set_pragma("cache_size", &format!("-{}", cache_size_in_kb), &conn)?;

    //WAL journaling system allows concurent READ/WRITE.
    set_pragma("journal_mode", "WAL", &conn)?;

    //WAL checkpoin every 1000 dirty pages.
    set_pragma("wal_autocheckpoint", "1000", &conn)?;

    //Best safe setting for WAL journaling.
    set_pragma("synchronous", "1", &conn)?;

    //increase write lock request timeout
    //has probably no effect because we insert data from a single thread
    set_pragma("busy_timeout", "5000", &conn)?;

    //Automatically reclaim storage after deletion
    //
    //enabled to keep database small
    set_pragma("auto_vacuum", "1", &conn)?;

    //enabled to avoid a bug when using json extract in partial index: "unsafe use of ->>() in CREATE INDEX"
    //see https://sqlite.org/forum/forumpost/c88a671ad083d153
    set_pragma("trusted_schema", "1", &conn)?;

    //enable foreign keys
    set_pragma("foreign_keys", "1", &conn)?;

    prepare_connection(&conn)?;
    Ok(conn)
}

///
/// Creates the necessary tables in one transaction.
///
/// Add a user defined function to handle base64 encoding directly in the database
///
/// This function is separated from create_connection() to be able to create unit test using in_memory databases
///
pub fn prepare_connection(conn: &Connection) -> Result<()> {
    add_base64_function(conn)?;
    let initialised: Option<String> = conn
        .query_row(
            "SELECT name FROM sqlite_schema WHERE type IN ('table','view') AND name = '_node'",
            [],
            |row| row.get(0),
        )
        .optional()?;

    if initialised.is_none() {
        conn.execute("BEGIN TRANSACTION", [])?;
        Node::create_tables(conn)?;
        Edge::create_tables(conn)?;
        DailyLog::create_tables(&conn)?;
        system_entities::create_table(conn)?;
        conn.execute("COMMIT", [])?;
    }
    Ok(())
}

//
// helper function to configure sqlite
//
fn set_pragma(pragma: &str, value: &str, conn: &rusqlite::Connection) -> Result<()> {
    let mut stmt = conn.prepare(&format!("PRAGMA {}={}", pragma, value))?;
    let _rows = stmt.query([])?;
    Ok(())
}

///
/// Database main entry point
///
///
#[derive(Clone)]
pub struct Database {
    pub reader: DatabaseReader,
    pub writer: BufferedDatabaseWriter,
}
impl Database {
    pub fn start(
        path: &PathBuf,
        secret: &[u8; 32],
        read_cache_size_in_kb: usize,
        read_parallelism: usize,
        write_cache_size_in_kb: usize,
        write_buffer_size: usize,
        enable_memory_security: bool,
    ) -> Result<Self> {
        let writer = BufferedDatabaseWriter::start(
            write_buffer_size,
            path,
            secret,
            write_cache_size_in_kb,
            enable_memory_security,
        )?;

        let reader = DatabaseReader::start(
            path,
            secret,
            read_cache_size_in_kb,
            read_parallelism,
            enable_memory_security,
        )?;

        Ok(Database { reader, writer })
    }
}

// Main entry point to perform SELECT queries
//
// Thread Safe: Clone it to safely perform queries across different thread
//
// Sqlite in WAL mode support READ/WRITE concurency, wich makes the separation between read and write thread efficient
// it is possible to open several reader but beware that each reader will consume 'cache_size_in_kb' of memory
//
#[derive(Clone)]
pub struct DatabaseReader {
    pub sender: flume::Sender<QueryFn>,
}
impl DatabaseReader {
    pub fn start(
        path: &PathBuf,
        secret: &[u8; 32],
        cache_size_in_kb: usize,
        parallelism: usize,
        enable_memory_security: bool,
    ) -> Result<Self> {
        let (sender, receiver) = flume::bounded::<QueryFn>(100);
        for _i in 0..parallelism {
            //
            // sleep a few milliseconds to avoid some random IO errors during tests on linux
            // might be caused by:
            //        - the cleanup process at the beginning of some tests (see graph_database tests)
            //        - the rapid creation of several instance of the connection
            //
            let ten_millis = time::Duration::from_millis(50);
            thread::sleep(ten_millis);
            let conn =
                create_connection(path, secret, cache_size_in_kb, enable_memory_security).unwrap();

            set_pragma("query_only", "1", &conn)?;

            let local_receiver = receiver.clone();
            thread::spawn(move || {
                while let Ok(q) = local_receiver.recv() {
                    q(&conn);
                }
            });
        }
        Ok(Self { sender })
    }

    pub fn send_blocking(&self, query: QueryFn) -> Result<()> {
        self.sender
            .send(query)
            .map_err(|e| Error::ChannelSend(e.to_string()))?;
        Ok(())
    }

    pub async fn send_async(&self, query: QueryFn) -> Result<()> {
        self.sender
            .send_async(query)
            .await
            .map_err(|e| Error::ChannelSend(e.to_string()))?;
        Ok(())
    }

    pub fn query_blocking<T: Send + Sized + 'static>(
        &self,
        query: String,
        params: Vec<Box<dyn ToSql + Sync + Send>>,
        mapping: RowMappingFn<T>,
    ) -> Result<Vec<T>> {
        let (send_response, receive_response) = oneshot::channel::<Result<Vec<T>>>();

        self.send_blocking(Box::new(move |conn| {
            let result = Self::select(&query, &params, &mapping, conn).map_err(Error::from);
            let _ = send_response.send(result);
        }))?;

        receive_response.blocking_recv()?
    }

    pub async fn query_async<T: Send + Sized + 'static>(
        &self,
        query: String,
        params: Vec<Box<dyn ToSql + Sync + Send>>,
        mapping: RowMappingFn<T>,
    ) -> Result<Vec<T>> {
        let (send_response, receive_response) = oneshot::channel::<Result<Vec<T>>>();

        self.send_async(Box::new(move |conn| {
            let result = Self::select(&query, &params, &mapping, conn).map_err(Error::from);
            let _ = send_response.send(result);
        }))
        .await?;

        receive_response.await?
    }

    pub fn select<T: Send + Sized + 'static>(
        query: &str,
        params: &Vec<Box<dyn ToSql + Sync + Send>>,
        mapping: &RowMappingFn<T>,
        conn: &Connection,
    ) -> Result<Vec<T>> {
        let mut stmt = conn.prepare_cached(query)?;
        let params = rusqlite::params_from_iter(params);
        let iter = stmt.query_map(params, mapping)?;
        let mut result: Vec<T> = vec![];
        for res in iter {
            result.push(*res?)
        }
        Ok(result)
    }
}

pub type WriteStmt = Box<dyn Writeable + Send>;
pub type WriteReplyFn = Box<dyn FnOnce(Result<WriteStmt>) + Send + 'static>;

/// Trait use to write content in the database
///   returns only rusqlite::Error as it is forbidden to do anything that could fails during the write process
///   writes happens in batched transaction, and we want to avoid any errors that would results in the rollback of a potentially large number of inserts
pub trait Writeable {
    fn write(&mut self, conn: &Connection) -> std::result::Result<(), rusqlite::Error>;
}

pub enum WriteMessage {
    Deletion(DeletionQuery, Sender<Result<DeletionQuery>>),
    Mutation(MutationQuery, Sender<Result<MutationQuery>>),
    MutationStream(MutationQuery, mpsc::Sender<Result<MutationQuery>>),
    RoomMutation(RoomMutationWriteQuery, mpsc::Sender<AuthorisationMessage>),
    RoomMutationStream(
        RoomMutationStreamWriteQuery,
        mpsc::Sender<AuthorisationMessage>,
    ),
    RoomNode(RoomNodeWriteQuery, mpsc::Sender<AuthorisationMessage>),
    Nodes(Vec<NodeToInsert>, Vec<Uid>, Sender<Result<Vec<Uid>>>),
    Edges(Vec<Edge>, Vec<Uid>, Sender<Result<Vec<Uid>>>),
    DeleteEdges(Vec<EdgeDeletionEntry>, Sender<Result<()>>),
    DeleteNodes(Vec<NodeDeletionEntry>, Sender<Result<()>>),
    Write(WriteStmt, Sender<Result<WriteStmt>>),
    ComputeDailyLog(DailyLogsUpdate, mpsc::Sender<DbMessage>),
}

/// Main entry point to insert data in the database
///
/// Thread Safe: Clone it to safely perform queries across different thread
/// Only one writer should be used per database
///
/// Write queries are buffered while the database thread is working.
/// When the database thread is ready, the buffer is sent and is processed in one single transaction
/// This greatly increase insertion and update rate, compared to autocommit.
///      To get an idea of the perforance difference,
///      a very simple benchmak on a laptop with 100 000 insertions gives:
///      Buffer size: 1      Insert/seconds: 55  <- this is equivalent to autocommit
///      Buffer size: 10     Insert/seconds: 500
///      Buffer size: 100    Insert/seconds: 3000
///      Buffer size: 1000   Insert/seconds: 32000
///
/// If one a buffered query fails, the transaction will be rolled back and every other queries in the buffer will fail too.
/// This should not be an issue as INSERT query are not expected to fail.
/// The only reasons to fail an insertion are a bugs or a system failure (like no more space available on disk),
/// And in both case, it is ok to fail the last insertions batch.
///
///
#[derive(Clone)]
pub struct BufferedDatabaseWriter {
    sender: mpsc::Sender<WriteMessage>,
}
impl BufferedDatabaseWriter {
    pub fn start(
        buffer_size: usize,
        path: &PathBuf,
        secret: &[u8; 32],
        write_cache_size: usize,
        enable_memory_security: bool,
    ) -> Result<Self> {
        let conn = create_connection(path, secret, write_cache_size, enable_memory_security)?;
        //only a few query can be buffered here
        //the real buffering using the buffer_size happens later
        const WRITE_QUERY_BUFFER: usize = 4;
        let (send_write, mut receive_write): (
            mpsc::Sender<WriteMessage>,
            mpsc::Receiver<WriteMessage>,
        ) = mpsc::channel::<WriteMessage>(WRITE_QUERY_BUFFER);

        //allows only one infligh buffer: one that is currentlu being processed
        const PROCESS_CHANNEL_SIZE: usize = 1;
        let (send_ready, mut receive_ready): (mpsc::Sender<bool>, mpsc::Receiver<bool>) =
            mpsc::channel::<bool>(PROCESS_CHANNEL_SIZE);

        let (send_buffer, mut receive_buffer): (
            mpsc::Sender<Vec<WriteMessage>>,
            mpsc::Receiver<Vec<WriteMessage>>,
        ) = mpsc::channel::<Vec<WriteMessage>>(PROCESS_CHANNEL_SIZE);

        tokio::spawn(async move {
            let mut query_buffer: Vec<WriteMessage> = vec![];
            let mut query_buffer_length = 0;
            let mut inflight: usize = 0;

            loop {
                tokio::select! {
                    write_query = receive_write.recv() => {
                        match write_query {
                            Some(query) => {
                                query_buffer_length += 1;
                                query_buffer.push(query);
                            },
                            None => break,
                        }
                    },
                    ready = receive_ready.recv() => {
                        if ready.is_none() {
                            break;
                        }
                        inflight = inflight.saturating_sub(1);
                    }
                };

                if query_buffer_length >= buffer_size {
                    //if send_buffer is full, wait for the insertion thread
                    if inflight >= PROCESS_CHANNEL_SIZE {
                        let ready = receive_ready.recv().await;
                        if ready.is_none() {
                            break;
                        }
                        inflight = inflight.saturating_sub(1);
                    }
                    inflight += 1;
                    let _s = send_buffer.send(query_buffer).await;

                    query_buffer_length = 0;
                    query_buffer = vec![];
                } else if !query_buffer.is_empty() && inflight == 0 {
                    //send a non full querry buffer because no buffer is curently being processed,
                    inflight += 1;
                    let _s = send_buffer.send(query_buffer).await;

                    query_buffer_length = 0;
                    query_buffer = vec![];
                }
            }
        });

        thread::spawn(move || {
            while let Some(mut buffer) = receive_buffer.blocking_recv() {
                let result = Self::process_batch_write(&mut buffer, &conn);
                match result {
                    Ok(_) => {
                        for msg in buffer {
                            match msg {
                                WriteMessage::Deletion(q, r) => {
                                    let _ = r.send(Ok(q));
                                }

                                WriteMessage::Mutation(q, r) => {
                                    let _ = r.send(Ok(q));
                                }

                                WriteMessage::MutationStream(q, r) => {
                                    let _ = r.blocking_send(Ok(q));
                                }

                                WriteMessage::RoomMutation(q, r) => {
                                    let _ = r.blocking_send(
                                        AuthorisationMessage::RoomMutationWrite(Ok(()), q),
                                    );
                                }
                                WriteMessage::RoomMutationStream(q, r) => {
                                    let _ = r.blocking_send(
                                        AuthorisationMessage::RoomMutationStreamWrite(Ok(()), q),
                                    );
                                }

                                WriteMessage::RoomNode(q, r) => {
                                    let _ = r.blocking_send(AuthorisationMessage::RoomNodeWrite(
                                        Ok(()),
                                        q,
                                    ));
                                }

                                WriteMessage::Write(q, r) => {
                                    let _ = r.send(Ok(q));
                                }

                                WriteMessage::ComputeDailyLog(q, r) => {
                                    let _ = r.blocking_send(DbMessage::DailyLogComputed(Ok(q)));
                                }

                                WriteMessage::Nodes(_, invalid_nodes, r) => {
                                    let _ = r.send(Ok(invalid_nodes));
                                }

                                WriteMessage::Edges(_, invalid_nodes, r) => {
                                    let _ = r.send(Ok(invalid_nodes));
                                }

                                WriteMessage::DeleteEdges(_, r) => {
                                    let _ = r.send(Ok(()));
                                }
                                WriteMessage::DeleteNodes(_, r) => {
                                    let _ = r.send(Ok(()));
                                }
                            }
                        }
                    }
                    Err(e) => {
                        for msg in buffer {
                            match msg {
                                WriteMessage::Deletion(_, r) => {
                                    let _ = r.send(Err(Error::DatabaseWrite(e.to_string())));
                                }
                                WriteMessage::Mutation(_, r) => {
                                    let _ = r.send(Err(Error::DatabaseWrite(e.to_string())));
                                }

                                WriteMessage::MutationStream(_, r) => {
                                    let _ =
                                        r.blocking_send(Err(Error::DatabaseWrite(e.to_string())));
                                }
                                WriteMessage::RoomMutation(q, r) => {
                                    let _ =
                                        r.blocking_send(AuthorisationMessage::RoomMutationWrite(
                                            Err(Error::DatabaseWrite(e.to_string())),
                                            q,
                                        ));
                                }
                                WriteMessage::RoomMutationStream(q, r) => {
                                    let _ = r.blocking_send(
                                        AuthorisationMessage::RoomMutationStreamWrite(
                                            Err(Error::DatabaseWrite(e.to_string())),
                                            q,
                                        ),
                                    );
                                }

                                WriteMessage::RoomNode(q, r) => {
                                    let _ = r.blocking_send(AuthorisationMessage::RoomNodeWrite(
                                        Err(Error::DatabaseWrite(e.to_string())),
                                        q,
                                    ));
                                }
                                WriteMessage::Write(_, r) => {
                                    let _ = r.send(Err(Error::DatabaseWrite(e.to_string())));
                                }
                                WriteMessage::ComputeDailyLog(_, r) => {
                                    let _ = r.blocking_send(DbMessage::DailyLogComputed(Err(
                                        Error::ComputeDailyLog(e.to_string()),
                                    )));
                                }
                                WriteMessage::Nodes(_, _, r) => {
                                    let _ = r.send(Err(Error::DatabaseWrite(e.to_string())));
                                }
                                WriteMessage::Edges(_, _, r) => {
                                    let _ = r.send(Err(Error::DatabaseWrite(e.to_string())));
                                }
                                WriteMessage::DeleteEdges(_, r) => {
                                    let _ = r.send(Err(Error::DatabaseWrite(e.to_string())));
                                }
                                WriteMessage::DeleteNodes(_, r) => {
                                    let _ = r.send(Err(Error::DatabaseWrite(e.to_string())));
                                }
                            }
                        }
                    }
                }
                let _s = send_ready.blocking_send(true);
            }
        });

        Ok(Self { sender: send_write })
    }

    fn process_batch_write(
        buffer: &mut Vec<WriteMessage>,
        conn: &Connection,
    ) -> std::result::Result<(), rusqlite::Error> {
        conn.execute("BEGIN TRANSACTION", [])?;
        let mut daily_log = DailyMutations::default();
        for query in buffer {
            match query {
                WriteMessage::Deletion(query, _) => {
                    if let Err(e) = query.delete(conn) {
                        conn.execute("ROLLBACK", [])?;
                        return Err(e);
                    }
                    query.update_daily_logs(&mut daily_log);
                }
                WriteMessage::Mutation(query, _) => {
                    if let Err(e) = query.write(conn) {
                        conn.execute("ROLLBACK", [])?;
                        return Err(e);
                    }
                    query.update_daily_logs(&mut daily_log);
                }

                WriteMessage::MutationStream(query, _) => {
                    if let Err(e) = query.write(conn) {
                        conn.execute("ROLLBACK", [])?;
                        return Err(e);
                    }
                    query.update_daily_logs(&mut daily_log);
                }

                WriteMessage::Nodes(node, _, _) => {
                    for nti in node {
                        if let Err(e) = nti.write(conn) {
                            conn.execute("ROLLBACK", [])?;
                            return Err(e);
                        }
                        nti.update_daily_logs(&mut daily_log);
                    }
                }

                WriteMessage::Edges(edges, _, _) => {
                    for edge in edges {
                        if let Err(e) = edge.write(conn) {
                            conn.execute("ROLLBACK", [])?;
                            return Err(e);
                        }
                    }
                }

                WriteMessage::RoomMutation(query, _) => {
                    if let Err(e) = query.write(conn) {
                        conn.execute("ROLLBACK", [])?;
                        return Err(e);
                    }
                    query.update_daily_logs(&mut daily_log);
                }

                WriteMessage::RoomMutationStream(query, _) => {
                    if let Err(e) = query.write(conn) {
                        conn.execute("ROLLBACK", [])?;
                        return Err(e);
                    }
                    query.update_daily_logs(&mut daily_log);
                }

                WriteMessage::RoomNode(room_node, _) => {
                    if let Err(e) = room_node.write(conn) {
                        conn.execute("ROLLBACK", [])?;
                        return Err(e);
                    }
                    //room add does not update_daily_log because room definitions are allways synchronized at the start of a p2p connection
                }
                WriteMessage::Write(stmt, _) => {
                    if let Err(e) = stmt.write(conn) {
                        conn.execute("ROLLBACK", [])?;
                        return Err(e);
                    }
                    //write is a generic query and is outside the daily_log feature
                }
                WriteMessage::ComputeDailyLog(daily_mutations, _) => {
                    if let Err(e) = daily_mutations.compute(conn) {
                        conn.execute("ROLLBACK", [])?;
                        return Err(e);
                    }
                }
                WriteMessage::DeleteEdges(edges, _) => {
                    if let Err(e) = EdgeDeletionEntry::delete_all(edges, &mut daily_log, conn) {
                        conn.execute("ROLLBACK", [])?;
                        return Err(e);
                    }
                }
                WriteMessage::DeleteNodes(nodes, _) => {
                    if let Err(e) = NodeDeletionEntry::delete_all(nodes, &mut daily_log, conn) {
                        conn.execute("ROLLBACK", [])?;
                        return Err(e);
                    }
                }
            }
        }
        //at the end of the batch, update the daily log with all room dates that needs to be recomputed
        daily_log.write(conn)?;
        conn.execute("COMMIT", [])?;
        Ok(())
    }

    ///
    /// send a write message a wait for the message to be processed
    ///
    pub async fn write(&self, stmt: WriteStmt) -> Result<WriteStmt> {
        let (reply, reciev) = oneshot::channel::<Result<WriteStmt>>();
        let _ = self.sender.send(WriteMessage::Write(stmt, reply)).await;
        reciev.await?
    }

    ///
    /// send a write message without waiting for the query to finish
    ///
    pub async fn send(&self, msg: WriteMessage) -> Result<()> {
        self.sender
            .send(msg)
            .await
            .map_err(|e| Error::ChannelSend(e.to_string()))?;
        Ok(())
    }

    ///
    /// send a write message without waiting for the query to finish
    ///
    pub fn send_blocking(&self, msg: WriteMessage) -> Result<()> {
        self.sender
            .blocking_send(msg)
            .map_err(|e| Error::ChannelSend(e.to_string()))
    }

    ///
    /// Optimize the sqlite database
    /// should be called from time to time, and after large insertions
    ///
    pub async fn optimize(&self) -> Result<WriteStmt> {
        self.write(Box::new(Optimize {})).await
    }
}

struct Optimize {}
impl Writeable for Optimize {
    fn write(&mut self, conn: &Connection) -> std::result::Result<(), rusqlite::Error> {
        conn.execute("PRAGMA OPTIMIZE", [])?;
        Ok(())
    }
}

///
/// Creates a Sqlite function to encode and decode base64 in sql queries
/// Used to convert the binary identifiers into a string.
/// Base64 is more efficient than hexadecimal
/// the variant used is URL safe
///
pub fn add_base64_function(db: &Connection) -> rusqlite::Result<()> {
    db.create_scalar_function(
        "base64_encode",
        1,
        FunctionFlags::SQLITE_UTF8 | FunctionFlags::SQLITE_DETERMINISTIC,
        move |ctx| {
            assert_eq!(ctx.len(), 1, "called with unexpected number of arguments");

            let blob = ctx.get_raw(0).as_blob_or_null()?;

            let result = blob.map(base64_encode);

            Ok(result)
        },
    )?;

    db.create_scalar_function(
        "base64_decode",
        1,
        FunctionFlags::SQLITE_UTF8 | FunctionFlags::SQLITE_DETERMINISTIC,
        move |ctx| {
            assert_eq!(ctx.len(), 1, "called with unexpected number of arguments");

            let str = ctx.get_raw(0).as_str_or_null()?;

            let result = match str {
                Some(data) => {
                    let val = base64_decode(data.as_bytes());
                    match val {
                        Ok(e) => Some(e),
                        Err(_) => None,
                    }
                }
                None => None,
            };

            Ok(result)
        },
    )?;

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::database::Error;
    use crate::security::hash;
    use std::result::Result;
    use std::{fs, path::Path, time::Instant};
    #[derive(Debug)]

    struct InsertPerson {
        name: String,
        surname: String,
    }
    impl Writeable for InsertPerson {
        fn write(&mut self, conn: &Connection) -> std::result::Result<(), rusqlite::Error> {
            let mut stmt =
                conn.prepare_cached("INSERT INTO person (name, surname) VALUES (?, ?)")?;

            stmt.execute((&self.name, &self.surname))?;
            Ok(())
        }
    }
    use std::str;

    const STRING_MAPPING: RowMappingFn<String> = |row| Ok(Box::new(row.get(0)?));
    const SELECT_ALL: &'static str = "
    SELECT 	
        json_object('name', name, 'surname', surname)
    FROM person";

    const DATA_PATH: &str = "test_data/database/sqlite_database";
    fn init_database_path(file: &str) -> Result<PathBuf, Error> {
        let mut path: PathBuf = DATA_PATH.into();
        fs::create_dir_all(&path)?;
        path.push(file);
        if Path::exists(&path) {
            fs::remove_file(&path)?;
        }
        Ok(path)
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn test_sqlite_version() {
        let path: PathBuf = init_database_path("test_sqlite_version.db").unwrap();
        let secret = hash(b"bytes");
        let conn = create_connection(&path, &secret, 1024, false).unwrap();
        let mut stmt = conn.prepare("SELECT sqlite_version();").unwrap();
        let mut rows = stmt.query([]).unwrap();
        let qs = rows.next().unwrap().expect("oupssie");

        let val: String = qs.get(0).unwrap();
        assert_eq!("3.39.4", val);
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn test_pragma() {
        let path: PathBuf = init_database_path("test_pragma.db").unwrap();
        let secret = hash(b"bytes");
        let conn = create_connection(&path, &secret, 1024, false).unwrap();
        let mut stmt = conn.prepare("PRAGMA mmap_size").unwrap();
        let mut rows = stmt.query([]).unwrap();
        let qs = rows.next().unwrap().expect("oupssie");

        let val: u32 = qs.get(0).unwrap();
        assert_eq!(0, val);
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn async_queries() {
        let path: PathBuf = init_database_path("async_queries.db").unwrap();
        let secret = hash(b"bytes");
        let conn = create_connection(&path, &secret, 1024, false).unwrap();
        conn.execute(
            "CREATE TABLE person (
                id              INTEGER PRIMARY KEY,
                name            TEXT NOT NULL,
                surname         TEXT
            ) STRICT",
            [],
        )
        .unwrap();

        let writer = BufferedDatabaseWriter::start(10, &path, &secret, 1024, false).unwrap();

        writer
            .write(Box::new(InsertPerson {
                name: "Steven".to_string(),
                surname: "Bob".to_string(),
            }))
            .await
            .unwrap();

        let reader = DatabaseReader::start(&path, &secret, 8192, 2, false).unwrap();
        let res = reader
            .query_async(SELECT_ALL.to_string(), Vec::new(), STRING_MAPPING)
            .await
            .unwrap();
        assert_eq!(r#"{"name":"Steven","surname":"Bob"}"#, res[0]);
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn batch_writes_buffersize_1() {
        let path: PathBuf = init_database_path("batch_writes_buffersize_1.db").unwrap();
        let secret = hash(b"bytes");
        let conn = create_connection(&path, &secret, 1024, false).unwrap();

        conn.execute(
            "CREATE TABLE person (
                id              INTEGER PRIMARY KEY,
                name            TEXT NOT NULL,
                surname         TEXT
            ) STRICT",
            [],
        )
        .unwrap();

        let writer = BufferedDatabaseWriter::start(1, &path, &secret, 1024, false).unwrap();

        let loop_number = 10;
        let _start = Instant::now();
        let mut reply_list = vec![];

        for _i in 0..loop_number {
            let (reply, reciev) = oneshot::channel::<Result<WriteStmt, Error>>();

            let query = WriteMessage::Write(
                Box::new(InsertPerson {
                    name: "Steven".to_string(),
                    surname: "Bob".to_string(),
                }),
                reply,
            );
            writer.send(query).await.unwrap();
            reply_list.push(reciev);
        }
        let _ = reply_list.pop().unwrap().await.unwrap().unwrap();

        let reader = DatabaseReader::start(&path, &secret, 8192, 2, false).unwrap();
        let res = reader
            .query_async(SELECT_ALL.to_string(), Vec::new(), STRING_MAPPING)
            .await
            .unwrap();

        assert_eq!(loop_number, res.len());
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn batch_writes_buffersize_10() {
        let path: PathBuf = init_database_path("batch_writes_buffersize_10.db").unwrap();
        let secret = hash(b"bytes");
        let conn = create_connection(&path, &secret, 1024, false).unwrap();

        conn.execute(
            "CREATE TABLE person (
                id              INTEGER PRIMARY KEY,
                name            TEXT NOT NULL,
                surname         TEXT
            ) STRICT",
            [],
        )
        .unwrap();

        let writer = BufferedDatabaseWriter::start(10, &path, &secret, 1024, false).unwrap();

        let loop_number = 32;
        let _start = Instant::now();
        let mut reply_list = vec![];

        for _i in 0..loop_number {
            let (reply, reciev) = oneshot::channel::<Result<WriteStmt, Error>>();

            let query = WriteMessage::Write(
                Box::new(InsertPerson {
                    name: "Steven".to_string(),
                    surname: "Bob".to_string(),
                }),
                reply,
            );
            writer.send(query).await.unwrap();
            reply_list.push(reciev);
        }
        reply_list.pop().unwrap().await.unwrap().unwrap();

        let reader = DatabaseReader::start(&path, &secret, 8192, 2, false).unwrap();
        let res = reader
            .query_async(SELECT_ALL.to_string(), Vec::new(), STRING_MAPPING)
            .await
            .unwrap();
        assert_eq!(loop_number, res.len());
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn read_only_test() {
        let path: PathBuf = init_database_path("read_only_test.db").unwrap();
        let secret = hash(b"bytes");
        let conn = create_connection(&path, &secret, 1024, false).unwrap();
        conn.execute(
            "CREATE TABLE person (
                id              INTEGER PRIMARY KEY,
                name            TEXT NOT NULL,
                surname         TEXT
            ) STRICT",
            [],
        )
        .unwrap();

        let writer = BufferedDatabaseWriter::start(10, &path, &secret, 1024, false).unwrap();
        writer
            .write(Box::new(InsertPerson {
                name: "Steven".to_string(),
                surname: "Bob".to_string(),
            }))
            .await
            .unwrap();

        let reader = DatabaseReader::start(&path, &secret, 8192, 2, false).unwrap();

        let insert_query = "INSERT INTO person (name, surname) VALUES ('bad', 'one')".to_string();
        let _res = reader
            .query_async(insert_query, Vec::new(), STRING_MAPPING)
            .await
            .expect_err("attempt to write a readonly database");
    }
}
