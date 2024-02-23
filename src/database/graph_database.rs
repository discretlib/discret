use rusqlite::{functions::FunctionFlags, Connection, OptionalExtension, Row};

use std::{path::PathBuf, thread, time::SystemTime, usize};
use tokio::sync::{mpsc, oneshot};

use crate::{base64_decode, base64_encode};

use super::{edge::Edge, mutation_query::MutationQuery, node::Node, Error, Result};
use rand::{rngs::OsRng, RngCore};

pub type MappingFn<T> = fn(&Row) -> std::result::Result<Box<T>, rusqlite::Error>;

pub trait FromRow {
    fn from_row() -> MappingFn<Self>;
}

pub trait Readable {
    fn read(&self, conn: &Connection) -> Result<QueryResult>;
}

pub struct ReadQuery {
    pub stmt: Box<dyn Readable + Send>,
    pub reply: oneshot::Sender<Result<QueryResult>>,
}

/// Trait use to write content in the database
///   returns only rusqlite::Error as it is forbidden to do anything that could fails during the write process
///   writes happens in batched transaction, and we want to avoid any errors that would results in the rollback of a potentially large number of inserts
pub trait Writeable {
    fn write(&self, conn: &Connection) -> std::result::Result<QueryResult, rusqlite::Error>;
}

pub struct WriteQuery {
    pub stmt: Box<dyn Writeable + Send>,
    pub reply: oneshot::Sender<Result<QueryResult>>,
}

#[derive(Debug)]
pub enum QueryResult {
    MutationQuery(MutationQuery),
    String(String),
    Strings(Vec<String>),
    None,
}
impl QueryResult {
    pub fn as_strings(&self) -> Option<&Vec<String>> {
        if let Self::Strings(e) = self {
            Some(e)
        } else {
            None
        }
    }

    pub fn as_str(&self) -> Option<&str> {
        if let Self::String(e) = self {
            Some(e)
        } else {
            None
        }
    }

    pub fn as_mutation_query(&mut self) -> Option<&mut MutationQuery> {
        if let Self::MutationQuery(e) = self {
            Some(e)
        } else {
            None
        }
    }
}

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
    cache_size_in_kb: u32,
    enable_memory_security: bool,
) -> Result<Connection> {
    let mut flags = rusqlite::OpenFlags::empty();
    flags.insert(rusqlite::OpenFlags::SQLITE_OPEN_READ_WRITE);
    flags.insert(rusqlite::OpenFlags::SQLITE_OPEN_CREATE);

    //Don't follow unix symbolic link
    flags.insert(rusqlite::OpenFlags::SQLITE_OPEN_NOFOLLOW);

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
    //  - Disabled because it hides the real RAM usage on linux, which is anoying for destop applications
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

    //Disable obscure legacy compatibility as recommended by doc.
    set_pragma("trusted_schema", "0", &conn)?;

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
        Node::create_table(conn)?;
        Edge::create_table(conn)?;
        // DailySynchLog::create_table(conn)?;
        conn.execute("COMMIT", [])?;
    }
    Ok(())
}

///
/// Database main entry point
///
///
pub struct GraphDatabase {
    reader: DatabaseReader,
    writer: BufferedDatabaseWriter,
}
impl GraphDatabase {
    pub fn new(
        path: &PathBuf,
        secret: &[u8; 32],
        cache_size_in_kb: u32,
        enable_memory_security: bool,
        parallelism: usize,
        write_buffer_size: usize,
    ) -> Result<Self> {
        let reader = DatabaseReader::new(
            path,
            secret,
            cache_size_in_kb,
            enable_memory_security,
            parallelism,
        )?;

        let writer = BufferedDatabaseWriter::new(
            write_buffer_size,
            path,
            secret,
            cache_size_in_kb,
            enable_memory_security,
        )?;
        Ok(GraphDatabase { reader, writer })
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
    sender: flume::Sender<ReadQuery>,
}
impl DatabaseReader {
    pub fn new(
        path: &PathBuf,
        secret: &[u8; 32],
        cache_size_in_kb: u32,
        enable_memory_security: bool,
        parallelism: usize,
    ) -> Result<Self> {
        let (sender, receiver) = flume::bounded::<ReadQuery>(100);
        for _i in 0..parallelism {
            let conn =
                create_connection(path, secret, cache_size_in_kb, enable_memory_security).unwrap();
            set_pragma("query_only", "1", &conn)?;

            let local_receiver = receiver.clone();
            thread::spawn(move || {
                while let Ok(q) = local_receiver.recv() {
                    if let Err(_) = q.reply.send(q.stmt.read(&conn)) {
                        println!("Reply channel is allready closed");
                    }
                }
            });
        }
        Ok(Self { sender })
    }

    pub async fn query_async(&self, stmt: Box<dyn Readable + Send>) -> Result<QueryResult> {
        let (reply, receive_response) = oneshot::channel::<Result<QueryResult>>();
        let query = ReadQuery { stmt, reply };
        self.sender
            .send_async(query)
            .await
            .map_err(|e| Error::TokioSendError(e.to_string()))?;

        receive_response.await.map_err(Error::from)?
    }

    pub fn query_blocking(&self, stmt: Box<dyn Readable + Send>) -> Result<QueryResult> {
        let (reply, receive_response) = oneshot::channel::<Result<QueryResult>>();
        let query = ReadQuery { stmt, reply };
        self.sender
            .send(query)
            .map_err(|e| Error::TokioSendError(e.to_string()))?;

        receive_response.blocking_recv().map_err(Error::from)?
    }
}

struct Optimize {}
impl Writeable for Optimize {
    fn write(&self, conn: &Connection) -> std::result::Result<QueryResult, rusqlite::Error> {
        conn.execute("PRAGMA OPTIMIZE", [])?;
        Ok(QueryResult::None)
    }
}

pub fn set_pragma(pragma: &str, value: &str, conn: &rusqlite::Connection) -> Result<()> {
    let mut stmt = conn.prepare(&format!("PRAGMA {}={}", pragma, value))?;
    let _rows = stmt.query([])?;
    Ok(())
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
    sender: mpsc::Sender<WriteQuery>,
}
impl BufferedDatabaseWriter {
    pub fn new(
        buffer_size: usize,
        path: &PathBuf,
        secret: &[u8; 32],
        cache_size_in_kb: u32,
        enable_memory_security: bool,
    ) -> Result<Self> {
        let conn = create_connection(path, secret, cache_size_in_kb, enable_memory_security)?;
        //only a few query can be buffered here
        //the real buffering using the buffer_size happens later
        const WRITE_QUERY_BUFFER: usize = 4;
        let (send_write, mut receive_write): (
            mpsc::Sender<WriteQuery>,
            mpsc::Receiver<WriteQuery>,
        ) = mpsc::channel::<WriteQuery>(WRITE_QUERY_BUFFER);

        //allows only one infligh buffer: one that is currentlu being processed
        const PROCESS_CHANNEL_SIZE: usize = 1;
        let (send_ready, mut receive_ready): (mpsc::Sender<bool>, mpsc::Receiver<bool>) =
            mpsc::channel::<bool>(PROCESS_CHANNEL_SIZE);

        let (send_buffer, mut receive_buffer): (
            mpsc::Sender<Vec<WriteQuery>>,
            mpsc::Receiver<Vec<WriteQuery>>,
        ) = mpsc::channel::<Vec<WriteQuery>>(PROCESS_CHANNEL_SIZE);

        tokio::spawn(async move {
            let mut query_buffer: Vec<WriteQuery> = vec![];
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
                let result = Self::process_batch_write(&buffer, &conn);
                match result {
                    Ok(mut e) => {
                        for _i in 0..buffer.len() {
                            let result = e.pop().unwrap();
                            let query = buffer.pop().unwrap();

                            if let Err(_) = query.reply.send(Ok(result)) {
                                println!("Reply channel closed prematurely");
                            }
                        }
                    }
                    Err(e) => {
                        for query in buffer {
                            let r = query
                                .reply
                                .send(Err(Error::DatabaseWriteError(e.to_string())));
                            if let Err(_) = r {
                                println!("Reply channel closed prematurely");
                            }
                        }
                    }
                }
                let _s = send_ready.blocking_send(true);
            }
        });

        Ok(Self { sender: send_write })
    }

    fn getbuffer(receive_buffer: &mut mpsc::Receiver<Vec<WriteQuery>>) -> Option<Vec<WriteQuery>> {
        receive_buffer.blocking_recv()
    }

    pub async fn write_async(&self, stmt: Box<dyn Writeable + Send>) -> Result<QueryResult> {
        let (reply, reciev) = oneshot::channel::<Result<QueryResult>>();
        let _ = self.sender.send(WriteQuery { stmt, reply }).await;
        reciev.await.map_err(Error::from)?
    }

    pub fn write_blocking(&self, stmt: Box<dyn Writeable + Send>) -> Result<QueryResult> {
        let (reply, reciev) = oneshot::channel::<Result<QueryResult>>();
        let _ = self.sender.blocking_send(WriteQuery { stmt, reply });
        reciev.blocking_recv().map_err(Error::from)?
    }

    pub async fn send_async(&self, msg: WriteQuery) -> Result<()> {
        self.sender
            .send(msg)
            .await
            .map_err(|e| Error::TokioSendError(e.to_string()))
    }

    pub fn send_blocking(&self, msg: WriteQuery) -> Result<()> {
        self.sender
            .blocking_send(msg)
            .map_err(|e| Error::TokioSendError(e.to_string()))
    }

    pub async fn optimize_async(&self) -> Result<QueryResult> {
        self.write_async(Box::new(Optimize {})).await
    }

    pub fn optimize_blocking(&self) -> Result<QueryResult> {
        self.write_blocking(Box::new(Optimize {}))
    }

    fn process_batch_write(
        buffer: &Vec<WriteQuery>,
        conn: &Connection,
    ) -> Result<Vec<QueryResult>> {
        conn.execute("BEGIN TRANSACTION", [])?;
        let mut result = Vec::new();
        for query in buffer {
            match query.stmt.write(conn) {
                Err(e) => {
                    conn.execute("ROLLBACK", [])?;
                    return Err(Error::DatabaseError(e));
                }
                Ok(e) => {
                    result.push(e);
                }
            }
        }
        conn.execute("COMMIT", [])?;
        Ok(result)
    }
}

///
/// Maximum allowed size for a row
/// set to a relatively low value to avoid large rows that would eats lots of ram and bandwith during synchronisation
///
pub const MAX_ROW_LENTGH: usize = 1024 * 1024; //1MB

//min numbers of char in an id //policy
pub const DB_ID_MIN_SIZE: usize = 16;

/// set to 33 to be able to store a public key in the id
pub const DB_ID_MAX_SIZE: usize = 33;

const DB_ID_SIZE: usize = 16;

///
/// id with time on first to improve index locality
///
pub fn new_id(time: i64) -> Vec<u8> {
    const TIME_BYTES: usize = 4;

    let time = &time.to_be_bytes()[TIME_BYTES..];

    let mut whole: [u8; DB_ID_SIZE] = [0; DB_ID_SIZE];
    let (one, two) = whole.split_at_mut(time.len());

    one.copy_from_slice(time);
    OsRng.fill_bytes(two);

    whole.to_vec()
}

///
/// control the validity of the id
///
pub fn is_valid_id_len(id: &Vec<u8>) -> bool {
    let v = id.len();
    (DB_ID_MIN_SIZE..=DB_ID_MAX_SIZE).contains(&v)
}

///
/// current time in milliseconds since unix epoch
///
pub fn now() -> i64 {
    SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_millis()
        .try_into()
        .unwrap()
}

///
/// Sqlite function encode or decode to base64
/// used to convert the binary identifiers into a String.
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
    use crate::cryptography::hash;
    use crate::database::Error;
    use std::result::Result;
    use std::{fs, path::Path, time::Instant};
    #[derive(Debug)]
    struct InsertPerson {
        name: String,
        surname: String,
    }
    impl Writeable for InsertPerson {
        fn write(&self, conn: &Connection) -> std::result::Result<QueryResult, rusqlite::Error> {
            let mut stmt =
                conn.prepare_cached("INSERT INTO person (name, surname) VALUES (?, ?)")?;

            stmt.execute((&self.name, &self.surname))?;
            Ok(QueryResult::None)
        }
    }
    use std::str;
    struct SelectAll {}
    impl Readable for SelectAll {
        fn read(&self, conn: &Connection) -> Result<QueryResult, Error> {
            let mut stmt = conn.prepare_cached(
                "
            SELECT 	
                json_object('name', name, 'surname', surname)
            FROM person",
            )?;

            let mut rows = stmt.query([])?;

            let mut result = Vec::new();

            while let Some(row) = rows.next()? {
                result.push(row.get(0)?);
            }
            Ok(QueryResult::Strings(result))
        }
    }

    const DATA_PATH: &str = "test/data/database/graph_service";
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

        let writer = BufferedDatabaseWriter::new(10, &path, &secret, 1024, false).unwrap();

        writer
            .write_async(Box::new(InsertPerson {
                name: "Steven".to_string(),
                surname: "Bob".to_string(),
            }))
            .await
            .unwrap();

        let reader = DatabaseReader::new(&path, &secret, 8192, false, 2).unwrap();
        let res = reader.query_async(Box::new(SelectAll {})).await.unwrap();
        assert_eq!(
            r#"{"name":"Steven","surname":"Bob"}"#,
            res.as_strings().unwrap()[0]
        );
        // println!("{}", res);
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn blocking_queries() {
        let path: PathBuf = init_database_path("blocking_queries.db").unwrap();
        let secret = hash(b"bytes");
        let writer_conn = create_connection(&path, &secret, 1024, false).unwrap();
        writer_conn
            .execute(
                "CREATE TABLE person (
                id              INTEGER PRIMARY KEY,
                name            TEXT NOT NULL,
                surname         TEXT
            ) STRICT",
                [],
            )
            .unwrap();

        let writer = BufferedDatabaseWriter::new(10, &path, &secret, 1024, false).unwrap();

        let _ = thread::spawn(move || {
            let _ = writer.write_blocking(Box::new(InsertPerson {
                name: "Steven".to_string(),
                surname: "Bob".to_string(),
            }));

            let reader = DatabaseReader::new(&path, &secret, 8192, false, 1).unwrap();
            let res = reader.query_blocking(Box::new(SelectAll {})).unwrap();
            assert_eq!(
                r#"{"name":"Steven","surname":"Bob"}"#,
                res.as_strings().unwrap()[0]
            );
        })
        .join();
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

        let writer = BufferedDatabaseWriter::new(1, &path, &secret, 1024, false).unwrap();

        let loop_number = 10;
        let _start = Instant::now();
        let mut reply_list = vec![];

        for _i in 0..loop_number {
            let (reply, reciev) = oneshot::channel::<Result<QueryResult, Error>>();

            let query = WriteQuery {
                stmt: Box::new(InsertPerson {
                    name: "Steven".to_string(),
                    surname: "Bob".to_string(),
                }),
                reply: reply,
            };
            writer.send_async(query).await.unwrap();
            reply_list.push(reciev);
        }
        reply_list.pop().unwrap().await.unwrap().unwrap();

        let reader = DatabaseReader::new(&path, &secret, 8192, false, 2).unwrap();
        let res = reader.query_async(Box::new(SelectAll {})).await.unwrap();

        assert_eq!(loop_number, res.as_strings().unwrap().len());
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

        let writer = BufferedDatabaseWriter::new(10, &path, &secret, 1024, false).unwrap();

        let loop_number = 32;
        let _start = Instant::now();
        let mut reply_list = vec![];

        for _i in 0..loop_number {
            let (reply, reciev) = oneshot::channel::<Result<QueryResult, Error>>();

            let query = WriteQuery {
                stmt: Box::new(InsertPerson {
                    name: "Steven".to_string(),
                    surname: "Bob".to_string(),
                }),
                reply: reply,
            };
            writer.send_async(query).await.unwrap();
            reply_list.push(reciev);
        }
        reply_list.pop().unwrap().await.unwrap().unwrap();

        let reader = DatabaseReader::new(&path, &secret, 8192, false, 2).unwrap();
        let res = reader.query_async(Box::new(SelectAll {})).await.unwrap();
        // println!("{}", res.len());
        assert_eq!(loop_number, res.as_strings().unwrap().len());
    }

    //batch write is much faster than inserting row one by one
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

        let writer = BufferedDatabaseWriter::new(10, &path, &secret, 1024, false).unwrap();
        writer
            .write_async(Box::new(InsertPerson {
                name: "Steven".to_string(),
                surname: "Bob".to_string(),
            }))
            .await
            .unwrap();

        let reader = DatabaseReader::new(&path, &secret, 8192, false, 2).unwrap();

        struct BadPerson {
            name: String,
            surname: String,
        }
        impl Readable for BadPerson {
            fn read(&self, conn: &Connection) -> Result<QueryResult, Error> {
                let mut stmt =
                    conn.prepare_cached("INSERT INTO person (name, surname) VALUES (?, ?)")?;

                stmt.execute((&self.name, &self.surname))?;
                Ok(QueryResult::None)
            }
        }

        let _ = reader
            .query_async(Box::new(BadPerson {
                name: "Steven".to_string(),
                surname: "Bob".to_string(),
            }))
            .await
            .expect_err("attempt to write a readonly database");
    }
}
