use crate::cryptography::base64_encode;
use crate::error::Error;

use rusqlite::functions::{Aggregate, Context, FunctionFlags};
use rusqlite::{Connection, Row, ToSql};

use std::{path::PathBuf, thread};
use tokio::sync::{mpsc, oneshot};

use blake3::Hasher;
use zstd::bulk::{compress, decompress};

type ReaderFn = Box<dyn FnOnce(&mut Connection) + Send + 'static>;
type MappingFn<T> = fn(&Row) -> rusqlite::Result<Box<T>, rusqlite::Error>;
pub trait FromRow {
    fn from_row() -> MappingFn<Self>;
}

pub trait Writable {
    fn write(&self, conn: &Connection) -> Result<(), Error>;
}

pub struct WriteQuery {
    pub writeable: Vec<Box<dyn Writable + Send>>,
    pub reply: oneshot::Sender<Result<(), Error>>,
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
) -> Result<Connection, rusqlite::Error> {
    //let conn = rusqlite::Connection::open(path)?;
    let mut flags = rusqlite::OpenFlags::empty();
    flags.insert(rusqlite::OpenFlags::SQLITE_OPEN_READ_WRITE);
    flags.insert(rusqlite::OpenFlags::SQLITE_OPEN_CREATE);

    //Don't follow unix symbolic link
    flags.insert(rusqlite::OpenFlags::SQLITE_OPEN_NOFOLLOW);

    //Disable mutex so a single connection can only be used by one thread.
    //
    //Perfect for rust concurency model
    flags.insert(rusqlite::OpenFlags::SQLITE_OPEN_NO_MUTEX);
    let conn = rusqlite::Connection::open_with_flags(path, flags)?;

    //Encrypt the database.
    //
    //The "x'key'"" format means that no additional key derivation is done by sqlcipher
    let sqlcipher_key = format!("\"x'{}'\"", hex::encode(secret));
    set_pragma("key", &sqlcipher_key, &conn)?;

    let page_size = "8192";
    //Increase page size.
    //
    //8 Kb, double of the default value
    //Could be usefull as Json takes more space than standard row
    set_pragma("cipher_page_size", page_size, &conn)?;
    set_pragma("page_size", page_size, &conn)?;

    //Enable/disable memory security.
    //
    if enable_memory_security {
        set_pragma("cipher_memory_security", "1", &conn)?;
    } else {
        set_pragma("cipher_memory_security", "0", &conn)?;
    }

    //Temp files are stored in memory.
    //
    //required for sqlciper security
    set_pragma("temp_store", "2", &conn)?;

    //Enable mmap for increased performance,
    //
    //Value is the one recommended in the doc: 256 Mb
    //--is it ok on phones?
    //
    set_pragma("mmap_size", "268435456", &conn)?;

    //8mb cache size.
    set_pragma("cache_size", &format!("-{}", cache_size_in_kb), &conn)?;

    //WAL journaling system allows for concurent READ/WRITE.
    set_pragma("journal_mode", "WAL", &conn)?;

    //WAL checkpoin every 1000 dirty pages.
    set_pragma("wal_autocheckpoint", "1000", &conn)?;

    //Best safe setting for WAL journaling.
    set_pragma("synchronous", "1", &conn)?;

    //Automatically reclaim storage after deletion
    //
    //enabled to keep database small
    set_pragma("auto_vacuum", "1", &conn)?;

    //Disable obscure legacy compatibility as recommended by doc.
    set_pragma("trusted_schema", "0", &conn)?;

    //enable foreign keys
    set_pragma("foreign_keys", "1", &conn)?;

    /*     //enable recursive trigger, delete trigger is triggered when INSERT OR REPLACE is used
    //mandatory when using triggers that update full text search virtual tables
    set_pragma("recursive_triggers", "1", &conn)?; */

    add_hash_function(&conn)?;
    add_compression_function(&conn)?;
    add_json_data_function(&conn)?;
    Ok(conn)
}

// Main entry point to perform SELECT queries
//
// Clone it to safely perform queries across different thread
//
// Sqlite in WAL mode support READ/WRITE concurency, wich makes the separation between read and write thread efficient
// it is possible to open several reader but beware that each reader can consume up to 8Mb of memory
//
#[derive(Clone)]
pub struct DatabaseReader {
    sender: mpsc::Sender<ReaderFn>,
}
impl DatabaseReader {
    pub fn start(mut conn: Connection) -> Self {
        // let s: Arc<Mutex<i32>> = Arc::new(Mutex::new(0));
        //enforce read only behavior for this connection
        //any attempt to CREATE, DELETE, DROP, INSERT, or UPDATE will result in an SQLITE_READONLY error
        let _ = set_pragma("query_only", "1", &conn);
        let (send_query, mut receiv_query) = mpsc::channel::<ReaderFn>(10);

        thread::spawn(move || {
            while let Some(f) = receiv_query.blocking_recv() {
                f(&mut conn);
            }
        });

        Self { sender: send_query }
    }

    pub async fn query_async<T: Send + Sized + 'static>(
        &self,
        query: String,
        params: Vec<Box<dyn ToSql + Sync + Send>>,
        mapping: MappingFn<T>,
    ) -> Result<Vec<T>, Error> {
        let (send_response, receive_response) = oneshot::channel::<Result<Vec<T>, Error>>();

        let _ = &self
            .sender
            .send(Box::new(move |conn| {
                let result = Self::select(&query, &params, &mapping, conn).map_err(Error::from);

                let _ = send_response.send(result);
            }))
            .await;

        receive_response
            .await
            .map_err(|e| Error::Unknown(e.to_string()))?
    }

    pub fn query_blocking<T: FromRow + Send + Sized + 'static>(
        &self,
        query: String,
        params: Vec<Box<dyn ToSql + Sync + Send>>,
        mapping: MappingFn<T>,
    ) -> Result<Vec<T>, Error> {
        let (send_response, receive_response) = oneshot::channel::<Result<Vec<T>, Error>>();

        let _ = &self.sender.blocking_send(Box::new(move |conn| {
            let result = Self::select(&query, &params, &mapping, conn).map_err(Error::from);
            let _ = send_response.send(result);
        }));

        receive_response
            .blocking_recv()
            .map_err(|e| Error::Unknown(e.to_string()))?
    }

    fn select<T: Send + Sized + 'static>(
        query: &str,
        params: &Vec<Box<dyn ToSql + Sync + Send>>,
        mapping: &MappingFn<T>,
        conn: &Connection,
    ) -> Result<Vec<T>, rusqlite::Error> {
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

// Main entry point to insert data in the database
//
// Clone it to safely perform queries across different thread
//
// Write queries are buffered while the database thread is working.
// When the database thread is ready, the buffer is sent and is processed in one single transaction
// This greatly increase insertion and update rate, compared to autocommit.
//      To get an idea of the perforance différence, a very simple benchmak on a laptop with 10000 insertions:
//      Buffer size: 1      Insert/seconds: 55  <- this is equivalent to autocommit
//      Buffer size: 10     Insert/seconds: 500
//      Buffer size: 100    Insert/seconds: 3000
//      Buffer size: 1000   Insert/seconds: 32000
//
// If one a buffered query fails, the transaction will be rolled back and every other queries in the buffer will fail too.
// This should not be an issue as insert query are not expected to fail.
// The only reasons to fail an insertion are a bugs or a system failure (like no more space available on disk),
// And in both case it is ok to fail the last insertions.
//
// Only one writer should be used per database
//
#[derive(Clone)]
pub struct BufferedDatabaseWriter {
    sender: mpsc::Sender<WriteQuery>,
}
impl BufferedDatabaseWriter {
    pub async fn start(buffer_size: usize, conn: Connection) -> Self {
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
                                query_buffer_length += &query.writeable.len();
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
            while let Some(buffer) = receive_buffer.blocking_recv() {
                let result = Self::process_batch_write(&buffer, &conn);
                match result {
                    Ok(_) => {
                        for write in buffer {
                            let _r = write.reply.send(Ok(()));
                        }
                    }
                    Err(e) => {
                        for write in buffer {
                            let _r = write
                                .reply
                                .send(Err(Error::DatabaseWriteError(e.to_string())));
                        }
                    }
                }
                let _s = send_ready.blocking_send(true);
            }
        });

        Self { sender: send_write }
    }

    fn getbuffer(receive_buffer: &mut mpsc::Receiver<Vec<WriteQuery>>) -> Option<Vec<WriteQuery>> {
        receive_buffer.blocking_recv()
    }

    pub async fn send_async(&self, msg: WriteQuery) -> Result<(), Error> {
        self.sender
            .send(msg)
            .await
            .map_err(|e| Error::Unknown(e.to_string()))
    }

    pub fn send_blocking(&self, msg: WriteQuery) -> Result<(), Error> {
        self.sender
            .blocking_send(msg)
            .map_err(|e| Error::Unknown(e.to_string()))
    }

    pub async fn write_async(
        &self,
        insert: Box<dyn Writable + Send>,
    ) -> Result<Result<(), Error>, Error> {
        let (reply, reciev) = oneshot::channel::<Result<(), crate::error::Error>>();
        let _ = self
            .sender
            .send(WriteQuery {
                writeable: vec![insert],
                reply,
            })
            .await;
        reciev.await.map_err(|e| Error::Unknown(e.to_string()))
    }

    pub fn write_blocking(
        &self,
        insert: Box<dyn Writable + Send>,
    ) -> Result<Result<(), Error>, Error> {
        let (reply, reciev) = oneshot::channel::<Result<(), crate::error::Error>>();
        let _ = self.sender.blocking_send(WriteQuery {
            writeable: vec![insert],
            reply,
        });
        reciev
            .blocking_recv()
            .map_err(|e| Error::Unknown(e.to_string()))
    }

    fn process_batch_write(buffer: &Vec<WriteQuery>, conn: &Connection) -> Result<(), Error> {
        conn.execute("BEGIN TRANSACTION", [])?;
        for write in buffer {
            Self::process_write(write, conn)?;
        }
        conn.execute("COMMIT", [])?;
        Ok(())
    }

    fn process_write(query: &WriteQuery, conn: &Connection) -> Result<(), Error> {
        for q in &query.writeable {
            q.write(conn)?;
        }
        Ok(())
    }
}

pub fn set_pragma(
    pragma: &str,
    value: &str,
    conn: &rusqlite::Connection,
) -> Result<(), rusqlite::Error> {
    let mut stmt = conn.prepare(&format!("PRAGMA {}={}", pragma, value))?;
    let _rows = stmt.query([])?;
    Ok(())
}

pub fn params_from_json(params: Vec<serde_json::Value>) -> Vec<Box<dyn ToSql>> {
    let mut temp_param: Vec<Box<dyn ToSql>> = vec![];

    for par in params {
        if par.is_string() {
            //removes the " " delimiters from the json string. ex: "value" becomes: value
            if let Some(e) = par.as_str() {
                temp_param.push(Box::new(e.to_string()));
            }
        } else if par.is_i64() {
            if let Some(e) = par.as_i64() {
                temp_param.push(Box::new(e));
            }
        } else if par.is_f64() {
            if let Some(e) = par.as_f64() {
                temp_param.push(Box::new(e));
            }
        } else {
            temp_param.push(Box::new(par.to_string()));
        }
    }
    temp_param
}

//errors for the user defined function added to sqlite
#[derive(thiserror::Error, Debug)]
pub enum FunctionError {
    #[error("Invalid data type only TEXT and BLOB can be compressed")]
    InvalidCompressType,
    #[error("Invalid data type only BLOB can be decompressed")]
    InvalidDeCompressType,
    #[error("Invalid data type only TEXT can be used for json_data")]
    InvalidJSONType,
    #[error("{0}")]
    CompressedSizeError(String),
}

struct Hash;

impl Aggregate<Hasher, Option<String>> for Hash {
    fn init(&self, _: &mut Context<'_>) -> rusqlite::Result<Hasher> {
        Ok(blake3::Hasher::new())
    }

    fn step(&self, ctx: &mut Context<'_>, hasher: &mut Hasher) -> rusqlite::Result<()> {
        let val = ctx.get::<String>(0)?;
        hasher.update(val.as_bytes());
        Ok(())
    }

    fn finalize(
        &self,
        _: &mut Context<'_>,
        hasher: Option<Hasher>,
    ) -> rusqlite::Result<Option<String>> {
        match hasher {
            Some(hash) => Ok(Some(base64_encode(hash.finalize().as_bytes()))),
            None => Ok(None),
        }
    }
}

//user defined function for blake3 hashing directly in sqlite queries
pub fn add_hash_function(db: &Connection) -> rusqlite::Result<()> {
    db.create_aggregate_function(
        "hash",
        1,
        FunctionFlags::SQLITE_UTF8 | FunctionFlags::SQLITE_DETERMINISTIC,
        Hash,
    )?;

    Ok(())
}

fn extract_json(val: serde_json::Value, buff: &mut String) -> rusqlite::Result<()> {
    match val {
        serde_json::Value::String(v) => {
            buff.push_str(&v);
            buff.push('\n');
            Ok(())
        }
        serde_json::Value::Array(arr) => {
            for v in arr {
                extract_json(v, buff)?;
            }
            Ok(())
        }
        serde_json::Value::Object(map) => {
            for v in map {
                extract_json(v.1, buff)?;
            }
            Ok(())
        }
        _ => Ok(()),
    }
}

//extract JSON textual data
pub fn add_json_data_function(db: &Connection) -> rusqlite::Result<()> {
    db.create_scalar_function(
        "json_data",
        1,
        FunctionFlags::SQLITE_UTF8 | FunctionFlags::SQLITE_DETERMINISTIC,
        move |ctx| {
            assert_eq!(ctx.len(), 1, "called with unexpected number of arguments");

            let data = ctx.get_raw(0).as_str_or_null()?;

            let mut extracted = String::new();
            let result = match data {
                Some(json) => {
                    let v: serde_json::Value = serde_json::from_str(json)
                        .map_err(|e| rusqlite::Error::UserFunctionError(e.into()))?;
                    extract_json(v, &mut extracted)?;
                    Some(extracted)
                }
                None => None,
            };

            Ok(result)
        },
    )?;

    Ok(())
}

//Compression functions using zstd
// compress: compress TEXT or BLOG type
// decompress: decompress BLOG into a BLOB
// decompress_text: decompress BLOB into TEXT
pub fn add_compression_function(db: &Connection) -> rusqlite::Result<()> {
    db.create_scalar_function(
        "compress",
        1,
        FunctionFlags::SQLITE_UTF8 | FunctionFlags::SQLITE_DETERMINISTIC,
        move |ctx| {
            assert_eq!(ctx.len(), 1, "called with unexpected number of arguments");
            const COMPRESSION_LEVEL: i32 = 3;

            let data = ctx.get_raw(0);
            let data_type = data.data_type();

            match data_type {
                rusqlite::types::Type::Text => {
                    let text = data
                        .as_str()
                        .map_err(|e| rusqlite::Error::UserFunctionError(e.into()))?;
                    let result = compress(text.as_bytes(), COMPRESSION_LEVEL)
                        .map_err(|e| rusqlite::Error::UserFunctionError(e.into()))?;
                    Ok(Some(result))
                }
                rusqlite::types::Type::Blob => {
                    let data = data
                        .as_blob()
                        .map_err(|e| rusqlite::Error::UserFunctionError(e.into()))?;
                    let result = compress(data, COMPRESSION_LEVEL)
                        .map_err(|e| rusqlite::Error::UserFunctionError(e.into()))?;

                    Ok(Some(result))
                }
                rusqlite::types::Type::Null => Ok(None),
                _ => Err(rusqlite::Error::UserFunctionError(
                    FunctionError::InvalidCompressType.into(),
                )),
            }
        },
    )?;

    db.create_scalar_function(
        "decompress",
        1,
        FunctionFlags::SQLITE_UTF8 | FunctionFlags::SQLITE_DETERMINISTIC,
        move |ctx| {
            assert_eq!(ctx.len(), 1, "called with unexpected number of arguments");

            let data = ctx.get_raw(0);
            let data_type = data.data_type();

            match data_type {
                rusqlite::types::Type::Blob => {
                    let data = data
                        .as_blob()
                        .map_err(|e| rusqlite::Error::UserFunctionError(e.into()))?;

                    let size = zstd::zstd_safe::get_frame_content_size(data).map_err(|e| {
                        rusqlite::Error::UserFunctionError(
                            FunctionError::CompressedSizeError(e.to_string()).into(),
                        )
                    })?;
                    match size {
                        Some(siz) => {
                            let decomp = decompress(data, siz as usize)
                                .map_err(|e| rusqlite::Error::UserFunctionError(e.into()))?;
                            Ok(Some(decomp))
                        }
                        None => Err(rusqlite::Error::UserFunctionError(
                            FunctionError::CompressedSizeError("Empty size".to_string()).into(),
                        )),
                    }
                }
                rusqlite::types::Type::Null => Ok(None),
                _ => Err(rusqlite::Error::UserFunctionError(
                    FunctionError::InvalidDeCompressType.into(),
                )),
            }
        },
    )?;

    db.create_scalar_function(
        "decompress_text",
        1,
        FunctionFlags::SQLITE_UTF8 | FunctionFlags::SQLITE_DETERMINISTIC,
        move |ctx| {
            assert_eq!(ctx.len(), 1, "called with unexpected number of arguments");

            let data = ctx.get_raw(0);
            let data_type = data.data_type();

            match data_type {
                rusqlite::types::Type::Blob => {
                    let data = data
                        .as_blob()
                        .map_err(|e| rusqlite::Error::UserFunctionError(e.into()))?;

                    let size = zstd::zstd_safe::get_frame_content_size(data).map_err(|e| {
                        rusqlite::Error::UserFunctionError(
                            FunctionError::CompressedSizeError(e.to_string()).into(),
                        )
                    })?;
                    match size {
                        Some(siz) => {
                            let decomp = decompress(data, siz as usize)
                                .map_err(|e| rusqlite::Error::UserFunctionError(e.into()))?;
                            let text = std::str::from_utf8(&decomp)
                                .map_err(|e| rusqlite::Error::UserFunctionError(e.into()))?
                                .to_string();
                            Ok(Some(text))
                        }
                        None => Err(rusqlite::Error::UserFunctionError(
                            FunctionError::CompressedSizeError("Empty size".to_string()).into(),
                        )),
                    }
                }
                rusqlite::types::Type::Null => Ok(None),
                _ => Err(rusqlite::Error::UserFunctionError(
                    FunctionError::InvalidDeCompressType.into(),
                )),
            }
        },
    )?;

    Ok(())
}

//Attach an encrypted database to the connection
//the maximum number of attached databases is 10
//  path: database file path. Panic if the path is not valid utf-8
//  name: the name that will be used in query. will fail if it contains spaces
//  secret: the encryption key
pub fn attach(
    path: PathBuf,
    name: String,
    secret: &[u8; 32],
    conn: &rusqlite::Connection,
) -> Result<(), rusqlite::Error> {
    let secr = hex::encode(secret);
    let path_string: String = path.to_str().unwrap().to_string();
    let query = format!(
        "ATTACH DATABASE '{}' AS {} KEY \"x'{}'\"",
        path_string, name, secr
    );
    conn.execute(&query, [])?;
    Ok(())
}

#[cfg(test)]
mod tests {

    use rusqlite::types::Null;

    use crate::cryptography::hash;
    use crate::error::Error;

    use super::*;
    use std::{fs, path::Path, time::Instant};
    #[derive(Debug)]
    struct Person {
        id: i32,
        name: String,
        surname: String,
    }
    impl FromRow for Person {
        fn from_row() -> fn(&Row) -> Result<Box<Self>, rusqlite::Error> {
            |row| {
                Ok(Box::new(Person {
                    id: row.get(0)?,
                    name: row.get(1)?,
                    surname: row.get(2)?,
                }))
            }
        }
    }
    impl Writable for Person {
        fn write(&self, conn: &Connection) -> Result<(), Error> {
            let mut stmt =
                conn.prepare_cached("INSERT INTO person (name, surname) VALUES (?, ?)")?;

            stmt.execute((&self.name, &self.surname))?;
            Ok(())
        }
    }

    const DATA_PATH: &str = "test/data/database/";
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
    async fn test_pragma() -> Result<(), Error> {
        let path: PathBuf = init_database_path("test_pragma.db")?;
        let secret = hash(b"bytes");
        let conn = create_connection(&path, &secret, 1024, false)?;
        let mut stmt = conn.prepare("PRAGMA mmap_size")?;
        let mut rows = stmt.query([])?;
        let qs = rows.next()?.expect("oupssie");

        let val: u32 = qs.get(0)?;

        println!("PRAGMA {} = {} ", "mmap_size", val);
        Ok(())
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn async_queries() -> Result<(), Error> {
        let path: PathBuf = init_database_path("async_queries.db")?;
        let secret = hash(b"bytes");
        let conn = create_connection(&path, &secret, 1024, false)?;
        conn.execute(
            "CREATE TABLE person (
                id              INTEGER PRIMARY KEY,
                name            TEXT NOT NULL,
                surname         TEXT
            ) STRICT",
            [],
        )?;

        let writer = BufferedDatabaseWriter::start(10, conn).await;

        writer
            .write_async(Box::new(Person {
                id: 0,
                name: "Steven".to_string(),
                surname: "Bob".to_string(),
            }))
            .await??;

        let conn = create_connection(&path, &secret, 8192, false)?;
        let reader = DatabaseReader::start(conn);
        let res = reader
            .query_async(
                "SELECT * FROM person".to_string(),
                vec![],
                Person::from_row(),
            )
            .await?;
        assert_eq!(res.len(), 1);
        assert_eq!(res[0].id, 1);

        Ok(())
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn blocking_queries() -> Result<(), Error> {
        let path: PathBuf = init_database_path("blocking_queries.db")?;
        let secret = hash(b"bytes");
        let writer_conn = create_connection(&path, &secret, 1024, false)?;
        writer_conn.execute(
            "CREATE TABLE person (
                id              INTEGER PRIMARY KEY,
                name            TEXT NOT NULL,
                surname         TEXT
            ) STRICT",
            [],
        )?;

        let writer = BufferedDatabaseWriter::start(10, writer_conn).await;
        let reader_conn = create_connection(&path, &secret, 8192, false)?;

        let _ = thread::spawn(move || {
            let _ = writer.write_blocking(Box::new(Person {
                id: 0,
                name: "Steven".to_string(),
                surname: "Bob".to_string(),
            }));

            let reader = DatabaseReader::start(reader_conn);
            let res = reader
                .query_blocking(
                    "SELECT * FROM person".to_string(),
                    vec![],
                    Person::from_row(),
                )
                .unwrap();
            assert_eq!(res.len(), 1);
            assert_eq!(res[0].id, 1);
            //     print!("");
        })
        .join();

        Ok(())
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn batch_writes_buffersize_1() -> Result<(), Error> {
        let path: PathBuf = init_database_path("batch_writes_buffersize_1.db")?;
        let secret = hash(b"bytes");
        let conn = create_connection(&path, &secret, 1024, false)?;

        conn.execute(
            "CREATE TABLE person (
                id              INTEGER PRIMARY KEY,
                name            TEXT NOT NULL,
                surname         TEXT
            ) STRICT",
            [],
        )?;

        let writer = BufferedDatabaseWriter::start(1, conn).await;

        let loop_number = 10;
        let _start = Instant::now();
        let mut reply_list = vec![];

        for i in 0..loop_number {
            let (reply, reciev) = oneshot::channel::<Result<(), crate::error::Error>>();

            let query = WriteQuery {
                writeable: vec![Box::new(Person {
                    id: 0,
                    name: format!("Steven-{}", i),
                    surname: "Bob".to_string(),
                })],
                reply: reply,
            };
            writer.send_async(query).await?;
            reply_list.push(reciev);
        }
        reply_list.pop().unwrap().await??;
        //    println!("Time buffered {}", start.elapsed().as_millis());

        // let start = Instant::now();

        let conn = create_connection(&path, &secret, 8192, false)?;
        let reader = DatabaseReader::start(conn);
        let res = reader
            .query_async(
                "SELECT * FROM person ORDER BY id".to_string(),
                vec![],
                Person::from_row(),
            )
            .await?;
        assert_eq!(res.len(), loop_number);
        assert_eq!(res[0].id, 1);

        Ok(())
    }

    //batch write is much faster than inserting row one by one
    #[tokio::test(flavor = "multi_thread")]
    async fn batch_writes_buffersize_10() -> Result<(), Error> {
        let path: PathBuf = init_database_path("batch_writes_buffersize_10.db")?;
        let secret = hash(b"bytes");
        let conn = create_connection(&path, &secret, 1024, false)?;

        conn.execute(
            "CREATE TABLE person (
                id              INTEGER PRIMARY KEY,
                name            TEXT NOT NULL,
                surname         TEXT
            ) STRICT",
            [],
        )?;

        let writer = BufferedDatabaseWriter::start(10, conn).await;
        let loop_number = 100;
        //   let start = Instant::now();
        let mut reply_list = vec![];

        for i in 0..loop_number {
            let (reply, reciev) = oneshot::channel::<Result<(), crate::error::Error>>();

            let query = WriteQuery {
                writeable: vec![Box::new(Person {
                    id: 0,
                    name: format!("Steven-{}", i),
                    surname: "Bob".to_string(),
                })],
                reply: reply,
            };
            writer.send_async(query).await?;
            reply_list.push(reciev);
        }
        reply_list.pop().unwrap().await??;

        // println!(
        //     "Time {} rows in {} ms",
        //     loop_number,
        //     start.elapsed().as_millis()
        // );

        // let start = Instant::now();

        let conn = create_connection(&path, &secret, 8192, false)?;
        let reader = DatabaseReader::start(conn);
        let res = reader
            .query_async(
                "SELECT * FROM person ORDER BY id".to_string(),
                vec![],
                Person::from_row(),
            )
            .await?;
        assert_eq!(res.len(), loop_number);
        assert_eq!(res[0].id, 1);

        Ok(())
    }

    //batch write is much faster than inserting row one by one
    #[tokio::test(flavor = "multi_thread")]
    async fn select_parameter_test() -> Result<(), Error> {
        let path: PathBuf = init_database_path("select_parameter_test.db")?;
        let secret = hash(b"bytes");
        let conn = create_connection(&path, &secret, 1024, false)?;

        conn.execute(
            "CREATE TABLE person (
                id              INTEGER PRIMARY KEY,
                name            TEXT NOT NULL,
                surname         TEXT
            ) STRICT",
            [],
        )?;

        let writer = BufferedDatabaseWriter::start(10, conn).await;
        let loop_number: usize = 100;
        //   let start = Instant::now();
        let mut buffer: Vec<Box<dyn Writable + Send>> = vec![];
        for i in 0..loop_number {
            buffer.push(Box::new(Person {
                id: i.try_into().unwrap(),
                name: format!("Steven-{}", i),
                surname: "Bob".to_string(),
            }));
        }

        let (reply, reciev) = oneshot::channel::<Result<(), crate::error::Error>>();
        let query = WriteQuery {
            writeable: buffer,
            reply: reply,
        };
        writer.send_async(query).await?;
        reciev.await??;

        let conn = create_connection(&path, &secret, 8192, false)?;
        let reader = DatabaseReader::start(conn);
        let res = reader
            .query_async(
                "SELECT * FROM person WHERE id = ? ORDER BY id".to_string(),
                vec![Box::new(1)],
                Person::from_row(),
            )
            .await?;
        assert_eq!(res.len(), 1);

        Ok(())
    }

    //batch write is much faster than inserting row one by one
    #[tokio::test(flavor = "multi_thread")]
    async fn read_only_test() -> Result<(), Error> {
        let path: PathBuf = init_database_path("read_only_test.db")?;
        let secret = hash(b"bytes");
        let conn = create_connection(&path, &secret, 1024, false)?;

        conn.execute(
            "CREATE TABLE person (
            id              INTEGER PRIMARY KEY,
            name            TEXT NOT NULL,
            surname         TEXT
        ) STRICT",
            [],
        )?;

        let writer = BufferedDatabaseWriter::start(10, conn).await;
        let loop_number: usize = 1;
        //   let start = Instant::now();
        let mut buffer: Vec<Box<dyn Writable + Send>> = vec![];
        for i in 0..loop_number {
            buffer.push(Box::new(Person {
                id: i.try_into().unwrap(),
                name: format!("Steven-{}", i),
                surname: "Bob".to_string(),
            }));
        }

        let (reply, reciev) = oneshot::channel::<Result<(), crate::error::Error>>();
        let query = WriteQuery {
            writeable: buffer,
            reply: reply,
        };
        writer.send_async(query).await?;
        reciev.await??;

        let conn = create_connection(&path, &secret, 8192, false)?;
        let reader = DatabaseReader::start(conn);
        let _res = reader
            .query_async(
                "Update person SET name = '2' ".to_string(),
                vec![],
                Person::from_row(),
            )
            .await
            .expect_err("attempt to write a readonly database");

        reader
            .query_async("pragma optimize; ".to_string(), vec![], |_e| {
                Ok(Box::new(true))
            })
            .await?;

        Ok(())
    }

    #[test]
    fn hash_function() -> Result<(), Error> {
        use fallible_iterator::FallibleIterator;
        let path: PathBuf = init_database_path("hash_function.db")?;
        let secret = hash(b"bytes");
        let conn = create_connection(&path, &secret, 1024, false)?;
        conn.execute(
            "CREATE TABLE HASHTABLE (
                name TEXT,
                grp INTEGER,
                rank INTEGER 
            ) ",
            [],
        )?;

        let mut stmt =
            conn.prepare("INSERT INTO HASHTABLE (name, grp, rank) VALUES (?1, ?2, ?3)")?;
        stmt.execute(("test1", 1, 1))?;
        stmt.execute(("test2", 1, 2))?;
        stmt.execute(("test3", 1, 3))?;
        stmt.execute(("test1", 2, 2))?;
        stmt.execute(("test2", 2, 1))?;
        stmt.execute(("test3", 2, 3))?;

        let mut expected: Vec<String> = vec![];

        let mut hasher = blake3::Hasher::new();
        hasher.update("test1".as_bytes());
        hasher.update("test2".as_bytes());
        hasher.update("test3".as_bytes());
        expected.push(base64_encode(hasher.finalize().as_bytes()));

        hasher = blake3::Hasher::new();
        hasher.update("test2".as_bytes());
        hasher.update("test1".as_bytes());
        hasher.update("test3".as_bytes());
        expected.push(base64_encode(hasher.finalize().as_bytes()));

        //hashing is order dependent, the subselect is for enforcing the order by
        let mut stmt = conn.prepare(
            "
        SELECT hash(name) 
        FROM (SELECT name, grp FROM HASHTABLE   ORDER BY rank)
        GROUP BY grp
         ",
        )?;

        let results: Vec<String> = stmt.query([])?.map(|row| Ok(row.get(0)?)).collect()?;

        assert_eq!(expected, results);

        Ok(())
    }

    #[test]
    fn compress_function() -> Result<(), Error> {
        use fallible_iterator::FallibleIterator;
        let path: PathBuf = init_database_path("compress_function.db")?;
        let secret = hash(b"bytes");
        let conn = create_connection(&path, &secret, 1024, false)?;
        conn.execute(
            "CREATE TABLE COMPRESS (
                string BLOB,
                binary BLOB
            ) ",
            [],
        )?;

        let value = "Lorem ipsum dolor sit amet, consectetur adipiscing elit, sed do eiusmod tempor incididunt ut labore et dolore magna aliqua.";
        let binary = " ipsum dolor sit amet, consectetur adipiscing elit, sed do eiusmod tempor incididunt ut labore et dolore magna aliqua.".as_bytes();

        let mut stmt = conn
            .prepare("INSERT INTO COMPRESS (string, binary) VALUES (compress(?1), compress(?2))")?;
        stmt.execute((value, binary))?;
        stmt.execute((value, Null))?;
        stmt.execute((Null, binary))?;

        let mut stmt = conn.prepare(
            "
        SELECT decompress_text(string)
        FROM COMPRESS
         ",
        )?;

        let results: Vec<Option<String>> = stmt.query([])?.map(|row| Ok(row.get(0)?)).collect()?;
        let expected: Vec<Option<String>> =
            vec![Some(value.to_string()), Some(value.to_string()), None];
        assert_eq!(results, expected);

        let mut stmt = conn.prepare(
            "
        SELECT decompress(binary)
        FROM COMPRESS
         ",
        )?;

        let results: Vec<Option<Vec<u8>>> = stmt.query([])?.map(|row| Ok(row.get(0)?)).collect()?;
        let expected: Vec<Option<Vec<u8>>> =
            vec![Some(binary.to_vec()), None, Some(binary.to_vec())];
        assert_eq!(results, expected);

        Ok(())
    }

    #[test]
    fn extract_json_test() -> Result<(), Error> {
        let json = r#"
        {
            "name": "John Doe",
            "age": 43,
            "phones": [
                "+44 1234567",
                "+44 2345678"
            ]
        }"#;
        let v: serde_json::Value = serde_json::from_str(json)?;
        let mut buff = String::new();
        extract_json(v, &mut buff)?;

        let mut expected = String::new();
        expected.push_str("John Doe\n");
        expected.push_str("+44 1234567\n");
        expected.push_str("+44 2345678\n");
        assert_eq!(buff, expected);

        Ok(())
    }

    #[test]
    fn json_data_function() -> Result<(), Error> {
        use fallible_iterator::FallibleIterator;
        let path: PathBuf = init_database_path("json_data_function.db")?;
        let secret = hash(b"bytes");
        let conn = create_connection(&path, &secret, 1024, false)?;
        conn.execute(
            "CREATE TABLE JSON (
                string BLOB
            ) ",
            [],
        )?;

        let json = r#"
        {
            "name": "John Doe",
            "age": 43,
            "phones": [
                "+44 1234567",
                "+44 2345678"
            ]
        }"#;

        let mut stmt = conn.prepare("INSERT INTO JSON (string) VALUES (compress(?1))")?;

        stmt.execute([json])?;
        stmt.execute([Null])?;

        let mut stmt = conn.prepare(
            "
        SELECT json_data(decompress_text(string))
        FROM JSON
         ",
        )?;

        let results: Vec<Option<String>> = stmt.query([])?.map(|row| Ok(row.get(0)?)).collect()?;

        let mut extract = String::new();
        extract.push_str("John Doe\n");
        extract.push_str("+44 1234567\n");
        extract.push_str("+44 2345678\n");

        let expected: Vec<Option<String>> = vec![Some(extract), None];

        assert_eq!(results, expected);

        Ok(())
    }
}
