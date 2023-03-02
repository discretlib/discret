use rusqlite::{Connection, Row, ToSql};

use std::{path::PathBuf, thread};
use tokio::sync::{mpsc, oneshot};

use super::{Error, Result};

pub type ReaderFn = Box<dyn FnOnce(&mut Connection) + Send + 'static>;
pub type MappingFn<T> = fn(&Row) -> std::result::Result<Box<T>, rusqlite::Error>;
pub trait FromRow {
    fn from_row() -> MappingFn<Self>;
}

pub trait Writable {
    fn write(&self, conn: &Connection) -> Result<()>;
}

pub struct WriteQuery {
    pub writeable: Vec<Box<dyn Writable + Send>>,
    pub reply: oneshot::Sender<Result<()>>,
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

    //set cache capacity to 128 (from default 16)
    conn.set_prepared_statement_cache_capacity(128);

    //Encrypt the database.
    //
    //The "x'key'"" format means that no additional key derivation is done by sqlcipher
    let sqlcipher_key = format!("\"x'{}'\"", hex::encode(secret));
    set_pragma("key", &sqlcipher_key, &conn)?;

    let page_size = "16384";
    //Increase page size.
    //
    //Could be usefull as for WITHOUT ROWID tables
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
    // Disabled because it hides the real RAM usage
    //set_pragma("mmap_size", "268435456", &conn)?;

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
    ) -> Result<Vec<T>> {
        let (send_response, receive_response) = oneshot::channel::<Result<Vec<T>>>();

        self.sender
            .send(Box::new(move |conn| {
                let result = Self::select(&query, &params, &mapping, conn).map_err(Error::from);

                let _ = send_response.send(result);
            }))
            .await
            .map_err(|e| Error::TokioSendError(e.to_string()))?;

        receive_response.await.map_err(Error::from)?
    }

    pub fn query_blocking<T: FromRow + Send + Sized + 'static>(
        &self,
        query: String,
        params: Vec<Box<dyn ToSql + Sync + Send>>,
        mapping: MappingFn<T>,
    ) -> Result<Vec<T>> {
        let (send_response, receive_response) = oneshot::channel::<Result<Vec<T>>>();

        self.sender
            .blocking_send(Box::new(move |conn| {
                let result = Self::select(&query, &params, &mapping, conn).map_err(Error::from);
                let _ = send_response.send(result);
            }))
            .map_err(|e| Error::TokioSendError(e.to_string()))?;

        receive_response.blocking_recv().map_err(Error::from)?
    }

    fn select<T: Send + Sized + 'static>(
        query: &str,
        params: &Vec<Box<dyn ToSql + Sync + Send>>,
        mapping: &MappingFn<T>,
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
struct Optimize {}
impl Writable for Optimize {
    fn write(&self, conn: &Connection) -> std::result::Result<(), Error> {
        conn.execute("PRAGMA OPTIMIZE", [])?;
        Ok(())
    }
}

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

    pub async fn write_async(&self, insert: Box<dyn Writable + Send>) -> Result<Result<()>> {
        let (reply, reciev) = oneshot::channel::<Result<()>>();
        let _ = self
            .sender
            .send(WriteQuery {
                writeable: vec![insert],
                reply,
            })
            .await;
        reciev.await.map_err(Error::from)
    }

    pub fn write_blocking(&self, insert: Box<dyn Writable + Send>) -> Result<Result<()>> {
        let (reply, reciev) = oneshot::channel::<Result<()>>();
        let _ = self.sender.blocking_send(WriteQuery {
            writeable: vec![insert],
            reply,
        });
        reciev.blocking_recv().map_err(Error::from)
    }

    pub async fn optimize_async(&self) -> Result<Result<()>> {
        self.write_async(Box::new(Optimize {})).await
    }

    pub fn optimize_blocking(&self) -> Result<Result<()>> {
        self.write_blocking(Box::new(Optimize {}))
    }

    fn process_batch_write(buffer: &Vec<WriteQuery>, conn: &Connection) -> Result<()> {
        conn.execute("BEGIN TRANSACTION", [])?;
        for write in buffer {
            let result = Self::process_write(write, conn);
            if let Err(e) = result {
                conn.execute("ROLLBACK", [])?;
                return Err(e);
            }
        }
        conn.execute("COMMIT", [])?;
        Ok(())
    }

    fn process_write(query: &WriteQuery, conn: &Connection) -> Result<()> {
        for q in &query.writeable {
            q.write(conn)?;
        }
        Ok(())
    }
}

pub fn set_pragma(pragma: &str, value: &str, conn: &rusqlite::Connection) -> Result<()> {
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cryptography::hash;
    use crate::database::Error;
    use std::result::Result;
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
        fn write(&self, conn: &Connection) -> std::result::Result<(), Error> {
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
    async fn test_pragma() {
        let path: PathBuf = init_database_path("test_pragma.db").unwrap();
        let secret = hash(b"bytes");
        let conn = create_connection(&path, &secret, 1024, false).unwrap();
        let mut stmt = conn.prepare("PRAGMA mmap_size").unwrap();
        let mut rows = stmt.query([]).unwrap();
        let qs = rows.next().unwrap().expect("oupssie");

        let val: u32 = qs.get(0).unwrap();

        println!("PRAGMA {} = {} ", "mmap_size", val);
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

        let writer = BufferedDatabaseWriter::start(10, conn).await;

        writer
            .write_async(Box::new(Person {
                id: 0,
                name: "Steven".to_string(),
                surname: "Bob".to_string(),
            }))
            .await
            .unwrap()
            .unwrap();

        let conn = create_connection(&path, &secret, 8192, false).unwrap();
        let reader = DatabaseReader::start(conn);
        let res = reader
            .query_async(
                "SELECT * FROM person".to_string(),
                vec![],
                Person::from_row(),
            )
            .await
            .unwrap();
        assert_eq!(res.len(), 1);
        assert_eq!(res[0].id, 1);
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

        let writer = BufferedDatabaseWriter::start(10, writer_conn).await;
        let reader_conn = create_connection(&path, &secret, 8192, false).unwrap();

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

        let writer = BufferedDatabaseWriter::start(1, conn).await;

        let loop_number = 10;
        let _start = Instant::now();
        let mut reply_list = vec![];

        for i in 0..loop_number {
            let (reply, reciev) = oneshot::channel::<Result<(), Error>>();

            let query = WriteQuery {
                writeable: vec![Box::new(Person {
                    id: 0,
                    name: format!("Steven-{}", i),
                    surname: "Bob".to_string(),
                })],
                reply: reply,
            };
            writer.send_async(query).await.unwrap();
            reply_list.push(reciev);
        }
        reply_list.pop().unwrap().await.unwrap().unwrap();
        //    println!("Time buffered {}", start.elapsed().as_millis());

        // let start = Instant::now();

        let conn = create_connection(&path, &secret, 8192, false).unwrap();
        let reader = DatabaseReader::start(conn);
        let res = reader
            .query_async(
                "SELECT * FROM person ORDER BY id".to_string(),
                vec![],
                Person::from_row(),
            )
            .await
            .unwrap();
        assert_eq!(res.len(), loop_number);
        assert_eq!(res[0].id, 1);
    }

    //batch write is much faster than inserting row one by one
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

        let writer = BufferedDatabaseWriter::start(10, conn).await;
        let loop_number = 100;
        //   let start = Instant::now();
        let mut reply_list = vec![];

        for i in 0..loop_number {
            let (reply, reciev) = oneshot::channel::<Result<(), Error>>();

            let query = WriteQuery {
                writeable: vec![Box::new(Person {
                    id: 0,
                    name: format!("Steven-{}", i),
                    surname: "Bob".to_string(),
                })],
                reply: reply,
            };
            writer.send_async(query).await.unwrap();
            reply_list.push(reciev);
        }
        reply_list.pop().unwrap().await.unwrap().unwrap();

        // println!(
        //     "Time {} rows in {} ms",
        //     loop_number,
        //     start.elapsed().as_millis()
        // );

        // let start = Instant::now();

        let conn = create_connection(&path, &secret, 8192, false).unwrap();
        let reader = DatabaseReader::start(conn);
        let res = reader
            .query_async(
                "SELECT * FROM person ORDER BY id".to_string(),
                vec![],
                Person::from_row(),
            )
            .await
            .unwrap();
        assert_eq!(res.len(), loop_number);
        assert_eq!(res[0].id, 1);
    }

    //batch write is much faster than inserting row one by one
    #[tokio::test(flavor = "multi_thread")]
    async fn select_parameter_test() {
        let path: PathBuf = init_database_path("select_parameter_test.db").unwrap();
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

        let (reply, reciev) = oneshot::channel::<Result<(), Error>>();
        let query = WriteQuery {
            writeable: buffer,
            reply: reply,
        };
        writer.send_async(query).await.unwrap();
        reciev.await.unwrap().unwrap();

        let conn = create_connection(&path, &secret, 8192, false).unwrap();
        let reader = DatabaseReader::start(conn);
        let res = reader
            .query_async(
                "SELECT * FROM person WHERE id = ? ORDER BY id".to_string(),
                vec![Box::new(1)],
                Person::from_row(),
            )
            .await
            .unwrap();
        assert_eq!(res.len(), 1);
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

        let (reply, reciev) = oneshot::channel::<Result<(), Error>>();
        let query = WriteQuery {
            writeable: buffer,
            reply: reply,
        };
        writer.send_async(query).await.unwrap();
        reciev.await.unwrap().unwrap();

        let conn = create_connection(&path, &secret, 8192, false).unwrap();
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
            .await
            .unwrap();
    }
}
