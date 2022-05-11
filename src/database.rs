use rusqlite::{types::Value, Connection, Row};
use std::{path::PathBuf, thread, time::Duration};
use tokio::sync::{mpsc, oneshot};

use crate::error::Error;

// pub struct SelectQuery<T> {
//     query: String,
//     params: Vec<Value>,
//     mapper: fn(&Row) -> Result<T, rusqlite::Error>,
// }

type ReaderFn = Box<dyn FnOnce(&mut Connection) + Send + 'static>;
type MappingFn<T> = fn(&Row) -> Result<Box<T>, rusqlite::Error>;
pub trait FromRow {
    fn from_row() -> MappingFn<Self>;
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
        params: Vec<Value>,
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
        params: Vec<Value>,
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
        params: &Vec<Value>,
        mapping: &MappingFn<T>,
        conn: &Connection,
    ) -> Result<Vec<T>, rusqlite::Error> {
        let mut stmt = conn.prepare_cached(query)?;

        let params = rusqlite::params_from_iter(params);

        let iter = stmt.query_map(params, mapping)?;

        let mut result: Vec<T> = vec![];
        for res in iter {
            let s = res?;
            result.push(*s)
        }

        Ok(result)
    }
}

// fn process_select<T>(query: &SelectQuery<T>, conn: &Connection) -> Result<Vec<T>, rusqlite::Error> {
//     let mut stmt = conn.prepare_cached(&query.query)?;

//     let params = rusqlite::params_from_iter(&query.params);

//     let iter = stmt.query_map(params, &query.mapper)?;

//     let mut result: Vec<T> = vec![];
//     for res in iter {
//         result.push(res?)
//     }

//     Ok(result)
// }
pub struct WriteQuery {
    query: String,
    params: Vec<Value>,
    reply: oneshot::Sender<Result<(), Error>>,
}
// Main entry point to insert data in the database
//
// Clone it to safely perform queries across different thread
//
// Write queries are buffered while the database thread is working.
// When the database thread is ready, the buffer is sent and is processed in one single transaction
// This greatly increase insertion and update rate, compared to autocommit.
//
// If one a buffered query fails, the transaction will be rolled back and every other queries in the buffer will fail too.
// This should not be an issue as insert query are not expected to fail.
// The only reasons to fail an insertion are a bugs or a system failure (like no more space available on disk)
//
// Only one writer should be used per database, as are write transactions are serialized
//
#[derive(Clone)]
pub struct BufferedDatabaseWriter {
    sender: mpsc::Sender<WriteQuery>,
}
impl BufferedDatabaseWriter {
    pub async fn start(buffer_size: usize, conn: Connection) -> Self {
        let (send_write, mut receive_write): (
            mpsc::Sender<WriteQuery>,
            mpsc::Receiver<WriteQuery>,
        ) = mpsc::channel::<WriteQuery>(buffer_size);

        let (send_ready, mut receive_ready): (mpsc::Sender<bool>, mpsc::Receiver<bool>) =
            mpsc::channel::<bool>(2);

        let (send_buffer, mut receive_buffer) = mpsc::channel::<Vec<WriteQuery>>(1);

        tokio::spawn(async move {
            let mut query_buffer: Vec<WriteQuery> = vec![];
            let mut is_ready = false;
            loop {
                tokio::select! {
                    write_query = receive_write.recv() => {
                        match write_query {
                            Some(val) => query_buffer.push(val),
                            None => break,
                        }
                    },
                    ready = receive_ready.recv() => {
                        if ready.is_none() {
                            break;
                        }
                        is_ready = true;
                    }
                };

                if (!query_buffer.is_empty() && is_ready) || query_buffer.len() >= buffer_size {
                    let _s = send_buffer.send(query_buffer).await;
                    is_ready = false;
                    query_buffer = vec![];
                }
            }
        });

        thread::spawn(move || {
            let _s = send_ready.blocking_send(true);

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
        query: String,
        params: Vec<Value>,
    ) -> Result<Result<(), Error>, Error> {
        let (reply, reciev) = oneshot::channel::<Result<(), crate::error::Error>>();
        let _ = self
            .sender
            .send(WriteQuery {
                query,
                params,
                reply,
            })
            .await;
        reciev.await.map_err(|e| Error::Unknown(e.to_string()))
    }

    pub fn write_blocking(
        &self,
        query: String,
        params: Vec<Value>,
    ) -> Result<Result<(), Error>, Error> {
        let (reply, reciev) = oneshot::channel::<Result<(), crate::error::Error>>();
        let _ = self.sender.blocking_send(WriteQuery {
            query,
            params,
            reply,
        });
        reciev
            .blocking_recv()
            .map_err(|e| Error::Unknown(e.to_string()))
    }

    fn process_batch_write(
        buffer: &Vec<WriteQuery>,
        conn: &Connection,
    ) -> Result<(), rusqlite::Error> {
        conn.execute("BEGIN TRANSACTION", [])?;
        for write in buffer {
            Self::process_write(write, conn)?;
        }
        conn.execute("COMMIT", [])?;
        Ok(())
    }

    fn process_write(query: &WriteQuery, conn: &Connection) -> Result<(), rusqlite::Error> {
        let mut stmt = conn.prepare_cached(&query.query)?;
        let params = rusqlite::params_from_iter(&query.params);
        stmt.execute(params)?;
        Ok(())
    }
}

//Perform sqlite optimize task on a frequency basis
//
//The receiver MUST be consumed, otherwise the optimise task will be run only once
//
//Optimize: Attempt to optimize the database
//  Recompute statistics when needed
//  Must be run on a regular basis to get good performances
//  frequency: every hours?
pub fn house_keeper(
    frequency: Duration,
    conn: Connection,
) -> mpsc::Receiver<Result<(), rusqlite::Error>> {
    let (send_status, receive_status) = mpsc::channel::<Result<(), rusqlite::Error>>(1);
    thread::spawn(move || loop {
        thread::sleep(frequency);
        let result = optimize(&conn);
        let s = send_status.blocking_send(result);
        if s.is_err() {
            break;
        }
    });
    receive_status
}

//Create a sqlcipher database connection
//
//path: database file path
//
//secret: the encryption key
//
//cache_size:
//  the discret app set its to 8Mb for SELECT conn and 1Mb for Insert conn to get a relatively low memory usage,
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

    //WAL checkpoin every 100 dirty pages.
    set_pragma("wal_autocheckpoint", "100", &conn)?;

    //Best safe setting for WAL journaling.
    set_pragma("synchronous", "1", &conn)?;

    //Automatically reclaim storage after deletion
    //
    //enabled to keep database small
    set_pragma("auto_vacuum", "1", &conn)?;

    //Disable obscure legacy compatibility as recommended by doc.
    set_pragma("trusted_schema", "0", &conn)?;

    Ok(conn)
}

//Attach an encrypted database to the connection
//
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

//Vaccumm: Defragment database to reduce the database size and increase performances
//  should be run from time to time
//  this is a long running task that blocks writes and temporarilly double the database size
//  frequency: manually? every month?
//
pub fn vaccuum(conn: &rusqlite::Connection) -> Result<(), rusqlite::Error> {
    let mut stmt = conn.prepare("VACUUM")?;
    let _rows = stmt.query([])?;
    Ok(())
}

fn optimize(conn: &rusqlite::Connection) -> Result<(), rusqlite::Error> {
    let mut stmt = conn.prepare("PRAGMA optimize")?;
    let _rows = stmt.query([])?;
    Ok(())
}

fn set_pragma(
    pragma: &str,
    value: &str,
    conn: &rusqlite::Connection,
) -> Result<(), rusqlite::Error> {
    let mut stmt = conn.prepare(&format!("PRAGMA {}={}", pragma, value))?;
    let _rows = stmt.query([])?;
    Ok(())
}

pub fn build_params_from_json(
    params: Vec<serde_json::Value>,
) -> rusqlite::ParamsFromIter<Vec<Value>> {
    let mut temp_param: Vec<Value> = vec![];

    for par in params {
        if par.is_string() {
            temp_param.push(Value::Text(
                //removes the " " delimiters from the json string. ex: "value" becomes: value
                par.as_str().unwrap().to_string(),
            ));
        } else if par.is_i64() {
            temp_param.push(Value::Integer(par.as_i64().unwrap()));
        } else if par.is_f64() {
            temp_param.push(Value::Real(par.as_f64().unwrap()));
        } else {
            temp_param.push(Value::Text(par.to_string()));
        }
    }
    rusqlite::params_from_iter(temp_param)
}

#[cfg(test)]
mod tests {

    use crate::cryptography::hash;

    use super::*;
    use std::error::Error;
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

    #[tokio::test(flavor = "multi_thread")]
    async fn async_queries() -> Result<(), Box<dyn Error>> {
        let path: PathBuf = "test/data/select_queries.db".into();
        let secret = hash(b"bytes");
        let conn = create_connection(&path, &secret, 1024, false)?;
        let writer = BufferedDatabaseWriter::start(10, conn).await;

        writer
            .write_async(
                "CREATE TABLE IF NOT EXISTS person (
            id              INTEGER PRIMARY KEY,
            name            TEXT NOT NULL,
            surname         TEXT
            ) STRICT"
                    .to_string(),
                vec![],
            )
            .await??;

        writer
            .write_async("DELETE FROM person".to_string(), vec![])
            .await??;

        let per = Person {
            id: 0,
            name: "Steven".to_string(),
            surname: "Bob".to_string(),
        };

        let (reply, reciev) = oneshot::channel::<Result<(), crate::error::Error>>();
        let query = WriteQuery {
            query: "INSERT INTO person (name, surname) VALUES (?, ?)".to_string(),
            params: vec![Value::Text(per.name), Value::Text(per.surname)],
            reply: reply,
        };
        writer.send_async(query).await?;
        reciev.await??;

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
    async fn blocking_queries() -> Result<(), Box<dyn Error>> {
        let path: PathBuf = "test/data/select_queries.db".into();
        let secret = hash(b"bytes");
        let writer_conn = create_connection(&path, &secret, 1024, false)?;
        let writer = BufferedDatabaseWriter::start(10, writer_conn).await;
        let reader_conn = create_connection(&path, &secret, 8192, false)?;
        let _ = thread::spawn(move || {
            let _ = writer.write_blocking(
                "CREATE TABLE IF NOT EXISTS person (
                id              INTEGER PRIMARY KEY,
                name            TEXT NOT NULL,
                surname         TEXT
                ) STRICT"
                    .to_string(),
                vec![],
            );

            let _ = writer
                .write_blocking("DELETE FROM person".to_string(), vec![])
                .unwrap();
            let per = Person {
                id: 0,
                name: "Steven".to_string(),
                surname: "Bob".to_string(),
            };

            let (reply, reciev) = oneshot::channel::<Result<(), crate::error::Error>>();
            let query = WriteQuery {
                query: "INSERT INTO person (name, surname) VALUES (?, ?)".to_string(),
                params: vec![Value::Text(per.name), Value::Text(per.surname)],
                reply: reply,
            };
            let _ = writer.send_blocking(query);
            let _ = reciev.blocking_recv();

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
}
