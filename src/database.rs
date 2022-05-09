use rusqlite::{types::Value, Connection, Row, ToSql};
use std::path::PathBuf;
use tokio::sync::{mpsc, oneshot};

struct WriteQuery {
    query: String,
    params: Vec<Value>,
    reply: oneshot::Sender<Result<(), rusqlite::Error>>,
}

struct SelectQuery<T> {
    query: String,
    params: Vec<Value>,
    reply: oneshot::Sender<Result<Vec<T>, rusqlite::Error>>,
    mapper: fn(&Row) -> Result<T, rusqlite::Error>,
}

fn buffered_database_writer(buffer_size: usize, conn: Connection) -> mpsc::Sender<WriteQuery> {
    let (send_write, mut receive_write): (mpsc::Sender<WriteQuery>, mpsc::Receiver<WriteQuery>) =
        mpsc::channel::<WriteQuery>(20);

    let (send_ready, mut receive_ready): (mpsc::Sender<bool>, mpsc::Receiver<bool>) =
        mpsc::channel::<bool>(20);

    let (send_buffer, mut receive_buffer) = mpsc::channel::<Vec<WriteQuery>>(buffer_size);

    tokio::spawn(async move {
        let mut query_buffer: Vec<WriteQuery> = vec![];
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
                    if query_buffer.len() > 0 {
                        let _s = send_buffer.send(query_buffer).await;
                        query_buffer = vec![];
                    }
                }
            };
            if query_buffer.len() >= buffer_size {
                let ready = receive_ready.recv().await;
                if ready.is_none() {
                    break;
                }
                if query_buffer.len() > 0 {
                    let _s = send_buffer.send(query_buffer).await;
                    query_buffer = vec![];
                }
            }
        }
    });

    tokio::task::spawn_blocking(move || {
        let _s = send_ready.blocking_send(true);
        while let Some(buffer) = receive_buffer.blocking_recv() {
            let result = process_batch_write(&buffer, &conn);
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
                            .send(Err(rusqlite::Error::ModuleError(e.to_string())));
                    }
                }
            }
            let _s = send_ready.blocking_send(true);
        }
    });

    send_write
}

fn process_batch_write(buffer: &Vec<WriteQuery>, conn: &Connection) -> Result<(), rusqlite::Error> {
    conn.execute("BEGIN TRANSACTION", [])?;
    for write in buffer {
        process_write(&write, &conn)?;
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

fn process_select<T>(query: &SelectQuery<T>, conn: &Connection) -> Result<Vec<T>, rusqlite::Error> {
    let mut stmt = conn.prepare_cached(&query.query)?;
    let params = rusqlite::params_from_iter(&query.params);
    let iter = stmt.query_map(params, &query.mapper)?;
    let mut result: Vec<T> = vec![];
    for res in iter {
        result.push(res?)
    }
    Ok(result)
}

fn create_connection(
    path: &PathBuf,
    secret: &[u8; 32],
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
    //Prevents memory to be written into swap and zeroise memory after free
    //Can be disabled because of a huge performance impact (about 50%),
    //When this feature is disabled, locking/unlocking of the memory address only occur for the internal SQLCipher
    //data structures used to store key material, and cryptographic structures.
    //source: https://discuss.zetetic.net/t/what-is-the-purpose-of-pragma-cipher-memory-security/3953
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
    set_pragma("cache_size", "-8192", &conn)?;

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

//Attempt to optimize the database
//Recompute statistics when needed
//Must be run on a regular basis to get good performances
//planned setup:every hours
fn optimize(conn: &rusqlite::Connection) -> Result<(), rusqlite::Error> {
    let mut stmt = conn.prepare("PRAGMA optimize")?;
    let _rows = stmt.query([])?;
    Ok(())
}

//Defragment database to reduce the database size and increase performances
//should be run from time to time
//this is a long running task that blocks writes and temporarilly double the database size
//planned setup: manually? every month?
fn vaccuum(conn: &rusqlite::Connection) -> Result<(), rusqlite::Error> {
    let mut stmt = conn.prepare("VACUUM")?;
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

#[cfg(test)]
mod tests {
    use rusqlite::{params, Params};

    use crate::cryptography::hash;

    use super::*;
    use std::error::Error;

    #[derive(Debug)]
    struct Person {
        id: i32,
        name: String,
        surname: String,
    }

    #[test]
    fn test_query() -> Result<(), Box<dyn Error>> {
        let path: PathBuf = "test/data/test.db".into();
        let secret = hash(b"bytes");
        let conn = create_connection(&path, &secret, false)?;

        let create = "CREATE TABLE IF NOT EXISTS person (
            id              INTEGER PRIMARY KEY,
            name            TEXT NOT NULL,
            data            BLOB
            )"
        .to_string();

        let (reply, _write) = oneshot::channel::<Result<(), rusqlite::Error>>();
        let query = WriteQuery {
            query: create,
            params: vec![],
            reply: reply,
        };
        process_write(&query, &conn)?;
        conn.execute("DELETE FROM person", [])?;
        let me = Person {
            id: 0,
            name: "Steven".to_string(),
            surname: "Bob".to_string(),
        };

        let (reply, _write) = oneshot::channel::<Result<(), rusqlite::Error>>();
        let query = WriteQuery {
            query: "INSERT INTO person (name, data) VALUES (?, ?)".to_string(),
            params: vec![Value::Text(me.name), Value::Text(me.surname)],
            reply: reply,
        };

        //  process_write(&query, &conn)?;

        process_write(&query, &conn)?;
        process_write(&query, &conn)?;

        let (reply, _write) = oneshot::channel::<Result<Vec<Person>, rusqlite::Error>>();
        let query = SelectQuery {
            query: "SELECT * FROM person".to_string(),
            params: vec![],
            reply: reply,
            mapper: |row| {
                Ok(Person {
                    id: row.get(0)?,
                    name: row.get(1)?,
                    surname: row.get(2)?,
                })
            },
        };

        let rs = process_select(&query, &conn)?;
        for per in rs {
            println!(
                "id:{}   name:{}   surname:{}",
                per.id, per.name, per.surname
            );
        }

        Ok(())
    }

    fn display_query(query: &str, conn: &rusqlite::Connection) -> Result<(), rusqlite::Error> {
        let mut stmt = conn.prepare(query)?;
        let len = stmt.column_count();
        let mut rows = stmt.query([])?;

        while let Some(row) = rows.next()? {
            for idx in 0..len {
                let val: rusqlite::types::ValueRef = row.get_ref(idx)?;
                match val {
                    rusqlite::types::ValueRef::Null => print!(" NULL |"),
                    rusqlite::types::ValueRef::Integer(val) => print!(" {} |", val),
                    rusqlite::types::ValueRef::Real(val) => print!(" {} |", val),
                    rusqlite::types::ValueRef::Text(val) => {
                        print!(" {} |", String::from_utf8_lossy(val))
                    }
                    rusqlite::types::ValueRef::Blob(_val) => print!(" BLOB |"),
                };
                println!("");
            }
        }

        Ok(())
    }
}
/*
let hook = |_: Action, _: &str, _: &str, _: i64| {
    if let Ok(ref mut mutex) = locked.try_lock() {
        **mutex = ();
    }
};

db.update_hook(Some(hook)); */

/* pub struct Database {
    path: PathBuf,
    secret: String,
    pool: Pool<Connection>,
}

impl Database {
    pub fn new(path: PathBuf, secret: [u8; 32]) -> Self {
        //this key format avoids additional key derivation from SQLCipher
        let sqlcipher_key = format!("x'{}'", hex::encode(&secret));
        Database {
            path,
            secret: sqlcipher_key,
            //start with zero capacity so the init closure  is never called
            //this avoid potential io error during initialisation
            pool: Pool::new(0, || Connection::open_in_memory().unwrap()),
        }
    }

    pub fn exist(&self) -> bool {
        self.path.exists()
    }

    pub fn pool_len(&self) -> usize {
        self.pool.len()
    }

    pub fn get_connection(&self) -> Result<Reusable<Connection>, rusqlite::Error> {
        let conn = self.pool.try_pull();
        match conn {
            Some(i) => Ok(i),
            None => {
                let newconn = self.create_connection()?;
                self.pool.attach(newconn);
                let newreusable = self.pool.try_pull().unwrap_or_else(|| {
                    panic!("This should never occur, we just put a new connection in the pool!")
                });
                Ok(newreusable)
            }
        }
    }

    fn create_connection(&self) -> Result<Connection, rusqlite::Error> {
        let conn = rusqlite::Connection::open(self.path.clone())?;
        {
            let query = format!("PRAGMA key=\"{}\" ", self.secret);
            let res: String = conn.query_row(&query, [], |row| row.get(0))?;
            assert_eq!("ok", res)
        }
        Ok(conn)
    }
}

#[cfg(test)]
mod tests {
    use super::Database;
    use crate::{build_path, database_file_name_for};
    use rusqlite::params;
    #[test]
    fn test_pool_reuse() -> Result<(), rusqlite::Error> {
        let secret = [1; 32];
        let file_name = database_file_name_for(&secret);
        let path = build_path("test/data/", &file_name).unwrap();
        let poule = Database::new(path, secret);
        // println!("Poule size  {:?}", poule.len());
        //brace to quickly push the Connection out of scope
        assert_eq!(poule.pool_len(), 0);
        {
            let conn = poule.get_connection()?;
            assert_eq!(poule.pool_len(), 0);
            let _t: i32 = conn.query_row("SELECT $1", [42], |row| row.get(0))?;
        }
        assert_eq!(poule.pool_len(), 1);
        {
            let conn = poule.get_connection()?;
            assert_eq!(poule.pool_len(), 0);
            let _t: i32 = conn.query_row("SELECT $1", [42], |row| row.get(0))?;
        }
        assert_eq!(poule.pool_len(), 1);
        Ok(())
    }

    struct Person {
        id: i32,
        name: String,
    }

    #[test]
    fn test_pool_encryption() -> Result<(), rusqlite::Error> {
        let db_path = "test/data/";
        let secret = [1; 32];
        let file_name = database_file_name_for(&secret);
        let path = build_path(db_path, &file_name).unwrap();

        let poule = Database::new(path.clone(), secret);
        // println!("Poule size  {:?}", poule.len());
        //brace to quickly push the Connection out of scope
        {
            let good_conn_1 = poule.get_connection()?;
            good_conn_1.execute(
                "CREATE TABLE IF NOT EXISTS person (
                    id    INTEGER PRIMARY KEY,
                    name  TEXT NOT NULL
                )",
                [], // empty list of parameters.
            )?;
            good_conn_1.execute("DELETE FROM person", [])?;
            let me = Person {
                id: 0,
                name: "Steven".to_string(),
            };
            good_conn_1.execute("INSERT INTO person (name) VALUES (?1)", params![me.name])?;

            let good_conn_2 = poule.get_connection()?;

            let mut stmt = good_conn_2.prepare("SELECT id, name FROM person")?;
            let person_iter = stmt.query_map([], |row| {
                Ok(Person {
                    id: row.get(0)?,
                    name: row.get(1)?,
                })
            })?;

            for person in person_iter {
                let p = person.unwrap();
                assert_eq!(p.id, 1);
                assert_eq!(p.name, "Steven");
            }

            //setup a bad secret
            let secret = [5; 32];
            let bad_poule = Database::new(path, secret);
            let bad_conn_1 = bad_poule.get_connection()?;

            let result: Result<i32, rusqlite::Error> =
                bad_conn_1.query_row("SELECT id FROM person", [], |row| row.get(0));
            let error_message = result
                .expect_err("Should have failed due to wrong database password")
                .to_string();
            assert_eq!("file is not a database", error_message);
        }

        Ok(())
    }
}
 */
