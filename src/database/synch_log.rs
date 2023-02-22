use rusqlite::{Connection, Row};

use super::Error;

use super::database_service::{FromRow, Writable};

pub struct DailySynchLog {
    pub source: String,
    pub schema: String,
    pub date: i64,
    pub previous_day: Option<i64>,
    pub daily_hash: Vec<u8>,
    pub history_hash: Option<Vec<u8>>,
}
impl DailySynchLog {
    pub fn create_table(conn: &Connection) -> Result<(), rusqlite::Error> {
        conn.execute(
            " 
            CREATE TABLE daily_synch_log (
                source TEXT NOT NULL,
                schema TEXT NOT NULL,
                date INTEGER NOT NULL,
                previous_day INTEGER,
                daily_hash BLOB,
                history_hash BLOB,
                PRIMARY KEY (source, schema, date)
            )STRICT;
            ",
            [],
        )?;
        Ok(())
    }
}
impl FromRow for DailySynchLog {
    fn from_row() -> fn(&Row) -> Result<Box<Self>, rusqlite::Error> {
        |row| {
            Ok(Box::new(DailySynchLog {
                source: row.get(0)?,
                schema: row.get(1)?,
                date: row.get(2)?,
                previous_day: row.get(3)?,
                daily_hash: row.get(4)?,
                history_hash: row.get(5)?,
            }))
        }
    }
}
impl Writable for DailySynchLog {
    fn write(&self, conn: &Connection) -> Result<(), Error> {
        //unixepoch(Date(?, 'unixepoch'))
        let mut insert_stmt = conn.prepare_cached(
            "INSERT OR REPLACE INTO daily_synch_log (source, schema, date, previous_day, daily_hash, history_hash) 
                            VALUES (?, ?, ?, ?, ?, ?)",
        )?;
        insert_stmt.execute((
            &self.source,
            &self.schema,
            &self.date,
            &self.previous_day,
            &self.daily_hash,
            &self.history_hash,
        ))?;
        Ok(())
    }
}
impl Default for DailySynchLog {
    fn default() -> Self {
        Self {
            source: "".to_string(),
            schema: "".to_string(),
            date: 0,
            previous_day: None,
            daily_hash: vec![],
            history_hash: None,
        }
    }
}

#[cfg(test)]
mod tests {

    use crate::{
        cryptography::{base64_encode, hash},
        database::{
            database_service::{create_connection, FromRow, Writable},
            datamodel::{initialise_datamodel, now},
        },
    };

    use std::{
        error::Error,
        fs,
        path::{Path, PathBuf},
    };

    use super::DailySynchLog;
    const DATA_PATH: &str = "test/data/datamodel/";
    fn init_database_path(file: &str) -> Result<PathBuf, Box<dyn Error>> {
        let mut path: PathBuf = DATA_PATH.into();
        fs::create_dir_all(&path)?;
        path.push(file);
        if Path::exists(&path) {
            fs::remove_file(&path)?;
        }
        Ok(path)
    }
    #[test]
    fn daily_log_insert() -> Result<(), Box<dyn Error>> {
        let path: PathBuf = init_database_path("daily_log_insert.db")?;
        let secret = hash(b"secret");
        let conn = create_connection(&path, &secret, 1024, false)?;
        initialise_datamodel(&conn)?;
        let source = base64_encode(&hash(b"source"));
        let daily_hash = hash(b"hash").to_vec();

        let log = DailySynchLog {
            source,
            schema: "TEST".to_string(),
            date: now(),
            daily_hash,
            ..Default::default()
        };

        log.write(&conn)?;
        log.write(&conn)?;
        let mut stmt = conn.prepare("SELECT daily_synch_log.* FROM daily_synch_log")?;
        let results = stmt.query_map([], DailySynchLog::from_row())?;
        assert_eq!(1, results.count());
        Ok(())
    }
}
