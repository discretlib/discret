use std::time::SystemTime;

use crate::cryptography::base64_encode;

use super::{edge_table::Edge, node_table::Node, synch_log::DailySynchLog, Error};

use rusqlite::{Connection, OptionalExtension};

pub type Result<T> = std::result::Result<T, Error>;

//Maximum allowed size for a row
pub const MAX_ROW_LENTGH: usize = 32768; //32kb

//Size in byte of a generated database id
pub const DB_ID_SIZE: usize = 16;

//min numbers of char in an id //policy
pub const DB_ID_MIN_SIZE: usize = 22;

//arbritrary choosen max numbers of char in an id
pub const DB_ID_MAX_SIZE: usize = 52;

//arbritrary choosen max numbers of char in a schema
pub const MAX_SCHEMA_SIZE: usize = 22;

pub struct RowFlag {}
impl RowFlag {
    //data is only soft deleted to avoid synchronization conflicts
    pub const DELETED: i8 = 0b0000001;
    //if disabled, a new version will be inserted when updating, keeping the full history.
    pub const KEEP_HISTORY: i8 = 0b0000010;
    //index text and json field
    pub const INDEX_ON_SAVE: i8 = 0b0000100;

    pub fn is(v: i8, f: &i8) -> bool {
        v & f > 0
    }
}

//create base64 encoded id,
//with time on first to improve index locality
pub fn database_timed_id(time: i64, hash: &[u8]) -> String {
    let time = &time.to_be_bytes()[4..];
    let has = &hash[0..DB_ID_SIZE - time.len()];

    let mut whole: [u8; DB_ID_SIZE] = [0; DB_ID_SIZE];
    let (one, two) = whole.split_at_mut(time.len());
    one.copy_from_slice(time);
    two.copy_from_slice(has);

    base64_encode(&whole)
}

pub fn is_valid_id(id: &String) -> bool {
    let v = id.as_bytes().len();
    (DB_ID_MIN_SIZE..DB_ID_MAX_SIZE).contains(&v)
}

pub fn is_valid_schema(schema: &String) -> bool {
    schema.as_bytes().len() <= MAX_SCHEMA_SIZE && !schema.is_empty()
}

pub fn now() -> i64 {
    SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_millis()
        .try_into()
        .unwrap()
}

const SYNCH_LOG_TABLE: &str = "
CREATE TABLE synch_log (
	source TEXT NOT NULL,
	target TEXT NOT NULL,
	schema TEXT NOT NULL,
	source_date INTEGER NOT NULL, 
	cdate INTEGER NOT NULL
) STRICT;

CREATE INDEX synch_log_idx  ON synch_log(source, schema, source_date );";

pub fn is_initialized(conn: &Connection) -> Result<bool> {
    let initialised: Option<String> = conn
        .query_row(
            "SELECT name FROM sqlite_schema WHERE type IN ('table','view') AND name = 'node_sys'",
            [],
            |row| row.get(0),
        )
        .optional()?;
    Ok(initialised.is_some())
}

pub fn initialise_datamodel(conn: &Connection) -> Result<()> {
    if !is_initialized(conn)? {
        conn.execute("BEGIN TRANSACTION", [])?;
        Node::create_table(conn)?;
        Edge::create_table(conn)?;
        DailySynchLog::create_table(conn)?;
        conn.execute("COMMIT", [])?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cryptography::hash;
    #[test]
    fn database_id_test() {
        let time = now();
        let has1 = hash(b"bytes");
        let id1 = database_timed_id(time, &has1);

        let has2 = hash(b"bytes2");
        let id2 = database_timed_id(time, &has2);

        assert_eq!(id1[0..3], id2[0..3]);
        assert_ne!(id1, id2);

        println!("{}", id1.as_bytes().len());
        println!("{}", id2.as_bytes().len());
    }
}
