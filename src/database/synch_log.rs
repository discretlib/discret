use std::collections::HashSet;

use rusqlite::{Connection, Row};

use super::Result;

use super::database_service::{FromRow, Writable};

use super::security_policy::POLICY_GROUP_SCHEMA;

// upon insert node
//      invalidate day from policy group
// upon insert edge
//      invalidate source from policy group
// upon update node
//      invalidate every policy group it references
// upon update edge
//      invalidate source policy group
pub struct DailySynchLog {
    pub policy_group: Vec<u8>,
    pub schema: String,
    pub date: i64,
    pub row_num: i32,
    pub size: i64,
    pub daily_hash: Option<Vec<u8>>,
    pub history_hash: Option<Vec<u8>>,
}
impl DailySynchLog {
    pub fn create_table(conn: &Connection) -> Result<()> {
        conn.execute(
            " 
            CREATE TABLE daily_node_log (
                policy_group BLOB NOT NULL,
                schema TEXT NOT NULL,
                date INTEGER NOT NULL,
                row_num INTEGER,
                size INTEGER,
                daily_hash BLOB,
                history_hash BLOB,
                PRIMARY KEY (policy_group, schema, date)
            ) WITHOUT ROWID, STRICT;
            ",
            [],
        )?;
        conn.execute(
            " 
            CREATE TABLE daily_edge_log (
                policy_group BLOB NOT NULL,
                schema TEXT NOT NULL,
                date INTEGER NOT NULL,
                row_num INTEGER,
                daily_hash BLOB,
                history_hash BLOB,
                PRIMARY KEY (policy_group, schema, date)
            )WITHOUT ROWID, STRICT;
            ",
            [],
        )?;
        Ok(())
    }
}
impl FromRow for DailySynchLog {
    fn from_row() -> fn(&Row) -> std::result::Result<Box<Self>, rusqlite::Error> {
        |row| {
            Ok(Box::new(DailySynchLog {
                policy_group: row.get(0)?,
                schema: row.get(1)?,
                date: row.get(2)?,
                row_num: row.get(3)?,
                size: row.get(4)?,
                daily_hash: row.get(5)?,
                history_hash: row.get(6)?,
            }))
        }
    }
}
impl Writable for DailySynchLog {
    fn write(&self, conn: &Connection) -> Result<()> {
        //unixepoch(Date(?, 'unixepoch'))
        let mut insert_stmt = conn.prepare_cached(
            "INSERT OR REPLACE INTO daily_node_log (policy_group, schema, date, row_num, size, daily_hash, history_hash) 
                            VALUES (?, ?, ?, ?, ?, ?, ?)",
        )?;
        insert_stmt.execute((
            &self.policy_group,
            &self.schema,
            &self.date,
            &self.row_num,
            &self.size,
            &self.daily_hash,
            &self.history_hash,
        ))?;
        Ok(())
    }
}
impl Default for DailySynchLog {
    fn default() -> Self {
        Self {
            policy_group: vec![],
            schema: "".to_string(),
            date: 0,
            row_num: 0,
            size: 0,
            daily_hash: None,
            history_hash: None,
        }
    }
}

// const INVALIDATE_POLICY_QUERY: &str = "
// INSERT INTO daily_node_log(policy_group, schema, date, row_num, size, daily_hash, history_hash)
// SELECT pol_grp.id as policy_group , node.schema as schema, unixepoch(Date(node.mdate/1000, 'unixepoch')) as date, 0 as row_num, 0 as size,NULL as daily_hash,NULL as history_hash
// from node
// JOIN edge ON
//     edge.target = node.id
// JOIN node pol_grp ON
//     pol_grp.id = edge.source
//     AND pol_grp.schema = ?
// WHERE
//     node.id = ?
//     AND node.mdate = ?
// ON CONFLICT (policy_group, schema, date)
// DO UPDATE SET
//     row_num = 0,
//     size = 0,
//     daily_hash = NULL,
//     history_hash = NULL";

const INVALIDATE_NODE_QUERY: &str = "
INSERT INTO daily_node_log(policy_group, schema, date, row_num, size, daily_hash, history_hash) 
SELECT pol_grp.id as policy_group , node.schema as schema, unixepoch(Date(node.mdate/1000, 'unixepoch')) as date, 0 as row_num, 0 as size,NULL as daily_hash,NULL as history_hash
from node 
JOIN edge ON
    edge.source = node.id
JOIN node pol_grp ON
    pol_grp.id = edge.target
    AND pol_grp.schema = ? 
WHERE 
    node.id = ?
    AND node.mdate = ?
ON CONFLICT (policy_group, schema, date)
DO UPDATE SET 
    row_num = 0,
    size = 0,
    daily_hash = NULL,
    history_hash = NULL";

pub fn invalidate_node_log(node_id: &Vec<u8>, date: i64, conn: &Connection) -> Result<()> {
    let mut stmt = conn.prepare_cached(INVALIDATE_NODE_QUERY)?;
    stmt.execute((POLICY_GROUP_SCHEMA, node_id, date))?;
    Ok(())
}

pub struct InvalidateNodeDay {
    days: HashSet<(Vec<u8>, String, i64)>,
}
impl Writable for InvalidateNodeDay {
    fn write(&self, conn: &Connection) -> Result<()> {
        let mut stmt = conn.prepare_cached(
            "INSERT INTO daily_node_log 
                    (policy_group, schema, date, row_num, size, daily_hash, history_hash)
                VALUES 
                    (?, ?,  unixepoch(Date(?/1000, 'unixepoch')), 0 , 0, NULL, NULL)
                ON CONFLICT (policy_group, schema, date)
                DO UPDATE SET
                    row_num = 0,
                    size = 0,
                    daily_hash = NULL,
                    history_hash = NULL",
        )?;
        for (pol_grp, schema, date) in &self.days {
            stmt.execute((pol_grp, schema, date))?;
        }
        Ok(())
    }
}
impl InvalidateNodeDay {
    pub fn new() -> Self {
        Self {
            days: HashSet::new(),
        }
    }
    pub fn add(&mut self, pol_grp: Vec<u8>, schema: String, date: i64) {
        self.days.insert((pol_grp, schema, date));
    }
}

// pub fn refresh_node_log(policy_group: &Vec<u8>, conn: &Connection) {}

// pub fn get_max_node_log(policy_group: &Vec<u8>, schema: &String, conn: &Connection) {}

// pub fn get_log_history(policy_group: &Vec<u8>, schema: &String, conn: &Connection) {}

#[cfg(test)]
mod tests {

    use rusqlite::Connection;

    use crate::{
        cryptography::hash,
        database::{
            database_service::{FromRow, Writable},
            datamodel::{now, prepare_connection},
        },
    };

    use super::DailySynchLog;

    #[test]
    fn daily_log_insert() {
        let conn = Connection::open_in_memory().unwrap();
        prepare_connection(&conn).unwrap();
        let policy_group = hash(b"source").to_vec();
        let daily_hash = Some(hash(b"hash").to_vec());

        let log = DailySynchLog {
            policy_group,
            schema: "TEST".to_string(),
            date: now(),
            daily_hash,
            ..Default::default()
        };

        log.write(&conn).unwrap();
        log.write(&conn).unwrap();
        let mut stmt = conn
            .prepare("SELECT daily_node_log.* FROM daily_node_log")
            .unwrap();
        let results = stmt.query_map([], DailySynchLog::from_row()).unwrap();
        assert_eq!(1, results.count());
    }
}
