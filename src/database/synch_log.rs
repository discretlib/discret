use std::collections::HashSet;

use rusqlite::{CachedStatement, Connection, Row};

use super::Result;

use super::database_service::{FromRow, Writable};

use super::security_policy::{POLICY_GROUP_SCHEMA, POLICY_SCHEMA};

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
            ) WITHOUT ROWID, STRICT
            ",
            [],
        )?;
        conn.execute(
            "CREATE INDEX daily_node_log_inv_idx ON daily_node_log (daily_hash, schema)",
            [],
        )?;

        conn.execute(
            " 
            CREATE TABLE daily_edge_log (
                policy_group BLOB NOT NULL,
                schema TEXT NOT NULL,
                date INTEGER NOT NULL,
                row_num INTEGER,
                size INTEGER,
                daily_hash BLOB,
                history_hash BLOB,
                PRIMARY KEY (policy_group, schema, date)
            )WITHOUT ROWID, STRICT
            ",
            [],
        )?;

        conn.execute(
            "CREATE INDEX daily_edge_log_inv_idx ON daily_edge_log (daily_hash, schema)",
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

pub fn invalidate_updated_node_log(node_id: &Vec<u8>, date: i64, conn: &Connection) -> Result<()> {
    let mut stmt = conn.prepare_cached("
    INSERT INTO daily_node_log(policy_group, schema, date, row_num, size, daily_hash, history_hash) 
    SELECT pol_grp.id as policy_group , node_sys.schema as schema, unixepoch(Date(node_sys.mdate/1000, 'unixepoch')) as date, 0 as row_num, 0 as size,NULL as daily_hash,NULL as history_hash
    from node_sys 
    JOIN edge_all ON
        edge_all.source = node_sys.id
    JOIN node_sys pol_grp ON
        pol_grp.id = edge_all.target
        AND pol_grp.schema = ? 
    WHERE 
        node_sys.id = ?
        AND node_sys.mdate = ?
    ON CONFLICT (policy_group, schema, date)
    DO UPDATE SET 
        row_num = 0,
        size = 0,
        daily_hash = NULL,
        history_hash = NULL")?;
    stmt.execute((POLICY_GROUP_SCHEMA, node_id, date))?;
    Ok(())
}

pub fn invalidate_updated_edge_log(
    source: &Vec<u8>,
    target: &Vec<u8>,
    date: i64,
    conn: &Connection,
) -> Result<()> {
    let mut stmt = conn.prepare_cached("
    INSERT INTO daily_edge_log(policy_group, schema, date, row_num, size, daily_hash, history_hash) 
    SELECT pol_grp.id as policy_group , source_node.schema as schema, unixepoch(Date(to_update.date/1000, 'unixepoch')) as date, 0 as row_num, 0 as size,NULL as daily_hash,NULL as history_hash
    from edge_all to_update 
    JOIN node_sys source_node ON
        source_node.id = to_update.source
    JOIN edge_all policy_edge ON
        policy_edge.source = source_node.id
    JOIN node_sys pol_grp ON
        pol_grp.id = policy_edge.target
        AND pol_grp.schema = ? 
    WHERE 
            to_update.source = ?
        AND to_update.target = ?
        AND to_update.date = ?
    ON CONFLICT (policy_group, schema, date)
    DO UPDATE SET 
        row_num = 0,
        size = 0,
        daily_hash = NULL,
        history_hash = NULL")?;
    stmt.execute((POLICY_GROUP_SCHEMA, source, target, date))?;

    Ok(())
}

pub struct InvalidateNodeLog {
    days: HashSet<(Vec<u8>, String, i64)>,
}
impl Writable for InvalidateNodeLog {
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
impl Default for InvalidateNodeLog {
    fn default() -> Self {
        Self::new()
    }
}
impl InvalidateNodeLog {
    pub fn new() -> Self {
        Self {
            days: HashSet::new(),
        }
    }
    pub fn add(&mut self, pol_grp: Vec<u8>, schema: String, date: i64) {
        self.days.insert((pol_grp, schema, date));
    }
}

pub struct InvalidateEdgeLog {
    days: HashSet<(Vec<u8>, String, i64)>,
}
impl Writable for InvalidateEdgeLog {
    fn write(&self, conn: &Connection) -> Result<()> {
        let mut stmt = conn.prepare_cached(
            "INSERT INTO daily_edge_log 
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
impl Default for InvalidateEdgeLog {
    fn default() -> Self {
        InvalidateEdgeLog::new()
    }
}
impl InvalidateEdgeLog {
    pub fn new() -> Self {
        Self {
            days: HashSet::new(),
        }
    }
    pub fn add(&mut self, pol_grp: Vec<u8>, schema: String, date: i64) {
        self.days.insert((pol_grp, schema, date));
    }
}

pub struct UpdateDailyNodeLog {
    pub policy_group: Vec<u8>,
}
impl Writable for UpdateDailyNodeLog {
    fn write(&self, conn: &Connection) -> Result<()> {
        let mut standard_node_smt = conn.prepare_cached(
            "
                WITH daily_log as NOT MATERIALIZED (
                    SELECT policy_group, schema, min(date) as min_date, history_hash
                    FROM  daily_node_log 
                    WHERE daily_hash IS NULL 
                          AND schema NOT IN (?, ?)
                          AND policy_group = ?
                    GROUP BY policy_group, schema 
                )  
                SELECT  
                    edge_all.target , 
                    node_sys.schema ,
                    unixepoch(Date(node_sys.mdate/1000, 'unixepoch')) as date,
                    node_sys.size, 
                    node_sys.signature,
                    daily_log.history_hash	
                FROM
                    daily_log
                    CROSS  JOIN edge_all ON edge_all.target =  daily_log.policy_group
                    CROSS  JOIN node_sys ON 
                        node_sys.id =  edge_all.source
                        AND node_sys.schema = daily_log.schema
                        AND (unixepoch(Date(node_sys.mdate/1000, 'unixepoch')) >= daily_log.min_date
                            OR
                            unixepoch(Date(node_sys.mdate/1000, 'unixepoch')) >= (
                                    SELECT max(date) 
                                    FROM daily_node_log 
                                    WHERE date < daily_log.min_date 
                                    AND policy_group = daily_log.policy_group
                                    AND schema = daily_log.schema)
                            )
                ORDER BY edge_all.target, node_sys.schema, node_sys.mdate,	node_sys.signature
                   ",
        )?;
        let rows =
            standard_node_smt.query((POLICY_GROUP_SCHEMA, POLICY_SCHEMA, &self.policy_group))?;

        let mut update_stmt = conn.prepare_cached(
            "
                UPDATE daily_node_log
                SET
                    row_num = ? ,
                    size = ? ,
                    daily_hash = ? ,
                    history_hash = ?
                WHERE
                    policy_group = ?
                    AND schema = ?
                    AND date = ?
                ",
        )?;

        update_daily_log(rows, &mut update_stmt)?;

        let mut policy_group_stmt = conn.prepare_cached(
            "
                WITH daily_log as NOT MATERIALIZED (
                    SELECT policy_group, schema, min(date) as min_date, history_hash
                    FROM  daily_node_log 
                    WHERE daily_hash IS NULL 
                          AND schema = ?
                          AND policy_group = ?
                    GROUP BY policy_group, schema 
                )  
                SELECT  
                    node_sys.id, 
                    node_sys.schema ,
                    unixepoch(Date(node_sys.mdate/1000, 'unixepoch')) as date,
                    node_sys.size, 
                    node_sys.signature,
                    daily_log.history_hash	
                FROM
                    daily_log
                    CROSS  JOIN node_sys  ON 
                        node_sys.id =  daily_log.policy_group
                        AND (unixepoch(Date(node_sys.mdate/1000, 'unixepoch')) >= daily_log.min_date
                            OR
                            unixepoch(Date(node_sys.mdate/1000, 'unixepoch')) >= (
                                    SELECT max(date) 
                                    FROM daily_node_log 
                                    WHERE date < daily_log.min_date 
                                    AND policy_group = daily_log.policy_group
                                    AND schema = daily_log.schema)
                            )
                ORDER BY node_sys.id, node_sys.schema, node_sys.mdate,	node_sys.signature
                   ",
        )?;
        let rows = policy_group_stmt.query((POLICY_GROUP_SCHEMA, &self.policy_group))?;
        update_daily_log(rows, &mut update_stmt)?;

        let mut policy_stmt = conn.prepare_cached(
            "
            WITH daily_log as NOT MATERIALIZED (
                SELECT policy_group, schema, min(date) as min_date, history_hash
                FROM  daily_node_log 
                WHERE daily_hash IS NULL 
                      AND schema = ?
                      AND policy_group = ?
                GROUP BY policy_group, schema 
            )  
            SELECT  
                edge_all.target , 
                node_sys.schema ,
                unixepoch(Date(node_sys.mdate/1000, 'unixepoch')) as date,
                node_sys.size, 
                node_sys.signature,
                daily_log.history_hash	
            FROM
                daily_log
                CROSS  JOIN edge_all ON edge_all.source =  daily_log.policy_group
                CROSS  JOIN node_sys ON 
                    node_sys.id =  edge_all.target
                    AND node_sys.schema = daily_log.schema
                    AND (unixepoch(Date(node_sys.mdate/1000, 'unixepoch')) >= daily_log.min_date
                        OR
                        unixepoch(Date(node_sys.mdate/1000, 'unixepoch')) >= (
                                SELECT max(date) 
                                FROM daily_node_log 
                                WHERE date < daily_log.min_date 
                                AND policy_group = daily_log.policy_group
                                AND schema = daily_log.schema)
                        )
            ORDER BY edge_all.target, node_sys.schema, node_sys.mdate,	node_sys.signature
               ",
        )?;
        let rows = policy_stmt.query((POLICY_SCHEMA, &self.policy_group))?;
        update_daily_log(rows, &mut update_stmt)?;

        Ok(())
    }
}

fn update_daily_log(mut rows: rusqlite::Rows, update_stmt: &mut CachedStatement) -> Result<()> {
    let mut hasher = blake3::Hasher::new();
    let mut last_policy: Vec<u8> = vec![];
    let mut last_schema = "".to_string();
    let mut last_date: i64 = -1;
    let mut last_hash: Vec<u8> = vec![];
    let mut last_size = 0;
    let mut count = 0;
    while let Some(row) = rows.next()? {
        let policy_group: Vec<u8> = row.get(0)?;
        let schema: String = row.get(1)?;
        let date: i64 = row.get(2)?;
        let size: i64 = row.get(3)?;
        let signature: Vec<u8> = row.get(4)?;
        let history: Option<Vec<u8>> = row.get(5)?;

        if policy_group.eq(&last_policy) && schema.eq(&last_schema) && date.eq(&last_date) {
            if history.is_none() {
                hasher.update(&signature);
                last_size += size;
                count += 1;
            }
        } else {
            let empty_history: bool = history.is_none();
            match history {
                Some(his) => last_hash = his,
                None => {
                    let hash = hasher.finalize().as_bytes().to_vec();
                    let history_hash = if last_hash.is_empty() {
                        hash.clone()
                    } else {
                        hasher.update(&last_hash);
                        let hash = hasher.finalize();
                        hash.as_bytes().to_vec()
                    };
                    if count != 0 {
                        update_stmt.execute((
                            &count,
                            &last_size,
                            &hash,
                            &history_hash,
                            &last_policy,
                            &last_schema,
                            &last_date,
                        ))?;
                    };
                    last_hash = history_hash;
                }
            }
            if !policy_group.eq(&last_policy) || !schema.eq(&last_schema) {
                last_hash = vec![];
            }
            hasher.reset();
            last_size = 0;
            count = 0;
            last_policy = policy_group;
            last_schema = schema;
            last_date = date;

            if empty_history {
                hasher.update(&signature);
                last_size += size;
                count += 1;
            }
        }
    }
    if count != 0 {
        let hash = hasher.finalize().as_bytes().to_vec();
        let history_hash = if last_hash.is_empty() {
            hash.to_vec()
        } else {
            hasher.update(&last_hash);
            let hash = hasher.finalize();
            hash.as_bytes().to_vec()
        };

        update_stmt.execute((
            &count,
            &last_size,
            &hash,
            &history_hash,
            &last_policy,
            &last_schema,
            &last_date,
        ))?;
    }
    Ok(())
}

pub struct UpdateDailyEdgeLog {
    pub policy_group: Vec<u8>,
}
impl Writable for UpdateDailyEdgeLog {
    fn write(&self, conn: &Connection) -> Result<()> {
        let mut update_stmt = conn.prepare_cached(
            "
                UPDATE daily_edge_log
                SET
                    row_num = ? ,
                    size = ? ,
                    daily_hash = ? ,
                    history_hash = ?
                WHERE
                    policy_group = ?
                    AND schema = ?
                    AND date = ?
                ",
        )?;

        let mut standard_edge_smt = conn.prepare_cached(
            "
            WITH daily_log as NOT MATERIALIZED (
                SELECT policy_group, schema, min(date) as min_date, history_hash
                FROM  daily_edge_log 
                WHERE daily_hash IS NULL 
                      AND schema NOT IN  (?, ?)
                      AND policy_group = ?
                GROUP BY policy_group, schema 
            )  
            SELECT 	pol_edge.target , 
                node_sys.schema ,
                unixepoch(Date(edges.date/1000, 'unixepoch')) as date,
                edges.size, 
                edges.signature,
                daily_log.history_hash	
            FROM
            daily_log
            CROSS JOIN edge_all pol_edge ON pol_edge.target = daily_log.policy_group 
            CROSS JOIN node_sys ON 
                node_sys.id =  pol_edge.source
                AND node_sys.schema = daily_log.schema
            CROSS JOIN edge_all edges ON   
                edges.source = node_sys.id
                AND (
                    unixepoch(Date(edges.date/1000, 'unixepoch')) >= daily_log.min_date
                    OR
                    unixepoch(Date(edges.date/1000, 'unixepoch')) >= (
                            SELECT max(date) 
                            FROM daily_node_log 
                            WHERE date < daily_log.min_date 
                            AND policy_group = daily_log.policy_group
                            AND schema = daily_log.schema)
                    )
            ORDER BY pol_edge.target, node_sys.schema, edges.date,	edges.signature
                   ",
        )?;
        let rows =
            standard_edge_smt.query((POLICY_GROUP_SCHEMA, POLICY_SCHEMA, &self.policy_group))?;
        update_daily_log(rows, &mut update_stmt)?;

        let mut policy_group_smt = conn.prepare_cached(
            "
            WITH daily_log as NOT MATERIALIZED (
                SELECT policy_group, schema, min(date) as min_date, history_hash
                FROM  daily_edge_log 
                WHERE daily_hash IS NULL 
                      AND schema = ?
                      AND policy_group = ?
                GROUP BY policy_group, schema 
            )  
            SELECT 	node_sys.id , 
                node_sys.schema ,
                unixepoch(Date(edges.date/1000, 'unixepoch')) as date,
                edges.size, 
                edges.signature,
                daily_log.history_hash	
            FROM
            daily_log
            CROSS JOIN node_sys ON 
                node_sys.id =  daily_log.policy_group
                AND node_sys.schema = daily_log.schema
            CROSS JOIN edge_all edges ON   
                edges.source = node_sys.id
                AND (
                    unixepoch(Date(edges.date/1000, 'unixepoch')) >= daily_log.min_date
                    OR
                    unixepoch(Date(edges.date/1000, 'unixepoch')) >= (
                            SELECT max(date) 
                            FROM daily_node_log 
                            WHERE date < daily_log.min_date 
                            AND policy_group = daily_log.policy_group
                            AND schema = daily_log.schema)
                    )
            ORDER BY node_sys.id, node_sys.schema, edges.date,	edges.signature
                   ",
        )?;
        let rows = policy_group_smt.query((POLICY_GROUP_SCHEMA, &self.policy_group))?;
        update_daily_log(rows, &mut update_stmt)?;

        let mut policy_smt = conn.prepare_cached(
            "
            WITH daily_log as NOT MATERIALIZED (
                SELECT policy_group, schema, min(date) as min_date, history_hash
                FROM  daily_edge_log 
                WHERE daily_hash IS NULL 
                      AND schema = ?
                      AND policy_group = ?
                GROUP BY policy_group, schema 
            )  
            SELECT 	pol_edge.target , 
                node_sys.schema ,
                unixepoch(Date(edges.date/1000, 'unixepoch')) as date,
                edges.size, 
                edges.signature,
                daily_log.history_hash	
            FROM
            daily_log
            CROSS JOIN edge_all pol_edge ON pol_edge.source = daily_log.policy_group 
            CROSS JOIN node_sys ON 
                node_sys.id =  pol_edge.target
                AND node_sys.schema = daily_log.schema
            CROSS JOIN edge_all edges ON   
                edges.source = node_sys.id
                AND (
                    unixepoch(Date(edges.date/1000, 'unixepoch')) >= daily_log.min_date
                    OR
                    unixepoch(Date(edges.date/1000, 'unixepoch')) >= (
                            SELECT max(date) 
                            FROM daily_node_log 
                            WHERE date < daily_log.min_date 
                            AND policy_group = daily_log.policy_group
                            AND schema = daily_log.schema)
                    )
            ORDER BY pol_edge.target, node_sys.schema, edges.date,	edges.signature
                   ",
        )?;
        let rows = policy_smt.query((POLICY_SCHEMA, &self.policy_group))?;
        update_daily_log(rows, &mut update_stmt)?;

        Ok(())
    }
}

#[cfg(test)]
mod tests {}
