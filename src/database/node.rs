use std::{
    collections::{HashMap, HashSet},
    hash::Hash,
};

use super::{
    daily_log::DailyMutations,
    sqlite_database::{RowMappingFn, Writeable},
    Error, Result, VEC_OVERHEAD,
};
use crate::{
    date_utils::{date, date_next_day, now},
    security::{import_verifying_key, new_uid, SigningKey, Uid},
};

use rusqlite::{params_from_iter, Connection, OptionalExtension};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use tokio::sync::mpsc;

impl Default for Node {
    fn default() -> Self {
        let date = now();
        Self {
            id: new_uid(),
            room_id: None,
            cdate: date,
            mdate: date,
            _entity: "".to_string(),
            _json: None,
            _binary: None,
            verifying_key: vec![],
            _signature: vec![],
            _local_id: None,
        }
    }
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct Node {
    pub id: Uid,
    pub room_id: Option<Uid>,
    pub cdate: i64,
    pub mdate: i64,
    pub _entity: String,
    pub _json: Option<String>,
    pub _binary: Option<Vec<u8>>,
    pub verifying_key: Vec<u8>,
    pub _signature: Vec<u8>,

    //_local_id stores the rowid of the Node for update purpose.
    // This id only make sense to the local sqlite database.
    // It will not be transmitted during synchronisation
    #[serde(skip)]
    pub _local_id: Option<i64>,
}
impl Node {
    ///
    /// Creates the required tables and indexes
    ///
    /// _node_fts is the table that provides the full text search functionality
    ///
    /// _nodes keeps its rowid because it is required for the full text seach.
    ///
    pub fn create_tables(conn: &Connection) -> Result<()> {
        //system table stores compressed text and json
        conn.execute(
            "
        CREATE TABLE _node (
            id BLOB NOT NULL,
            room_id BLOB,
            cdate INTEGER  NOT NULL,
            mdate INTEGER  NOT NULL,
            _entity TEXT  NOT NULL,
            _json TEXT,
            _binary BLOB,
            verifying_key BLOB NOT NULL,
            _signature BLOB NOT NULL
        ) STRICT",
            [],
        )?;

        conn.execute(
            "CREATE  INDEX _node_id__entity ON _node (id, _entity, mdate)",
            [],
        )?;

        conn.execute(
            "CREATE INDEX _node_entity ON _node (_entity, room_id, mdate)",
            [],
        )?;

        //the full text search virtual table
        conn.execute(
            "CREATE VIRTUAL TABLE _node_fts USING fts5(text, content='' , tokenize='trigram', detail=full)",
            [],
        )?;

        // conn.execute(
        //     "CREATE VIRTUAL TABLE _node_fts USING fts5(text, content='' , prefix='2,3' , detail=none)",
        //     [],
        // )?;

        //log the deletions for synchronisation
        conn.execute(
            "CREATE TABLE _node_deletion_log (
            room_id BLOB,
            id BLOB,
            mdate INTEGER,
            entity TEXT,
            deletion_date INTEGER,
            verifying_key BLOB NOT NULL,
            signature BLOB NOT NULL,
            PRIMARY KEY(room_id, deletion_date, id, entity )
        ) WITHOUT ROWID, STRICT",
            [],
        )?;

        Ok(())
    }

    pub fn eq(&self, node: &Node) -> bool {
        let room_id = match (&self.room_id, &node.room_id) {
            (Some(a), Some(b)) => a.eq(b),
            (None, None) => true,
            _ => false,
        };

        let _json = match (&self._json, &node._json) {
            (Some(a), Some(b)) => a.eq(b),
            (None, None) => true,
            _ => false,
        };

        let _binary = match (&self._binary, &node._binary) {
            (Some(a), Some(b)) => a.eq(b),
            (None, None) => true,
            _ => false,
        };

        room_id
            && _json
            && _binary
            && self.id.eq(&node.id)
            && self.cdate.eq(&node.cdate)
            && self.mdate.eq(&node.mdate)
            && self._entity.eq(&node._entity)
            && self.verifying_key.eq(&node.verifying_key)
    }

    pub fn hash(&self) -> Result<blake3::Hash> {
        let mut hasher = blake3::Hasher::new();
        hasher.update(&self.id);
        if let Some(rid) = &self.room_id {
            hasher.update(rid);
        }
        hasher.update(&self.cdate.to_le_bytes());
        hasher.update(&self.mdate.to_le_bytes());
        hasher.update(self._entity.as_bytes());

        if let Some(v) = &self._json {
            let serialized = serde_json::to_string(v)?;
            hasher.update(serialized.as_bytes());
        }

        if let Some(v) = &self._binary {
            hasher.update(v);
        }

        hasher.update(&self.verifying_key);
        Ok(hasher.finalize())
    }

    ///
    /// check the node's signature
    ///
    pub fn verify(&self) -> Result<()> {
        if self._entity.is_empty() {
            return Err(Error::EmptyNodeEntity());
        }

        //ensure that the Json field is an Object field
        if let Some(v) = &self._json {
            let value: Value = serde_json::from_str(v)?;
            if value.as_object().is_none() {
                return Err(Error::InvalidNode(String::from(
                    "json field is not an Object",
                )));
            }
        }
        let hash = self.hash()?;

        let pub_key = import_verifying_key(&self.verifying_key)?;
        pub_key.verify(hash.as_bytes(), &self._signature)?;

        Ok(())
    }

    ///
    /// sign the node after performing some checks
    ///
    pub fn sign(&mut self, signing_key: &impl SigningKey) -> Result<()> {
        self.verifying_key = signing_key.export_verifying_key();

        if self._entity.is_empty() {
            return Err(Error::EmptyNodeEntity());
        }
        //ensure that the Json field is an Object field
        if let Some(v) = &self._json {
            let value: Value = serde_json::from_str(v)?;
            if value.as_object().is_none() {
                return Err(Error::InvalidNode(String::from(
                    "json field is not an Object",
                )));
            }
        }

        let hash = self.hash()?;
        let signature = signing_key.sign(hash.as_bytes());
        self._signature = signature;

        Ok(())
    }

    ///
    /// Convert sql query result into a Node
    ///
    pub const NODE_MAPPING: RowMappingFn<Self> = |row| {
        Ok(Box::new(Node {
            id: row.get(0)?,
            room_id: row.get(1)?,
            cdate: row.get(2)?,
            mdate: row.get(3)?,
            _entity: row.get(4)?,
            _json: row.get(5)?,
            _binary: row.get(6)?,
            verifying_key: row.get(7)?,
            _signature: row.get(8)?,
            _local_id: row.get(9)?,
        }))
    };

    ///
    /// Retrieve a node using its primary key
    ///
    pub fn get_with_entity(
        id: &Uid,
        entity: &str,
        conn: &Connection,
    ) -> std::result::Result<Option<Box<Node>>, rusqlite::Error> {
        const QUERY: &str = "
            SELECT id , room_id, cdate, mdate, _entity,_json, _binary, verifying_key, _signature, rowid  
            FROM _node 
            WHERE 
            id = ? AND 
            _entity = ?";
        let mut get_stmt = conn.prepare_cached(QUERY)?;
        let node = get_stmt
            .query_row((id, entity), Self::NODE_MAPPING)
            .optional()?;
        Ok(node)
    }

    pub const NODE_ROOM_QUERY: &'static str = "
    SELECT id , room_id, cdate, mdate, _entity,_json, _binary, verifying_key, _signature, rowid  
    FROM _node 
    WHERE 
        id = ? AND 
        room_id = ? AND  
        _entity = ?";
    ///
    /// Retrieve a node using its primary key
    ///
    pub fn get_in_room(
        id: &Uid,
        room_id: &Uid,
        entity: &str,
        conn: &Connection,
    ) -> std::result::Result<Option<Box<Node>>, rusqlite::Error> {
        let mut get_stmt = conn.prepare_cached(Self::NODE_ROOM_QUERY)?;
        let node = get_stmt
            .query_row((id, room_id, entity), Self::NODE_MAPPING)
            .optional()?;
        Ok(node)
    }

    ///
    /// Low level method to delete a node
    /// This method is intended to be used in the write thread wich perform operations in larges batches.
    /// This method does not check for data integrity to avoid any errors that would cause the rollback of a potentially large number of write queries
    ///
    /// Nodes are soft deleted first. Upon deletion they are updated by prepending '$' to the _entity field field value.
    ///
    /// Deleting an allready deleted node wil result in an hard deletion
    /// Hard deletions are not synchronized
    ///
    pub fn delete(id: &Uid, conn: &Connection) -> std::result::Result<(), rusqlite::Error> {
        let mut delete_stmt = conn.prepare_cached("DELETE FROM _node WHERE id=? ")?;
        delete_stmt.execute([id])?;
        Ok(())
    }

    ///
    /// Verify the existence of a specific Node
    ///
    ///
    pub fn exist(id: &Uid, entity: &str, conn: &Connection) -> Result<bool> {
        let mut exists_stmt =
            conn.prepare_cached("SELECT 1 FROM _node WHERE id = ? AND _entity = ?")?;
        let node: Option<i64> = exists_stmt
            .query_row((id, entity), |row| row.get(0))
            .optional()?;

        Ok(node.is_some())
    }

    ///
    /// Intended to be used in the GraphDatase insert thread.
    /// There is only one insert thread, so we only do the minimal amount of query to avoid any overhead.
    /// The parameters: rowid, previous_fts are retrieved in a select thread
    ///
    pub fn write(
        &mut self,
        conn: &Connection,
        index: bool,
        old_fts_str: &Option<String>,
        node_fts_str: &Option<String>,
    ) -> std::result::Result<(), rusqlite::Error> {
        static UPDATE_FTS_QUERY: &str = "INSERT INTO _node_fts (rowid, text) VALUES (?, ?)";
        if let Some(id) = self._local_id {
            if index {
                if let Some(previous) = old_fts_str {
                    let mut delete_fts_stmt = conn.prepare_cached(
                        "INSERT INTO _node_fts (_node_fts, rowid, text) VALUES('delete', ?, ?)",
                    )?;
                    delete_fts_stmt.execute((id, previous))?;
                }

                if let Some(current) = node_fts_str {
                    let mut insert_fts_stmt = conn.prepare_cached(UPDATE_FTS_QUERY)?;
                    insert_fts_stmt.execute((id, current))?;
                }
            }

            let mut update_node_stmt = conn.prepare_cached(
                "
            UPDATE _node SET 
                id = ?,
                room_id = ?,
                cdate = ?,
                mdate = ?,
                _entity = ?,
                _json = ?,
                _binary = ?,
                verifying_key = ?,
                _signature = ?
            WHERE
                rowid = ? ",
            )?;

            update_node_stmt.execute((
                &self.id,
                &self.room_id,
                &self.cdate,
                &self.mdate,
                &self._entity,
                &self._json,
                &self._binary,
                &self.verifying_key,
                &self._signature,
                id,
            ))?;
        } else {
            let mut insert_stmt = conn.prepare_cached(
                "INSERT INTO _node ( 
                    id,
                    room_id,
                    cdate,
                    mdate,
                    _entity,
                    _json,
                    _binary,
                    verifying_key,
                    _signature
                ) VALUES (
                    ?, ?, ?, ?, ?, ?, ?, ?, ?
                )",
            )?;
            let rowid = insert_stmt.insert((
                &self.id,
                &self.room_id,
                &self.cdate,
                &self.mdate,
                &self._entity,
                &self._json,
                &self._binary,
                &self.verifying_key,
                &self._signature,
            ))?;
            self._local_id = Some(rowid);
            if index {
                if let Some(current) = node_fts_str {
                    let mut insert_fts_stmt = conn.prepare_cached(UPDATE_FTS_QUERY)?;
                    insert_fts_stmt.execute((rowid, current))?;
                }
            }
        }
        Ok(())
    }

    //
    // retrieve all node id for a room at a specific date
    // used for synchonisation
    //
    pub fn get_daily_nodes_for_room(
        room_id: &Uid,
        entity: String,
        day: i64,
        batch_size: usize,
        sender: &mpsc::Sender<Result<HashSet<NodeIdentifier>>>,
        conn: &Connection,
    ) -> Result<()> {
        let query = "SELECT id, mdate, _signature
            FROM _node 
            WHERE 
                room_id = ? AND
                _entity = ? AND
                mdate >= ? AND mdate < ? 
            ORDER BY mdate DESC";
        let mut stmt = conn.prepare_cached(query)?;

        let mut rows = stmt.query((room_id, entity, date(day), date_next_day(day)))?;
        let mut res = HashSet::new();
        let mut len = 0;
        while let Some(row) = rows.next()? {
            let node = NodeIdentifier {
                id: row.get(0)?,
                mdate: row.get(1)?,
                signature: row.get(2)?,
            };

            let size = bincode::serialized_size(&node)?;
            let insert_len = len + size + VEC_OVERHEAD;
            if insert_len > batch_size as u64 {
                let ready = res;
                res = HashSet::new();
                len = 0;
                let s = sender.blocking_send(Ok(ready));
                if s.is_err() {
                    break;
                }
            } else {
                len = insert_len;
            }

            res.insert(node);
        }
        if !res.is_empty() {
            let _ = sender.blocking_send(Ok(res));
        }
        Ok(())
    }

    //
    // Filter the node id set by removing unwanted nodes
    // remaining id will be requested during synchonisation
    // the set is provided by the get_ids_for_room_at method
    //
    pub fn filter_existing(
        node_ids: &mut HashSet<NodeIdentifier>,
        conn: &Connection,
    ) -> Result<Vec<NodeToInsert>> {
        let it = &mut node_ids.iter().peekable();
        let mut q = String::new();
        let mut ids = Vec::new();
        while let Some(node) = it.next() {
            q.push('?');
            if it.peek().is_some() {
                q.push(',');
            }
            ids.push(&node.id);
        }

        let query = format!("
        SELECT id , room_id, cdate, mdate, _entity,_json, _binary, verifying_key, _signature, rowid  
        FROM _node 
        WHERE 
         id in ({}) ",
            q,);

        let mut stmt = conn.prepare(&query)?;
        let mut rows = stmt.query(params_from_iter(ids.iter()))?;

        let mut result = Vec::new();
        while let Some(row) = rows.next()? {
            let node = Node {
                id: row.get(0)?,
                room_id: row.get(1)?,
                cdate: row.get(2)?,
                mdate: row.get(3)?,
                _entity: row.get(4)?,
                _json: row.get(5)?,
                _binary: row.get(6)?,
                verifying_key: row.get(7)?,
                _signature: row.get(8)?,
                _local_id: row.get(9)?,
            };

            let existing = NodeIdentifier {
                id: node.id,
                mdate: node.mdate,
                signature: node._signature,
            };

            if let Some(new) = node_ids.get(&existing) {
                //remove the incoming node if it is older to that the existing one
                if new.mdate < existing.mdate {
                    node_ids.remove(&existing);
                } else
                //Removes the incoming node if
                //  mdate are equals AND
                //      signature is lower than the existing one: arbitrary heuristic to handle the unlucky case of two updates at the same millisecond
                //      OR signature are equals: no need to update
                if (new.mdate.eq(&existing.mdate)) && (new.signature <= existing.signature) {
                    node_ids.remove(&existing);
                } else {
                    let node_id = node_ids.take(&existing).unwrap();

                    let old_fts = if let Some(json_str) = node._json {
                        let json: serde_json::Value = serde_json::from_str(&json_str)?;
                        let mut old_tfs = String::new();
                        extract_json(&json, &mut old_tfs)?;
                        Some(old_tfs)
                    } else {
                        None
                    };

                    let node_to_insert = NodeToInsert {
                        id: node_id.id,
                        node: None,
                        entity_name: None,
                        index: false,
                        old_local_id: node._local_id,
                        old_room_id: node.room_id,
                        old_mdate: node.mdate,
                        old_verifying_key: Some(node.verifying_key),
                        old_fts_str: old_fts,
                        node_fts_str: None,
                    };

                    result.push(node_to_insert);
                }
            }
        }

        for node_id in node_ids.drain() {
            let node_to_insert = NodeToInsert {
                id: node_id.id,
                node: None,
                entity_name: None,
                index: false,
                old_local_id: None,
                old_room_id: None,
                old_mdate: 0,
                old_verifying_key: None,
                old_fts_str: None,
                node_fts_str: None,
            };

            result.push(node_to_insert);
        }

        Ok(result)
    }

    pub fn filtered_by_room(
        room_id: &Uid,
        node_ids: Vec<Uid>,
        batch_size: usize,
        sender: &mpsc::Sender<Result<Vec<Node>>>,
        conn: &Connection,
    ) -> Result<()> {
        let it = &mut node_ids.iter().peekable();
        let mut q = String::new();
        while let Some(_) = it.next() {
            q.push('?');
            if it.peek().is_some() {
                q.push(',');
            }
        }

        let query = format!(
            "
        SELECT 
            id, room_id, cdate, mdate, _entity, _json, _binary, verifying_key, _signature, rowid
        FROM _node
        WHERE 
            id in ({}) 
        ",
            q
        );

        let mut stmt = conn.prepare(&query)?;
        let mut rows = stmt.query(params_from_iter(node_ids.iter()))?;

        let mut len = 0;
        let mut res: Vec<Node> = Vec::new();
        while let Some(row) = rows.next()? {
            let id: Uid = row.get(0)?;
            let db_room_id: Option<Uid> = row.get(1)?;
            match &db_room_id {
                Some(rid) => {
                    if !rid.eq(room_id) {
                        continue;
                    }
                }
                None => {
                    continue;
                }
            }
            let node = Node {
                id: id,
                room_id: db_room_id,
                cdate: row.get(2)?,
                mdate: row.get(3)?,
                _entity: row.get(4)?,
                _json: row.get(5)?,
                _binary: row.get(6)?,
                verifying_key: row.get(7)?,
                _signature: row.get(8)?,
                _local_id: row.get(9)?,
            };
            let size = bincode::serialized_size(&node)?;
            let insert_len = len + size + VEC_OVERHEAD;

            if insert_len > batch_size as u64 {
                let ready = res;
                res = Vec::new();
                len = 0;
                let s = sender.blocking_send(Ok(ready));
                if s.is_err() {
                    break;
                }
            } else {
                len = insert_len;
            }
            res.push(node);
        }
        if !res.is_empty() {
            let _ = sender.blocking_send(Ok(res));
        }
        Ok(())
    }
}
impl Writeable for Node {
    fn write(&mut self, conn: &Connection) -> std::result::Result<(), rusqlite::Error> {
        if let Some(id) = self._local_id {
            let mut update_node_stmt = conn.prepare_cached(
                "
            UPDATE _node SET 
                id = ?,
                room_id = ?,
                cdate = ?,
                mdate = ?,
                _entity = ?,
                _json = ?,
                _binary = ?,
                verifying_key = ?,
                _signature = ?
            WHERE
                rowid = ? ",
            )?;

            update_node_stmt.execute((
                &self.id,
                &self.room_id,
                &self.cdate,
                &self.mdate,
                &self._entity,
                &self._json,
                &self._binary,
                &self.verifying_key,
                &self._signature,
                id,
            ))?;
        } else {
            let mut insert_stmt = conn.prepare_cached(
                "INSERT INTO _node ( 
                    id,
                    room_id,
                    cdate,
                    mdate,
                    _entity,
                    _json,
                    _binary,
                    verifying_key,
                    _signature
                ) VALUES (
                    ?, ?, ?, ?, ?, ?, ?, ?, ?
                )",
            )?;
            let rowid = insert_stmt.insert((
                &self.id,
                &self.room_id,
                &self.cdate,
                &self.mdate,
                &self._entity,
                &self._json,
                &self._binary,
                &self.verifying_key,
                &self._signature,
            ))?;
            self._local_id = Some(rowid);
        }
        Ok(())
    }
}
#[derive(Serialize, Deserialize, Debug)]
pub struct NodeIdentifier {
    pub id: Uid,
    pub mdate: i64,
    pub signature: Vec<u8>,
}
impl Eq for NodeIdentifier {}
impl PartialEq for NodeIdentifier {
    fn eq(&self, other: &Self) -> bool {
        self.id == other.id
    }
}
impl Hash for NodeIdentifier {
    fn hash<H: std::hash::Hasher>(&self, state: &mut H) {
        self.id.hash(state);
    }
}

///
/// data structure that will gather all information required to properly insert a node
/// used during synchronisation
///
#[derive(Default)]
pub struct NodeToInsert {
    pub id: Uid,
    pub node: Option<Node>,
    pub entity_name: Option<String>,
    pub index: bool,
    pub old_room_id: Option<Uid>,
    pub old_mdate: i64,
    pub old_verifying_key: Option<Vec<u8>>,
    pub old_local_id: Option<i64>,
    pub old_fts_str: Option<String>,
    pub node_fts_str: Option<String>,
}
impl NodeToInsert {
    pub fn update_daily_logs(&self, daily_log: &mut DailyMutations) {
        if self.node.is_none() {
            return;
        }
        let node = self.node.as_ref().unwrap();

        if let Some(room_id) = &node.room_id {
            if let Some(old_id) = &self.old_room_id {
                if !room_id.eq(old_id) {
                    daily_log.set_need_update(old_id.clone(), &node._entity, self.old_mdate);
                }
            }
            daily_log.set_need_update(room_id.clone(), &node._entity, node.mdate);
        }
    }
}

impl Writeable for NodeToInsert {
    fn write(&mut self, conn: &Connection) -> std::result::Result<(), rusqlite::Error> {
        if self.node.is_none() {
            return Ok(());
        }
        let node = self.node.as_mut().unwrap();
        node.write(conn, self.index, &self.old_fts_str, &self.node_fts_str)?;

        Ok(())
    }
}

#[derive(Serialize, Deserialize, Debug)]
pub struct NodeDeletionEntry {
    pub room_id: Uid,
    pub id: Uid,
    pub entity: String,
    pub mdate: i64,
    pub deletion_date: i64,
    pub verifying_key: Vec<u8>,
    pub signature: Vec<u8>,
    //used for synchronisation authorisation
    #[serde(skip)]
    pub entity_name: Option<String>,
}
impl NodeDeletionEntry {
    pub fn build(
        room: Uid,
        node: &Node,
        deletion_date: i64,
        signing_key: &impl SigningKey,
    ) -> Self {
        let verifying_key = signing_key.export_verifying_key();
        let signature = Self::sign(&room, node, deletion_date, &verifying_key, signing_key);
        Self {
            room_id: room,
            id: node.id,
            entity: node._entity.clone(),
            mdate: node.mdate,
            deletion_date,
            verifying_key,
            signature,
            entity_name: None,
        }
    }

    pub fn sign(
        room: &[u8],
        node: &Node,
        deletion_date: i64,
        verifying_key: &[u8],
        signing_key: &impl SigningKey,
    ) -> Vec<u8> {
        let mut hasher = blake3::Hasher::new();
        hasher.update(room);
        hasher.update(&node.id);
        hasher.update(&node.mdate.to_le_bytes());
        hasher.update(node._entity.as_bytes());
        hasher.update(&deletion_date.to_le_bytes());
        hasher.update(verifying_key);
        let hash = hasher.finalize();
        signing_key.sign(hash.as_bytes())
    }

    pub fn verify(&self) -> Result<()> {
        let mut hasher = blake3::Hasher::new();
        hasher.update(&self.room_id);
        hasher.update(&self.id);
        hasher.update(&self.mdate.to_le_bytes());
        hasher.update(self.entity.as_bytes());
        hasher.update(&self.deletion_date.to_le_bytes());
        hasher.update(&self.verifying_key);
        let hash = hasher.finalize();
        let pub_key = import_verifying_key(&self.verifying_key)?;
        pub_key.verify(hash.as_bytes(), &self.signature)?;
        Ok(())
    }

    pub fn get_entries(
        room_id: &Uid,
        entity: String,
        del_date: i64,
        batch_size: usize,
        sender: &mpsc::Sender<Result<Vec<NodeDeletionEntry>>>,
        conn: &Connection,
    ) -> Result<()> {
        let mut stmt = conn.prepare_cached(
            "
            SELECT 
                room_id ,
                id,
                entity,
                mdate,
                deletion_date,
                verifying_key,
                signature
            FROM _node_deletion_log
            WHERE 
                room_id = ? AND
                entity = ? AND
                deletion_date >= ? AND deletion_date < ? 
        ",
        )?;

        let mut rows = stmt.query((room_id, entity, date(del_date), date_next_day(del_date)))?;
        let mut res = Vec::new();
        let mut len = 0;
        while let Some(row) = rows.next()? {
            let deletion_lo = Self {
                room_id: row.get(0)?,
                id: row.get(1)?,
                entity: row.get(2)?,
                mdate: row.get(3)?,
                deletion_date: row.get(4)?,
                verifying_key: row.get(5)?,
                signature: row.get(6)?,
                entity_name: None,
            };
            let size = bincode::serialized_size(&deletion_lo)?;
            let insert_len = len + size + VEC_OVERHEAD;
            if insert_len > batch_size as u64 {
                let ready = res;
                res = Vec::new();
                len = 0;
                let s = sender.blocking_send(Ok(ready));
                if s.is_err() {
                    break;
                }
            } else {
                len = insert_len;
            }
            res.push(deletion_lo);
        }
        if !res.is_empty() {
            let _ = sender.blocking_send(Ok(res));
        }

        Ok(())
    }

    pub fn with_previous_authors(
        nodes: Vec<Self>,
        conn: &Connection,
    ) -> Result<HashMap<Uid, (Self, Option<Vec<u8>>)>> {
        let mut map = HashMap::new();
        let mut nodes_id: Vec<Uid> = Vec::with_capacity(nodes.len());
        let it = &mut nodes.into_iter().peekable();

        let mut in_clause = String::new();
        while let Some(nid) = it.next() {
            in_clause.push('?');
            nodes_id.push(nid.id);
            map.insert(nid.id, (nid, None));
            if it.peek().is_some() {
                in_clause.push(',');
            }
        }
        let query = format!(
            "SELECT id, verifying_key  FROM _node WHERE id in ({})",
            in_clause
        );
        let mut stmt = conn.prepare(&query)?;
        let mut rows = stmt.query(params_from_iter(nodes_id.iter()))?;
        while let Some(row) = rows.next()? {
            let id: Uid = row.get(0)?;
            let verifying_key: Option<Vec<u8>> = row.get(1)?;
            if let Some(entry) = map.get_mut(&id) {
                entry.1 = verifying_key;
            }
        }
        Ok(map)
    }

    pub fn delete_all(
        nodes: &mut Vec<Self>,
        daily_log: &mut DailyMutations,
        conn: &Connection,
    ) -> std::result::Result<(), rusqlite::Error> {
        let query = "DELETE FROM _node WHERE room_id=? AND id=?";
        let mut stmt = conn.prepare_cached(query)?;
        for node in nodes {
            stmt.execute((node.room_id, node.id))?;
            node.write(conn)?;
            daily_log.set_need_update(node.room_id, &node.entity, node.deletion_date);
            daily_log.set_need_update(node.room_id, &node.entity, node.mdate);
        }

        Ok(())
    }
}
impl Writeable for NodeDeletionEntry {
    fn write(&mut self, conn: &Connection) -> std::result::Result<(), rusqlite::Error> {
        let mut insert_stmt = conn.prepare_cached(
            "INSERT OR REPLACE INTO _node_deletion_log (
                room_id,
                id,
                entity,
                mdate,
                deletion_date,
                verifying_key,
                signature
            ) VALUES (?,?,?,?,?,?,?)
        ",
        )?;
        insert_stmt.execute((
            &self.room_id,
            &self.id,
            &self.entity,
            &self.mdate,
            &self.deletion_date,
            &self.verifying_key,
            &self.signature,
        ))?;
        Ok(())
    }
}

///
/// Extract all text from a json object for full text search
///
pub fn extract_json(val: &serde_json::Value, buff: &mut String) -> Result<()> {
    match val {
        serde_json::Value::String(v) => {
            buff.push_str(v);
            buff.push(' ');
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

#[cfg(test)]
mod tests {

    use crate::security::{new_uid, Ed25519SigningKey};

    use super::*;

    #[test]
    fn node_signature() {
        let keypair = Ed25519SigningKey::new();
        let mut node = Node {
            _entity: "TEST".to_string(),
            ..Default::default()
        };
        node.sign(&keypair).unwrap();
        node.verify().unwrap();

        node.id = new_uid();
        node.sign(&keypair).unwrap();
        node.verify().unwrap();

        node.cdate = node.cdate + 1;
        node.verify()
            .expect_err("cdate has changed, the verification fails");
        node.sign(&keypair).unwrap();
        node.verify().unwrap();

        node.mdate = node.mdate + 1;
        node.verify()
            .expect_err("mdate has changed, the verification fails");
        node.sign(&keypair).unwrap();
        node.verify().unwrap();

        let bad_json = r#"["expecting an object, not an array"]"#.to_string();
        node._json = Some(bad_json);
        node.verify().expect_err("Invalid json");
        node.sign(&keypair).expect_err("Invalid json");
        let good_json = r#"{
            "randomtext": "Lorem ipsum dolor sit amet"
        }"#
        .to_string();
        node._json = Some(good_json);
        node.verify()
            .expect_err("_json has changed, verification fails");
        node.sign(&keypair).unwrap();
        node.verify().unwrap();

        node._binary = Some(vec![1, 2, 3]);
        node.verify()
            .expect_err("_json changed, the verification fails");
        node.sign(&keypair).unwrap();
        node.verify().unwrap();

        node.verifying_key = b"badkey".to_vec();
        node.verify()
            .expect_err("_pub_key has changed, the verifcation fails");
        node.sign(&keypair).unwrap();
        assert_ne!(b"badkey".to_vec(), node.verifying_key);
        node.verify().unwrap();
    }

    #[test]
    fn node_fts() {
        let conn = Connection::open_in_memory().unwrap();
        Node::create_tables(&conn).unwrap();

        let keypair = Ed25519SigningKey::new();

        let good_json = r#"{
            "randomtext": "Lorem ipsum dolor sit amet"
        }"#
        .to_string();

        let mut node = Node {
            _entity: "TEST".to_string(),
            cdate: now(),
            _json: Some(good_json),
            ..Default::default()
        };
        node.sign(&keypair).unwrap();
        node.write(
            &conn,
            true,
            &None,
            &Some(String::from("Lorem ipsum dolor sit amet")),
        )
        .unwrap();

        let mut stmt = conn
            .prepare(
                "
        SELECT id ,room_id, cdate, mdate, _entity,_json, _binary, verifying_key, _signature, _node.rowid 
        FROM _node_fts JOIN _node ON _node_fts.rowid=_node.rowid 
        WHERE _node_fts MATCH ? 
        ORDER BY rank;",
            )
            .unwrap();
        let results = stmt.query_map(["Lorem"], Node::NODE_MAPPING).unwrap();
        let mut res = vec![];
        for node in results {
            let node = node.unwrap();
            node.verify().unwrap();
            res.push(node);
        }
        assert_eq!(1, res.len());

        let results = stmt.query_map(["randomtext"], Node::NODE_MAPPING).unwrap();
        assert_eq!(0, results.count()); //JSON fields name are not indexed

        node._json = Some(
            r#"{
            "randomtext": "ipsum dolor sit amet Conjectur"
        }"#
            .to_string(),
        );

        node.write(
            &conn,
            true,
            &Some(String::from("Lorem ipsum dolor sit amet")),
            &Some(String::from("ipsum dolor sit amet Conjectur")),
        )
        .unwrap();

        let results = stmt.query_map(["lorem"], Node::NODE_MAPPING).unwrap();
        assert_eq!(0, results.count()); //Search table is correctly updated

        let results = stmt.query_map(["conjectur"], Node::NODE_MAPPING).unwrap();
        assert_eq!(1, results.count()); //Search table is correctly updated

        //
        // Test disabling indexing
        //
        node.write(
            &conn,
            false,
            &Some(String::from("ipsum dolor sit amet Conjectur")),
            &Some(String::from("will not be inserted")),
        )
        .unwrap();

        let results = stmt.query_map(["lorem"], Node::NODE_MAPPING).unwrap();
        assert_eq!(0, results.count()); //Search table is correctly updated

        let results = stmt.query_map(["inserted"], Node::NODE_MAPPING).unwrap();
        assert_eq!(0, results.count()); //Search table is correctly updated
    }

    #[test]
    fn mutate_test() {
        let conn = Connection::open_in_memory().unwrap();
        Node::create_tables(&conn).unwrap();

        let keypair = Ed25519SigningKey::new();

        let good_json = r#"{
            "randomtext": "Lorem ipsum dolor sit amet"
        }"#
        .to_string();

        let mut node = Node {
            _entity: "TEST".to_string(),
            cdate: now(),
            _json: Some(good_json),
            ..Default::default()
        };
        node.sign(&keypair).unwrap();
        node.write(
            &conn,
            true,
            &None,
            &Some(String::from("Lorem ipsum dolor sit amet")),
        )
        .unwrap();

        node._json = Some(
            r#"{
            "randomtext": "dolor sit amet"
        }"#
            .to_string(),
        );

        node.sign(&keypair).unwrap();
        node.write(
            &conn,
            true,
            &None,
            &Some(String::from("Lorem ipsum dolor sit amet")),
        )
        .unwrap();
    }

    #[test]
    fn delete() {
        let conn = Connection::open_in_memory().unwrap();
        Node::create_tables(&conn).unwrap();

        let signing_key = Ed25519SigningKey::new();
        let entity = "Pet";

        let mut node = Node {
            _entity: String::from(entity),
            ..Default::default()
        };
        node.sign(&signing_key).unwrap();
        node.write(&conn, false, &None, &None).unwrap();

        let new_node = Node::get_with_entity(&node.id, entity, &conn).unwrap();
        assert!(new_node.is_some());

        Node::delete(&node.id, &conn).unwrap();
        let node_exists = Node::exist(&node.id, entity, &conn).unwrap();
        assert!(!node_exists);

        let mut exists_stmt = conn.prepare("SELECT count(1) FROM _node").unwrap();
        let num_nodes: i64 = exists_stmt.query_row([], |row| Ok(row.get(0)?)).unwrap();
        assert_eq!(0, num_nodes);
    }

    #[test]
    fn node_deletion_log() {
        let conn = Connection::open_in_memory().unwrap();
        Node::create_tables(&conn).unwrap();

        let signing_key = Ed25519SigningKey::new();
        let entity = "Pet";
        let room_id = new_uid();
        let mut node = Node {
            room_id: Some(room_id),
            _entity: String::from(entity),
            ..Default::default()
        };
        node.sign(&signing_key).unwrap();
        node.write(&conn, false, &None, &None).unwrap();
        Node::delete(&node.id, &conn).unwrap();

        let mut node_deletion_log = NodeDeletionEntry::build(room_id, &node, now(), &signing_key);
        node_deletion_log.write(&conn).unwrap();

        let batch_size = 4096;
        let (reply, mut receive) = mpsc::channel::<Result<Vec<NodeDeletionEntry>>>(1);

        NodeDeletionEntry::get_entries(
            &room_id,
            entity.to_string(),
            date(node_deletion_log.deletion_date),
            batch_size,
            &reply,
            &conn,
        )
        .unwrap();
        let deletion_logs = receive.blocking_recv().unwrap().unwrap();
        let entry = &deletion_logs[0];

        assert_eq!(&node.room_id.unwrap(), &entry.room_id);
        assert_eq!(&node.id, &entry.id);
        assert_eq!(&node._entity, &entry.entity);
        assert_eq!(&node.mdate, &entry.mdate);
    }

    #[test]
    fn get_room_nodes_at() {
        let conn = Connection::open_in_memory().unwrap();
        Node::create_tables(&conn).unwrap();

        let signing_key = Ed25519SigningKey::new();
        let entity = "Pet";
        let room_id1 = new_uid();
        let date = 1000;
        let mut node1 = Node {
            room_id: Some(room_id1.clone()),
            _entity: String::from(entity),
            mdate: date,
            ..Default::default()
        };
        node1.sign(&signing_key).unwrap();
        node1.write(&conn, false, &None, &None).unwrap();

        let mut node2 = Node {
            room_id: Some(room_id1.clone()),
            _entity: String::from(entity),
            mdate: date,
            ..Default::default()
        };
        node2.sign(&signing_key).unwrap();
        node2.write(&conn, false, &None, &None).unwrap();

        let mut node3 = Node {
            room_id: Some(room_id1.clone()),
            _entity: String::from(entity),
            mdate: date,
            ..Default::default()
        };
        node3.sign(&signing_key).unwrap();
        node3.write(&conn, false, &None, &None).unwrap();
        let (reply, mut receive) = mpsc::channel::<Result<HashSet<NodeIdentifier>>>(1);

        Node::get_daily_nodes_for_room(
            &room_id1,
            entity.to_string(),
            date,
            1024 * 8,
            &reply,
            &conn,
        )
        .unwrap();
        let mut ids = receive.blocking_recv().unwrap().unwrap();
        assert_eq!(3, ids.len());

        let date2 = now();
        node3.mdate = date2;
        node3.sign(&signing_key).unwrap();
        node3.write(&conn, false, &None, &None).unwrap();

        let (reply, mut receive) = mpsc::channel::<Result<HashSet<NodeIdentifier>>>(1);
        Node::get_daily_nodes_for_room(
            &room_id1,
            entity.to_string(),
            date,
            1024 * 8,
            &reply,
            &conn,
        )
        .unwrap();
        let ids_2 = receive.blocking_recv().unwrap().unwrap();
        assert_eq!(2, ids_2.len());

        Node::filter_existing(&mut ids, &conn).unwrap();
        assert_eq!(0, ids.len());
    }

    #[test]
    fn delete_from_deletion_log() {
        let conn = Connection::open_in_memory().unwrap();
        Node::create_tables(&conn).unwrap();

        let signing_key = Ed25519SigningKey::new();
        let entity = "Pet";
        let room_id = new_uid();
        let mut node = Node {
            room_id: Some(room_id),
            _entity: String::from(entity),
            ..Default::default()
        };
        node.sign(&signing_key).unwrap();
        node.write(&conn, false, &None, &None).unwrap();

        let mut node_deletion_log = NodeDeletionEntry::build(room_id, &node, now(), &signing_key);
        node_deletion_log.write(&conn).unwrap();
        let batch_size = 4096;
        let (reply, mut receive) = mpsc::channel::<Result<Vec<NodeDeletionEntry>>>(1);

        NodeDeletionEntry::get_entries(
            &room_id,
            entity.to_string(),
            date(node_deletion_log.deletion_date),
            batch_size,
            &reply,
            &conn,
        )
        .unwrap();
        let deletion_logs = receive.blocking_recv().unwrap().unwrap();
        let entry = &deletion_logs[0];

        assert_eq!(&node.room_id.unwrap(), &entry.room_id);
        assert_eq!(&node.id, &entry.id);
        assert_eq!(&node._entity, &entry.entity);
        assert_eq!(&node.mdate, &entry.mdate);

        assert!(Node::get_with_entity(&node.id, &entity, &conn)
            .unwrap()
            .is_some());

        let log_with_author =
            NodeDeletionEntry::with_previous_authors(deletion_logs, &conn).unwrap();
        let entry = log_with_author.get(&node.id).unwrap();
        assert!(entry.1.is_some());
        let mut deletion: Vec<NodeDeletionEntry> =
            log_with_author.into_iter().map(|e| e.1 .0).collect();
        NodeDeletionEntry::delete_all(&mut deletion, &mut DailyMutations::new(), &conn).unwrap();

        assert!(Node::get_with_entity(&node.id, &entity, &conn)
            .unwrap()
            .is_none());
    }
}
