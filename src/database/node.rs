use super::{
    sqlite_database::{is_valid_id_len, RowMappingFn, Writeable, MAX_ROW_LENTGH},
    Error, Result,
};
use crate::cryptography::{base64_encode, import_verifying_key, new_id, now, SigningKey};
use rusqlite::{Connection, OptionalExtension};
use serde::{Deserialize, Serialize};
use serde_json::Value;

///
/// Upon deletion or mutation, the _entity field is updated by appending $ at the start, resulting in a 'soft' deletion or archival
///
pub const ARCHIVED_CHAR: char = '$';

impl Default for Node {
    fn default() -> Self {
        let date = now();
        Self {
            id: new_id(),
            cdate: date,
            mdate: date,
            _entity: "".to_string(),
            _json: None,
            _binary: None,
            _verifying_key: vec![],
            _signature: vec![],
        }
    }
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct Node {
    pub id: Vec<u8>,
    pub cdate: i64,
    pub mdate: i64,
    pub _entity: String,
    pub _json: Option<String>,
    pub _binary: Option<Vec<u8>>,
    pub _verifying_key: Vec<u8>,
    pub _signature: Vec<u8>,
}
impl Node {
    ///
    /// Creates the required tables and indexes
    ///
    /// _node_fts is the table that provides the full text search functionality
    ///
    /// _nodes keeps its rowid because it is required for the full text seach.
    ///
    pub fn create_table(conn: &Connection) -> Result<()> {
        //system table stores compressed text and json
        conn.execute(
            "
        CREATE TABLE _node (
            id BLOB NOT NULL,
            cdate INTEGER  NOT NULL,
            mdate INTEGER  NOT NULL,
            _entity TEXT  NOT NULL,
            _json TEXT,
            _binary BLOB,
            _verifying_key BLOB NOT NULL,
            _signature BLOB NOT NULL
        ) STRICT",
            [],
        )?;

        //node primary key
        //mdate is part to allow for archiving nodes
        conn.execute(
            "CREATE UNIQUE INDEX _node_id__entity_mdate ON _node (id, _entity, mdate)",
            [],
        )?;

        //allows for more efficient "entity full scan" for example when loading all rooms for the authorisation feature
        conn.execute(
            "CREATE INDEX _node__entity_id__mdate_idx ON _node (_entity, id)",
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
            room BLOB,
            id BLOB,
            entity TEXT,
            deletion_date INTEGER,
            verifying_key BLOB NOT NULL,
            signature BLOB NOT NULL,
            PRIMARY KEY(room, deletion_date, id, entity )
        ) WITHOUT ROWID, STRICT",
            [],
        )?;

        conn.execute(
            "CREATE TABLE _daily_node_log (
            room BLOB NOT NULL,
            date INTEGER NOT NULL,
            entry_number INTEGER,
            daily_hash BLOB,
            need_recompute INTEGER, 
            PRIMARY KEY (room, date)
        ) WITHOUT ROWID, STRICT",
            [],
        )?;
        conn.execute(
            "CREATE INDEX _daily_node_log_recompute_room_date ON _daily_node_log (need_recompute, room, date)",
            [],
        )?;
        Ok(())
    }

    fn len(&self) -> Result<usize> {
        let mut len = 0;
        len += self.id.len();
        len += 8; //date
        len += 8; //cdate
        len += self._entity.as_bytes().len();

        if let Some(v) = &self._json {
            let serialized = serde_json::to_string(v)?;
            len += serialized.as_bytes().len();
        }

        if let Some(v) = &self._binary {
            len += v.len();
        }

        len += &self._verifying_key.len();
        len += &self._signature.len();
        Ok(len)
    }

    fn hash(&self) -> Result<blake3::Hash> {
        let mut hasher = blake3::Hasher::new();
        hasher.update(&self.id);
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

        hasher.update(&self._verifying_key);
        Ok(hasher.finalize())
    }

    ///
    /// check the node's signature
    ///
    pub fn verify(&self) -> Result<()> {
        if !is_valid_id_len(&self.id) {
            return Err(Error::InvalidId());
        }

        if self._entity.is_empty() {
            return Err(Error::EmptyNodeEntity());
        }
        let size = self.len()?;
        if size > MAX_ROW_LENTGH {
            return Err(Error::DatabaseRowToLong(format!(
                "Node {} is too large. {} bytes instead of {}",
                base64_encode(&self.id),
                size,
                MAX_ROW_LENTGH
            )));
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

        let pub_key = import_verifying_key(&self._verifying_key)?;
        pub_key.verify(hash.as_bytes(), &self._signature)?;

        Ok(())
    }

    ///
    /// sign the node after performing some checks
    ///
    pub fn sign(&mut self, signing_key: &impl SigningKey) -> Result<()> {
        self._verifying_key = signing_key.export_verifying_key();

        if !is_valid_id_len(&self.id) {
            return Err(Error::InvalidId());
        }

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

        let size = self.len()?;
        if size > MAX_ROW_LENTGH {
            return Err(Error::DatabaseRowToLong(format!(
                "Node {} is too long {} bytes instead of {}",
                base64_encode(&self.id.clone()),
                size,
                MAX_ROW_LENTGH
            )));
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
            cdate: row.get(1)?,
            mdate: row.get(2)?,
            _entity: row.get(3)?,
            _json: row.get(4)?,
            _binary: row.get(5)?,
            _verifying_key: row.get(6)?,
            _signature: row.get(7)?,
        }))
    };

    ///
    /// SQL Query to retrieve a Node by its primary key
    ///
    pub const NODE_QUERY: &'static str = "
    SELECT id , cdate, mdate, _entity,_json, _binary, _verifying_key, _signature  
    FROM _node 
    WHERE id = ? AND 
    _entity = ?";
    ///
    /// Retrieve a node using its primary key
    ///
    pub fn get(id: &Vec<u8>, entity: &str, conn: &Connection) -> Result<Option<Box<Node>>> {
        let mut get_stmt = conn.prepare_cached(Self::NODE_QUERY)?;
        let node = get_stmt
            .query_row((id, entity), Self::NODE_MAPPING)
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
    pub fn delete(
        id: &Vec<u8>,
        entity: &str,
        mdate: i64,
        enable_archives: bool,
        conn: &Connection,
    ) -> std::result::Result<(), rusqlite::Error> {
        if entity.starts_with(ARCHIVED_CHAR) || !enable_archives {
            let mut delete_stmt =
                conn.prepare_cached("DELETE FROM _node WHERE id=? AND _entity=?")?;
            delete_stmt.execute((id, entity))?;
        } else {
            let mut deleted_entity = String::new();
            deleted_entity.push(ARCHIVED_CHAR);
            deleted_entity.push_str(entity);

            let mut update_stmt = conn
                .prepare_cached("UPDATE _node SET _entity=?, mdate=? WHERE id=? AND _entity=?")?;
            update_stmt.execute((deleted_entity, mdate, id, entity))?;
        }
        Ok(())
    }

    ///
    /// archive the node by appending '$' to its entity name
    /// every mutation query that updates a generates an archived version
    ///
    pub fn archive(&self, conn: &Connection) -> std::result::Result<(), rusqlite::Error> {
        let mut insert_stmt = conn.prepare_cached(
            "INSERT INTO _node ( 
                    id,
                    cdate,
                    mdate,
                    _entity,
                    _json,
                    _binary,
                    _verifying_key,
                    _signature
                ) VALUES (
                    ?, ?, ?, ?, ?, ?, ?, ?
                )",
        )?;
        let archived_entity = format!("{}{}", ARCHIVED_CHAR, &self._entity);
        let _ = insert_stmt.insert((
            &self.id,
            &self.cdate,
            &self.mdate,
            &archived_entity,
            &self._json,
            &self._binary,
            &self._verifying_key,
            &self._signature,
        ))?;

        Ok(())
    }

    ///
    /// Verify the existence of a specific Node
    ///
    pub fn exist(id: &Vec<u8>, entity: &str, conn: &Connection) -> Result<bool> {
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
        &self,
        conn: &Connection,
        index: bool,
        rowid: &Option<i64>,
        old_fts_str: &Option<String>,
        node_fts_str: &Option<String>,
    ) -> std::result::Result<(), rusqlite::Error> {
        static UPDATE_FTS_QUERY: &str = "INSERT INTO _node_fts (rowid, text) VALUES (?, ?)";
        if let Some(id) = rowid {
            if let Some(previous) = old_fts_str {
                let mut delete_fts_stmt = conn.prepare_cached(
                    "INSERT INTO _node_fts (_node_fts, rowid, text) VALUES('delete', ?, ?)",
                )?;
                delete_fts_stmt.execute((id, previous))?;
            }

            if index {
                if let Some(current) = node_fts_str {
                    let mut insert_fts_stmt = conn.prepare_cached(UPDATE_FTS_QUERY)?;
                    insert_fts_stmt.execute((id, current))?;
                }
            }

            let mut update_node_stmt = conn.prepare_cached(
                "
            UPDATE _node SET 
                id = ?,
                cdate = ?,
                mdate = ?,
                _entity = ?,
                _json = ?,
                _binary = ?,
                _verifying_key = ?,
                _signature = ?
            WHERE
                rowid = ? ",
            )?;

            update_node_stmt.execute((
                &self.id,
                &self.cdate,
                &self.mdate,
                &self._entity,
                &self._json,
                &self._binary,
                &self._verifying_key,
                &self._signature,
                id,
            ))?;
        } else {
            let mut insert_stmt = conn.prepare_cached(
                "INSERT INTO _node ( 
                    id,
                    cdate,
                    mdate,
                    _entity,
                    _json,
                    _binary,
                    _verifying_key,
                    _signature
                ) VALUES (
                    ?, ?, ?, ?, ?, ?, ?, ?
                )",
            )?;
            let rowid = insert_stmt.insert((
                &self.id,
                &self.cdate,
                &self.mdate,
                &self._entity,
                &self._json,
                &self._binary,
                &self._verifying_key,
                &self._signature,
            ))?;

            if index {
                if let Some(current) = node_fts_str {
                    let mut insert_fts_stmt = conn.prepare_cached(UPDATE_FTS_QUERY)?;
                    insert_fts_stmt.execute((rowid, current))?;
                }
            }
        }
        Ok(())
    }
}
#[derive(Debug)]
pub struct NodeDeletionEntry {
    pub room: Vec<u8>,
    pub id: Vec<u8>,
    pub entity: String,
    pub deletion_date: i64,
    pub verifying_key: Vec<u8>,
    pub signature: Vec<u8>,
    pub mdate: i64,
}
impl NodeDeletionEntry {
    pub fn build(
        room: Vec<u8>,
        node: &Node,
        deletion_date: i64,
        verifying_key: Vec<u8>,
        signing_key: &impl SigningKey,
    ) -> Self {
        let signature = Self::sign(&room, node, deletion_date, &verifying_key, signing_key);
        Self {
            room,
            id: node.id.clone(),
            entity: node._entity.clone(),
            deletion_date,
            verifying_key,
            signature,
            mdate: node.mdate,
        }
    }

    pub fn sign(
        room: &Vec<u8>,
        node: &Node,
        deletion_date: i64,
        verifying_key: &Vec<u8>,
        signing_key: &impl SigningKey,
    ) -> Vec<u8> {
        let mut hasher = blake3::Hasher::new();
        hasher.update(room);
        hasher.update(&node.id);
        hasher.update(&node._entity.as_bytes());
        hasher.update(&deletion_date.to_le_bytes());
        hasher.update(verifying_key);
        let hash = hasher.finalize();
        signing_key.sign(hash.as_bytes())
    }

    pub fn verify(&self) -> Result<()> {
        let mut hasher = blake3::Hasher::new();
        hasher.update(&self.room);
        hasher.update(&self.id);
        hasher.update(&self.entity.as_bytes());
        hasher.update(&self.deletion_date.to_le_bytes());
        hasher.update(&self.verifying_key);
        let hash = hasher.finalize();
        let pub_key = import_verifying_key(&self.verifying_key)?;
        pub_key.verify(hash.as_bytes(), &self.signature)?;
        Ok(())
    }

    pub const MAPPING: RowMappingFn<Self> = |row| {
        Ok(Box::new(NodeDeletionEntry {
            room: row.get(0)?,
            id: row.get(1)?,
            entity: row.get(2)?,
            deletion_date: row.get(3)?,
            verifying_key: row.get(4)?,
            signature: row.get(5)?,
            mdate: 0,
        }))
    };
}
impl Writeable for NodeDeletionEntry {
    fn write(&self, conn: &Connection) -> std::result::Result<(), rusqlite::Error> {
        let mut insert_stmt = conn.prepare_cached(
            "INSERT OR REPLACE INTO _node_deletion_log (
                room,
                id,
                entity,
                deletion_date,
                verifying_key,
                signature
            ) VALUES (?,?,?,?,?,?)
        ",
        )?;
        insert_stmt.execute((
            &self.room,
            &self.id,
            &self.entity,
            &self.deletion_date,
            &self.verifying_key,
            &self.signature,
        ))?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {

    use crate::cryptography::Ed25519SigningKey;

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

        node.id = b"key too short".to_vec();
        node.verify().expect_err("Key is too short");
        node.sign(&keypair)
            .expect_err("Key is too short to be signed");

        node.id = new_id();
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

        node._verifying_key = b"badkey".to_vec();
        node.verify()
            .expect_err("_pub_key has changed, the verifcation fails");
        node.sign(&keypair).unwrap();
        assert_ne!(b"badkey".to_vec(), node._verifying_key);
        node.verify().unwrap();

        let sq = &['a'; MAX_ROW_LENTGH];
        let big_string = String::from_iter(sq);
        node._entity = big_string;
        node.verify().expect_err("node is too big");
        node.sign(&keypair).expect_err("node is too big");
    }

    #[test]
    fn node_fts() {
        let conn = Connection::open_in_memory().unwrap();
        Node::create_table(&conn).unwrap();

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
            &None,
            &Some(String::from("Lorem ipsum dolor sit amet")),
        )
        .unwrap();

        let mut stmt = conn
            .prepare(
                "
        SELECT id , cdate, mdate, _entity,_json, _binary, _verifying_key, _signature 
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
        let id = &res[0].id;

        let results = stmt.query_map(["randomtext"], Node::NODE_MAPPING).unwrap();
        assert_eq!(0, results.count()); //JSON fields name are not indexed

        let mut rowid_stmt = conn
            .prepare_cached("SELECT rowid FROM _node WHERE id = ?")
            .unwrap();
        let row_id: i64 = rowid_stmt.query_row([id], |row| Ok(row.get(0)?)).unwrap();

        node._json = Some(
            r#"{
            "randomtext": "ipsum dolor sit amet Conjectur"
        }"#
            .to_string(),
        );
        //node can be writen without resigning first, which could lead to errors
        node.write(
            &conn,
            true,
            &Some(row_id),
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
            &Some(row_id),
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
    fn node_with_archive() {
        let conn = Connection::open_in_memory().unwrap();
        Node::create_table(&conn).unwrap();

        let signing_key = Ed25519SigningKey::new();
        let entity = "Pet";

        let mut node = Node {
            _entity: String::from(entity),
            ..Default::default()
        };
        node.sign(&signing_key).unwrap();
        node.write(&conn, false, &None, &None, &None).unwrap();

        let new_node = Node::get(&node.id, entity, &conn).unwrap();
        assert!(new_node.is_some());

        Node::delete(&node.id, entity, now(), true, &conn).unwrap();
        let node_exists = Node::exist(&node.id, entity, &conn).unwrap();
        assert!(!node_exists);

        let del_entity = format!("{}{}", ARCHIVED_CHAR, entity);

        let node_exists = Node::exist(&node.id, &del_entity, &conn).unwrap();
        assert!(node_exists);

        //deleting an entity results in a hard delete
        Node::delete(&node.id, &del_entity, now(), true, &conn).unwrap();

        let mut exists_stmt = conn.prepare("SELECT count(1) FROM _node").unwrap();
        let num_nodes: i64 = exists_stmt.query_row([], |row| Ok(row.get(0)?)).unwrap();
        assert_eq!(0, num_nodes);
    }

    #[test]
    fn node_without_archive() {
        let conn = Connection::open_in_memory().unwrap();
        Node::create_table(&conn).unwrap();

        let signing_key = Ed25519SigningKey::new();
        let entity = "Pet";

        let mut node = Node {
            _entity: String::from(entity),
            ..Default::default()
        };
        node.sign(&signing_key).unwrap();
        node.write(&conn, false, &None, &None, &None).unwrap();

        let new_node = Node::get(&node.id, entity, &conn).unwrap();
        assert!(new_node.is_some());

        Node::delete(&node.id, entity, now(), false, &conn).unwrap();
        let node_exists = Node::exist(&node.id, entity, &conn).unwrap();
        assert!(!node_exists);

        let del_entity = format!("{}{}", ARCHIVED_CHAR, entity);

        let node_exists = Node::exist(&node.id, &del_entity, &conn).unwrap();
        assert!(!node_exists);

        let mut exists_stmt = conn.prepare("SELECT count(1) FROM _node").unwrap();
        let num_nodes: i64 = exists_stmt.query_row([], |row| Ok(row.get(0)?)).unwrap();
        assert_eq!(0, num_nodes);
    }

    #[test]
    fn node_deletion_log() {
        let conn = Connection::open_in_memory().unwrap();
        Node::create_table(&conn).unwrap();

        let signing_key = Ed25519SigningKey::new();
        let entity = "Pet";

        let mut node = Node {
            _entity: String::from(entity),
            ..Default::default()
        };
        node.sign(&signing_key).unwrap();
        node.write(&conn, false, &None, &None, &None).unwrap();
        Node::delete(&node.id, &node._entity, node.mdate, false, &conn).unwrap();

        let node_deletion_log = NodeDeletionEntry::build(
            Vec::new(),
            &node,
            now(),
            signing_key.export_verifying_key(),
            &signing_key,
        );
        node_deletion_log.write(&conn).unwrap();
        let mut exists_stmt = conn
            .prepare(
                "SELECT  
                        room,
                        id,
                        entity,
                        deletion_date,
                        verifying_key,
                        signature 
                    FROM _node_deletion_log",
            )
            .unwrap();
        let node_deletion_log = exists_stmt
            .query_row([], NodeDeletionEntry::MAPPING)
            .unwrap();
        node_deletion_log.verify().unwrap();

        assert_eq!(&node.id, &node_deletion_log.id);
        assert_eq!(&node._entity, &node_deletion_log.entity);
    }
}
