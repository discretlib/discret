use super::{
    graph_database::{new_id, now, valid_id_len, FromRow, MAX_ROW_LENTGH},
    Error, Result,
};
use crate::cryptography::{
    base64_encode, Ed2519PublicKey, Ed2519SigningKey, PublicKey, SigningKey,
};
use rusqlite::{Connection, OptionalExtension, Row};
use serde::{Deserialize, Serialize};
use serde_json::Value;

#[derive(Serialize, Deserialize, Debug)]
pub struct Node {
    pub id: Vec<u8>,
    pub cdate: i64,
    pub mdate: i64,
    pub _entity: String,
    pub _json_data: Option<String>,
    pub _binary_data: Option<Vec<u8>>,
    pub _pub_key: Vec<u8>,
    pub _signature: Vec<u8>,
}
impl Node {
    pub fn create_table(conn: &Connection) -> Result<()> {
        //system table stores compressed text and json
        conn.execute(
            "
        CREATE TABLE _node (
            id BLOB NOT NULL,
            cdate INTEGER  NOT NULL,
            mdate INTEGER  NOT NULL,
            _entity TEXT  NOT NULL,
            _json_data TEXT,
            _binary_data BLOB,
            _pub_key BLOB NOT NULL,
            _signature BLOB NOT NULL
        ) STRICT",
            [],
        )?;

        conn.execute(
            "CREATE UNIQUE INDEX _node_sys_id__entity_mdate_idx ON _node (id, _entity,  mdate)",
            [],
        )?;

        conn.execute(
            "CREATE VIRTUAL TABLE _node_fts USING fts5(text, content='' , prefix='2,3' , detail=none)",
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

        if let Some(v) = &self._json_data {
            let serialized = serde_json::to_string(v)?;
            len += serialized.as_bytes().len();
        }

        if let Some(v) = &self._binary_data {
            len += v.len();
        }

        len += &self._pub_key.len();
        len += &self._signature.len();
        Ok(len)
    }

    fn hash(&self) -> Result<blake3::Hash> {
        let mut hasher = blake3::Hasher::new();

        hasher.update(&self.id);
        hasher.update(&self.cdate.to_le_bytes());
        hasher.update(&self.mdate.to_le_bytes());
        hasher.update(self._entity.as_bytes());

        if let Some(v) = &self._json_data {
            let serialized = serde_json::to_string(v)?;
            hasher.update(serialized.as_bytes());
        }

        if let Some(v) = &self._binary_data {
            hasher.update(v);
        }

        hasher.update(&self._pub_key);
        Ok(hasher.finalize())
    }

    pub fn verify(&self) -> Result<()> {
        if !valid_id_len(&self.id) {
            return Err(Error::InvalidId());
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
        if let Some(v) = &self._json_data {
            let value: Value = serde_json::from_str(v)?;
            if value.as_object().is_none() {
                return Err(Error::InvalidNode(String::from(
                    "json field is not an Object",
                )));
            }
        }
        let hash = self.hash()?;

        let pub_key = Ed2519PublicKey::import(&self._pub_key)?;
        pub_key.verify(hash.as_bytes(), &self._signature)?;

        Ok(())
    }

    pub fn sign(&mut self, keypair: &Ed2519SigningKey) -> Result<()> {
        self._pub_key = keypair.export_public();

        if !valid_id_len(&self.id) {
            return Err(Error::InvalidId());
        }

        //ensure that the Json field is an Object field
        if let Some(v) = &self._json_data {
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
        let signature = keypair.sign(hash.as_bytes());
        self._signature = signature;

        Ok(())
    }

    pub fn get(id: &Vec<u8>, entity: &str, conn: &Connection) -> Result<Option<Box<Node>>> {
        let mut get_stmt = conn.prepare_cached(
            "SELECT id , cdate, mdate, _entity,_json_data, _binary_data, _pub_key, _signature  FROM _node WHERE id = ? AND _entity = ?",
        )?;
        let node = get_stmt
            .query_row((id, entity), Node::from_row())
            .optional()?;
        Ok(node)
    }

    pub fn exist(id: &Vec<u8>, entity: &str, conn: &Connection) -> Result<bool> {
        let mut exists_stmt =
            conn.prepare_cached("SELECT 1 FROM _node WHERE id = ? AND _entity = ?")?;
        let node: Option<i64> = exists_stmt
            .query_row((id, entity), |row| Ok(row.get(0)?))
            .optional()?;

        Ok(node.is_some())
    }

    ///
    /// intended to be used in the GraphDatase insert thread
    /// only insert statement are done to avoid any overhead on in the thread
    ///
    pub fn write(
        &self,
        conn: &Connection,
        index: bool,
        rowid: Option<i64>,
        previous_fts: Option<String>,
        current_fts: Option<String>,
    ) -> std::result::Result<(), rusqlite::Error> {
        const UPDATE_FTS_QUERY: &'static str = "INSERT INTO _node_fts (rowid, text) VALUES (?, ?)";
        if let Some(id) = rowid {
            if let Some(previous) = previous_fts {
                let mut delete_fts_stmt = conn.prepare_cached(
                    "INSERT INTO _node_fts (_node_fts, rowid, text) VALUES('delete', ?, ?)",
                )?;
                delete_fts_stmt.execute((id, previous))?;
            }

            if index {
                if let Some(current) = current_fts {
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
                _json_data = ?,
                _binary_data = ?,
                _pub_key = ?,
                _signature = ?
            WHERE
                rowid = ? ",
            )?;

            update_node_stmt.execute((
                &self.id,
                &self.cdate,
                &self.mdate,
                &self._entity,
                &self._json_data,
                &self._binary_data,
                &self._pub_key,
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
                    _json_data,
                    _binary_data,
                    _pub_key,
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
                &self._json_data,
                &self._binary_data,
                &self._pub_key,
                &self._signature,
            ))?;
            if index {
                if let Some(current) = current_fts {
                    let mut insert_fts_stmt = conn.prepare_cached(UPDATE_FTS_QUERY)?;
                    insert_fts_stmt.execute((rowid, current))?;
                }
            }
        }
        Ok(())
    }
}

impl FromRow for Node {
    fn from_row() -> fn(&Row) -> std::result::Result<Box<Self>, rusqlite::Error> {
        |row| {
            Ok(Box::new(Node {
                id: row.get(0)?,
                cdate: row.get(1)?,
                mdate: row.get(2)?,
                _entity: row.get(3)?,
                _json_data: row.get(4)?,
                _binary_data: row.get(5)?,
                _pub_key: row.get(6)?,
                _signature: row.get(7)?,
            }))
        }
    }
}

impl Default for Node {
    fn default() -> Self {
        let date = now();
        Self {
            id: new_id(date),
            cdate: date,
            mdate: date,
            _entity: "".to_string(),
            _json_data: None,
            _binary_data: None,
            _pub_key: vec![],
            _signature: vec![],
        }
    }
}

#[cfg(test)]
mod tests {

    use super::*;

    #[test]
    fn node_signature() {
        let keypair = Ed2519SigningKey::new();
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

        node.id = new_id(now());
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
        node._json_data = Some(bad_json);
        node.verify().expect_err("Invalid json");
        node.sign(&keypair).expect_err("Invalid json");
        let good_json = r#"{
            "randomtext": "Lorem ipsum dolor sit amet"
        }"#
        .to_string();
        node._json_data = Some(good_json);
        node.verify()
            .expect_err("_json_data has changed, verification fails");
        node.sign(&keypair).unwrap();
        node.verify().unwrap();

        node._binary_data = Some(vec![1, 2, 3]);
        node.verify()
            .expect_err("_json_data changed, the verification fails");
        node.sign(&keypair).unwrap();
        node.verify().unwrap();

        node._pub_key = b"badkey".to_vec();
        node.verify()
            .expect_err("_pub_key has changed, the verifcation fails");
        node.sign(&keypair).unwrap();
        assert_ne!(b"badkey".to_vec(), node._pub_key);
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

        let keypair = Ed2519SigningKey::new();

        let good_json = r#"{
            "randomtext": "Lorem ipsum dolor sit amet"
        }"#
        .to_string();

        let mut node = Node {
            _entity: "TEST".to_string(),
            cdate: now(),
            _json_data: Some(good_json),
            ..Default::default()
        };
        node.sign(&keypair).unwrap();
        node.write(
            &conn,
            true,
            None,
            None,
            Some(String::from("Lorem ipsum dolor sit amet")),
        )
        .unwrap();

        let mut stmt = conn.prepare("SELECT _node.* FROM _node_fts JOIN _node ON _node_fts.rowid=_node.rowid WHERE _node_fts MATCH ? ORDER BY rank;").unwrap();
        let results = stmt.query_map(["Lorem"], Node::from_row()).unwrap();
        let mut res = vec![];
        for node in results {
            let node = node.unwrap();
            node.verify().unwrap();
            res.push(node);
        }
        assert_eq!(1, res.len());
        let id = &res[0].id;

        let results = stmt.query_map(["randomtext"], Node::from_row()).unwrap();
        assert_eq!(0, results.count()); //JSON fields name are not indexed

        let mut rowid_stmt = conn
            .prepare_cached("SELECT rowid FROM _node WHERE id = ?")
            .unwrap();
        let row_id: i64 = rowid_stmt.query_row([id], |row| Ok(row.get(0)?)).unwrap();

        node._json_data = Some(
            r#"{
            "randomtext": "ipsum dolor sit amet Conjectur"
        }"#
            .to_string(),
        );
        //node can be writen without resigning first, which could lead to errors
        node.write(
            &conn,
            true,
            Some(row_id),
            Some(String::from("Lorem ipsum dolor sit amet")),
            Some(String::from("ipsum dolor sit amet Conjectur")),
        )
        .unwrap();

        let results = stmt.query_map(["lorem"], Node::from_row()).unwrap();
        assert_eq!(0, results.count()); //Search table is correctly updated

        let results = stmt.query_map(["conjectur"], Node::from_row()).unwrap();
        assert_eq!(1, results.count()); //Search table is correctly updated

        //
        // Test disabling indexing
        //
        node.write(
            &conn,
            false,
            Some(row_id),
            Some(String::from("ipsum dolor sit amet Conjectur")),
            Some(String::from("will not be inserted")),
        )
        .unwrap();

        let results = stmt.query_map(["lorem"], Node::from_row()).unwrap();
        assert_eq!(0, results.count()); //Search table is correctly updated

        let results = stmt.query_map(["inserted"], Node::from_row()).unwrap();
        assert_eq!(0, results.count()); //Search table is correctly updated
    }
}
