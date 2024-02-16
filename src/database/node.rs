use super::{
    graph_database::{new_id, now, valid_id_len, FromRow, Statement, MAX_ROW_LENTGH},
    Error, Result,
};
use crate::cryptography::{
    base64_encode, Ed2519PublicKey, Ed2519SigningKey, PublicKey, SigningKey,
};
use rusqlite::{Connection, OptionalExtension, Row};
use serde::{Deserialize, Serialize};

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

    fn len(&self) -> usize {
        let mut len = 0;
        len += self.id.len();
        len += 8; //date
        len += 8; //cdate
        len += self._entity.as_bytes().len();

        if let Some(v) = &self._json_data {
            len += v.as_bytes().len();
        }

        if let Some(v) = &self._binary_data {
            len += v.len();
        }

        len += &self._pub_key.len();
        len += &self._signature.len();
        len
    }

    fn hash(&self) -> blake3::Hash {
        let mut hasher = blake3::Hasher::new();

        hasher.update(&self.id);
        hasher.update(&self.cdate.to_le_bytes());
        hasher.update(&self.mdate.to_le_bytes());
        hasher.update(self._entity.as_bytes());

        if let Some(v) = &self._json_data {
            hasher.update(v.as_bytes());
        }

        if let Some(v) = &self._binary_data {
            hasher.update(v);
        }

        hasher.update(&self._pub_key);
        hasher.finalize()
    }

    pub fn verify(&self) -> Result<()> {
        if !valid_id_len(&self.id) {
            return Err(Error::InvalidId());
        }

        let size = self.len();
        if size > MAX_ROW_LENTGH.try_into().unwrap() {
            return Err(Error::DatabaseRowToLong(format!(
                "Node {} is too large. {} bytes instead of {}",
                base64_encode(&self.id),
                size,
                MAX_ROW_LENTGH
            )));
        }

        //ensure that the Json field is well formed
        if let Some(v) = &self._json_data {
            let v: std::result::Result<serde_json::Value, serde_json::Error> =
                serde_json::from_str(v);
            if v.is_err() {
                return Err(Error::from(v.expect_err("this is an error")));
            }
        }
        let hash = self.hash();

        let pub_key = Ed2519PublicKey::import(&self._pub_key)?;
        pub_key.verify(hash.as_bytes(), &self._signature)?;

        Ok(())
    }

    pub fn sign(&mut self, keypair: &Ed2519SigningKey) -> Result<()> {
        self._pub_key = keypair.export_public();

        if !valid_id_len(&self.id) {
            return Err(Error::InvalidId());
        }

        //ensure that the Json field is well formed
        if let Some(v) = &self._json_data {
            let v: std::result::Result<serde_json::Value, serde_json::Error> =
                serde_json::from_str(v);
            if v.is_err() {
                // println!("Error id:{}",self.text.clone().unwrap() );
                return Err(Error::from(v.expect_err("this is an error")));
            }
        }

        let size = self.len();
        if size > MAX_ROW_LENTGH.try_into().unwrap() {
            return Err(Error::DatabaseRowToLong(format!(
                "Node {} is too long {} bytes instead of {}",
                base64_encode(&self.id.clone()),
                size,
                MAX_ROW_LENTGH
            )));
        }

        let hash = self.hash();
        let signature = keypair.sign(hash.as_bytes());
        self._signature = signature;

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
impl Statement for Node {
    //Updates needs to delete old data from the full text search index. To do so it must retrieve of old data before updating
    fn execute(&self, conn: &Connection) -> Result<Vec<String>> {
        let mut insert_fts_stmt =
            conn.prepare_cached("INSERT INTO _node_fts (rowid, text) VALUES (?, json_data(?))")?;

        let mut chek_stmt = conn
            .prepare_cached("SELECT rowid , _json_data FROM _node WHERE id = ? AND _entity = ?")?;

        struct PreviousRow(i64, String);

        let previous_row = chek_stmt
            .query_row((&self.id, &self._entity), |row| {
                Ok(PreviousRow(row.get(0)?, row.get(1)?))
            })
            .optional()?;

        if let Some(old_row) = previous_row {
            let mut delete_fts_stmt = conn.prepare_cached(
                "INSERT INTO _node_fts (_node_fts, rowid, text) VALUES('delete', ?, json_data(?))",
            )?;
            delete_fts_stmt.execute((&old_row.0, &old_row.1))?;
            insert_fts_stmt.execute((&old_row.0, &self._json_data))?;

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
                &old_row.0,
            ))?;
            //   invalidate_updated_node_log(&old_node.id, old_node.mdate, conn)?;
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

            insert_fts_stmt.execute((&rowid, &self._json_data))?;
        }

        Ok(Vec::new())
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
    use crate::database::graph_database::add_json_data_function;

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

        node._json_data = Some("f".to_string());
        node.verify().expect_err("Invalid json");
        node.sign(&keypair).expect_err("Invalid json");

        node._json_data = Some("{}".to_string());
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
        add_json_data_function(&conn).unwrap();
        let keypair = Ed2519SigningKey::new();
        let mut node = Node {
            _entity: "TEST".to_string(),
            cdate: now(),
            _json_data: Some(String::from(
                r#"{ "randomtext": "Lorem ipsum dolor sit amet"}"#,
            )),
            ..Default::default()
        };
        node.sign(&keypair).unwrap();
        node.execute(&conn).unwrap();

        let mut stmt = conn.prepare("SELECT _node.* FROM _node_fts JOIN _node ON _node_fts.rowid=_node.rowid WHERE _node_fts MATCH ? ORDER BY rank;").unwrap();
        let results = stmt.query_map(["Lorem"], Node::from_row()).unwrap();
        let mut res = vec![];
        for node in results {
            let node = node.unwrap();
            node.verify().unwrap();
            res.push(node);
        }
        assert_eq!(1, res.len());

        let results = stmt.query_map(["randomtext"], Node::from_row()).unwrap();
        assert_eq!(0, results.count()); //JSON fields name are not indexed

        node._json_data = Some(String::from(
            r#"{ "randomtext": "ipsum dolor sit amet conjectur"}"#,
        ));
        //node can be writen without resigning first, which could lead to errors
        node.execute(&conn).unwrap();
        let results = stmt.query_map(["lorem"], Node::from_row()).unwrap();
        assert_eq!(0, results.count()); //Search table is correctly updated

        let results = stmt.query_map(["conjectur"], Node::from_row()).unwrap();
        assert_eq!(1, results.count()); //Search table is correctly updated
    }
}
