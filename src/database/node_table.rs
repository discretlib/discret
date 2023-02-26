use super::{
    database_service::{FromRow, Writable},
    datamodel::{is_valid_id, new_id, now, RowFlag, MAX_ROW_LENTGH},
    Error,
};
use crate::cryptography::{
    base64_decode, base64_encode, Ed2519KeyPair, Ed2519PublicKey, KeyPair, PublicKey,
};
use rusqlite::{Connection, OptionalExtension, Row};

//arbritrary choosen max numbers of char in a schema
pub const MAX_SCHEMA_SIZE: usize = 22;
pub fn is_valid_schema(schema: &String) -> bool {
    schema.as_bytes().len() <= MAX_SCHEMA_SIZE && !schema.is_empty()
}

pub struct Node {
    pub id: String,
    pub schema: String,
    pub cdate: i64,
    pub mdate: i64,
    pub text: Option<String>,
    pub json: Option<String>,
    pub binary: Option<Vec<u8>>,
    pub pub_key: String,
    pub signature: Option<Vec<u8>>,
    pub flag: i8,
}

impl Node {
    pub fn create_table(conn: &Connection) -> Result<(), rusqlite::Error> {
        //system table stores compressed text and json
        conn.execute(
            "CREATE TABLE node_sys (
            id TEXT NOT NULL,
            schema TEXT  NOT NULL,
            cdate INTEGER  NOT NULL,
            mdate INTEGER  NOT NULL,
            flag INTEGER DEFAULT 0,
            bin_text BLOB,
            bin_json BLOB,
            binary BLOB,
            pub_key TEXT NOT NULL,
            signature BLOB NOT NULL,
            PRIMARY KEY(id, mdate)
        ) STRICT",
            [],
        )?;

        conn.execute(
            "CREATE VIRTUAL TABLE node_fts USING fts5(fts_text, fts_json, content='' , prefix='2,3' , detail=none)",
            [],
        )?;

        Ok(())
    }

    pub fn create_temporary_view(conn: &Connection) -> Result<(), rusqlite::Error> {
        //this view filter deleted edge
        //node view is intended to be used for every SELECT,
        // decompress text and json on the fly
        // and filter deleted nodes
        conn.execute(
            " CREATE TEMP VIEW node AS SELECT    
                id,
                schema,
                cdate,
                mdate,
                flag,
                decompress_text(bin_text) as text,
                decompress_text(bin_json) as json ,
                binary,
                pub_key,
                signature,
                rowid
            FROM node_sys 
            WHERE flag & 1 = 0",
            [],
        )?;

        //node view that contains the deleted nodes
        conn.execute(
            " CREATE TEMP VIEW node_all AS SELECT    
                id,
                schema,
                cdate,
                mdate,
                flag,
                decompress_text(bin_text) as text,
                decompress_text(bin_json) as json ,
                binary,
                pub_key,
                signature,
                rowid
            FROM node_sys",
            [],
        )?;
        Ok(())
    }

    fn len(&self) -> usize {
        let mut len = 0;

        len += self.id.as_bytes().len();

        len += self.schema.as_bytes().len();
        len += 8; //date
        len += 8; //cdate
        len += 1; //flag

        if let Some(v) = &self.text {
            len += v.as_bytes().len();
        }

        if let Some(v) = &self.json {
            len += v.as_bytes().len();
        }
        if let Some(v) = &self.binary {
            len += v.len();
        }

        len += &self.pub_key.as_bytes().len();

        if let Some(v) = &self.signature {
            len += v.len();
        }
        len
    }

    fn hash(&self) -> blake3::Hash {
        let mut hasher = blake3::Hasher::new();

        hasher.update(self.id.as_bytes());
        hasher.update(self.schema.as_bytes());
        hasher.update(&self.cdate.to_le_bytes());
        hasher.update(&self.mdate.to_le_bytes());
        hasher.update(&self.flag.to_le_bytes());

        if let Some(v) = &self.text {
            hasher.update(v.as_bytes());
        }

        if let Some(v) = &self.json {
            hasher.update(v.as_bytes());
        }

        if let Some(v) = &self.binary {
            hasher.update(v);
        }

        hasher.update(self.pub_key.as_bytes());

        hasher.finalize()
    }

    // by design, only soft deletes are supported
    // hard deletes are too complex to sign and verify
    pub fn set_deleted(&mut self) {
        self.flag |= RowFlag::DELETED;
        self.text = None;
        self.json = None;
    }

    pub fn verify(&self) -> Result<(), Error> {
        if !is_valid_id(&self.id) {
            return Err(Error::InvalidDatabaseId());
        }

        if !is_valid_schema(&self.schema) {
            return Err(Error::InvalidNodeSchema(MAX_SCHEMA_SIZE));
        }

        let size = self.len();
        if size > MAX_ROW_LENTGH {
            return Err(Error::DatabaseRowToLong(format!(
                "Node {} is too long {} bytes instead of {}",
                &self.id.clone(),
                size,
                MAX_ROW_LENTGH
            )));
        }

        //ensure that the Json field is well formed
        if let Some(v) = &self.json {
            let v: Result<serde_json::Value, serde_json::Error> = serde_json::from_str(v);
            if v.is_err() {
                return Err(Error::from(v.expect_err("msg")));
            }
        }
        let hash = self.hash();

        match &self.signature {
            Some(sig) => {
                let key = base64_decode(self.pub_key.as_bytes())?;

                let pub_key = Ed2519PublicKey::import(&key)?;
                pub_key.verify(hash.as_bytes(), sig)?;
            }
            None => return Err(Error::InvalidNode("Signature is empty".to_string())),
        }

        Ok(())
    }

    pub fn sign(&mut self, keypair: &Ed2519KeyPair) -> Result<(), Error> {
        let pubkey = base64_encode(&keypair.export_public());
        self.pub_key = pubkey;

        if !is_valid_schema(&self.schema) {
            return Err(Error::InvalidNodeSchema(MAX_SCHEMA_SIZE));
        }

        if !is_valid_id(&self.id) {
            return Err(Error::InvalidDatabaseId());
        }

        //ensure that the Json field is well formed
        if let Some(v) = &self.json {
            let v: Result<serde_json::Value, serde_json::Error> = serde_json::from_str(v);
            if v.is_err() {
                // println!("Error id:{}",self.text.clone().unwrap() );
                return Err(Error::from(v.expect_err("already checked")));
            }
        }

        let hash = self.hash();
        let signature = keypair.sign(hash.as_bytes());
        self.signature = Some(signature);
        let size = self.len();
        if size > MAX_ROW_LENTGH {
            return Err(Error::DatabaseRowToLong(format!(
                "Node {} is too long {} bytes instead of {}",
                &self.id.clone(),
                size,
                MAX_ROW_LENTGH
            )));
        }
        Ok(())
    }
}

impl FromRow for Node {
    fn from_row() -> fn(&Row) -> Result<Box<Self>, rusqlite::Error> {
        |row| {
            Ok(Box::new(Node {
                id: row.get(0)?,
                schema: row.get(1)?,
                cdate: row.get(2)?,
                mdate: row.get(3)?,
                flag: row.get(4)?,
                text: row.get(5)?,
                json: row.get(6)?,
                binary: row.get(7)?,
                pub_key: row.get(8)?,
                signature: row.get(9)?,
            }))
        }
    }
}
impl Writable for Node {
    //Updates needs to delete old data from the full text search index hence the retrieval of old data before updating
    fn write(&self, conn: &Connection) -> Result<(), Error> {
        let mut insert_stmt = conn.prepare_cached(
            "INSERT OR REPLACE INTO node_sys (id, schema, cdate, mdate, flag, bin_text, bin_json, binary, pub_key, signature) 
                                VALUES (?, ?, ?, ?, ?, compress(?), compress(?),?, ?, ?)")?;

        let mut insert_fts_stmt = conn.prepare_cached(
            "INSERT INTO node_fts (rowid, fts_text, fts_json) VALUES (?, ?,  json_data(?))",
        )?;

        let mut chek_stmt = conn
            .prepare_cached("SELECT node_all.rowid FROM node_all WHERE id=? ORDER BY mdate DESC")?;

        let existing_row: Option<i64> = chek_stmt
            .query_row([&self.id], |row| row.get(0))
            .optional()?;

        if let Some(mut rowid) = existing_row {
            let mut chek_statement =
                conn.prepare_cached("SELECT node_all.* FROM node_all WHERE rowid=?")?;
            let old_node = chek_statement.query_row([&rowid], Node::from_row())?;

            //delete previously indexed data
            if RowFlag::is(RowFlag::INDEX_ON_SAVE, &old_node.flag) {
                let mut delete_fts_stmt = conn.prepare_cached("INSERT INTO node_fts (node_fts, rowid, fts_text, fts_json) VALUES('delete', ?, ?,  json_data(?))")?;
                delete_fts_stmt.execute((&rowid, &old_node.text, &old_node.json))?;
            }

            if RowFlag::is(RowFlag::KEEP_HISTORY, &self.flag) {
                rowid = insert_stmt.insert((
                    &self.id,
                    &self.schema,
                    &self.cdate,
                    &self.mdate,
                    &self.flag,
                    &self.text,
                    &self.json,
                    &self.binary,
                    &self.pub_key,
                    &self.signature,
                ))?;
            } else {
                let mut update_node_stmt = conn.prepare_cached(
                    "
            UPDATE node_sys SET 
                id = ?,
                schema = ?,
                cdate = ?,
                mdate = ?,
                flag = ?,
                bin_text = compress(?),
                bin_json = compress(?),
                binary = ?,
                pub_key = ?,
                signature = ?
            WHERE
                rowid = ? ",
                )?;

                update_node_stmt.execute((
                    &self.id,
                    &self.schema,
                    &self.cdate,
                    &self.mdate,
                    &self.flag,
                    &self.text,
                    &self.json,
                    &self.binary,
                    &self.pub_key,
                    &self.signature,
                    &rowid,
                ))?;
            }
            if RowFlag::is(RowFlag::INDEX_ON_SAVE, &self.flag) {
                insert_fts_stmt.execute((&rowid, &self.text, &self.json))?;
            }
        } else {
            let rowid = insert_stmt.insert((
                &self.id,
                &self.schema,
                &self.cdate,
                &self.mdate,
                &self.flag,
                &self.text,
                &self.json,
                &self.binary,
                &self.pub_key,
                &self.signature,
            ))?;

            if RowFlag::is(RowFlag::INDEX_ON_SAVE, &self.flag) {
                insert_fts_stmt.execute((&rowid, &self.text, &self.json))?;
            }
        }

        Ok(())
    }
}

impl Default for Node {
    fn default() -> Self {
        let date = now();
        Self {
            id: new_id(now()),
            schema: "".to_string(),
            cdate: date,
            mdate: date,
            flag: RowFlag::INDEX_ON_SAVE,
            text: None,
            json: None,
            binary: None,
            pub_key: "".to_string(),
            signature: None,
        }
    }
}

#[cfg(test)]
mod tests {

    use super::*;
    use crate::database::datamodel::prepare_connection;
    use crate::{cryptography::hash, database::database_service::create_connection};

    use std::{
        error::Error,
        fs,
        path::{Path, PathBuf},
    };

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
    fn node_signature() {
        let keypair = Ed2519KeyPair::new();
        let mut node = Node {
            schema: "TEST".to_string(),
            ..Default::default()
        };
        node.sign(&keypair).unwrap();
        node.verify().unwrap();

        let id = node.id.clone();

        node.text = Some("hello world".to_string());
        node.verify().expect_err("");
        node.sign(&keypair).unwrap();
        node.verify().unwrap();

        let newid = node.id.clone();
        assert_eq!(id, newid);

        node.id = "key too short".to_string();
        node.verify().expect_err("");
        node.sign(&keypair).expect_err("");

        node.id = new_id(now());
        node.sign(&keypair).unwrap();
        node.verify().unwrap();

        node.schema = "re".to_string();
        node.verify().expect_err("");
        node.sign(&keypair).unwrap();
        node.verify().unwrap();

        node.cdate = node.cdate + 1;
        node.verify().expect_err("");
        node.sign(&keypair).unwrap();
        node.verify().unwrap();

        node.mdate = node.mdate + 1;
        node.verify().expect_err("");
        node.sign(&keypair).unwrap();
        node.verify().unwrap();

        node.flag = 1;
        node.verify().expect_err("");
        node.sign(&keypair).unwrap();
        node.verify().unwrap();

        node.json = Some("f".to_string());
        node.verify().expect_err("");
        node.sign(&keypair).expect_err("");

        node.json = Some("{}".to_string());
        node.sign(&keypair).unwrap();
        node.verify().unwrap();

        node.binary = Some(vec![1, 2, 3]);
        node.verify().expect_err("");
        node.sign(&keypair).unwrap();
        node.verify().unwrap();

        node.pub_key = "badkey".to_string();
        node.verify().expect_err("");
        node.sign(&keypair).unwrap();
        node.verify().unwrap();

        let sq = &['a'; MAX_ROW_LENTGH];
        let big_string = String::from_iter(sq);
        node.schema = big_string;
        node.verify().expect_err("msg");

        node.sign(&keypair).expect_err("msg");
    }

    #[test]
    fn node_write_flags() {
        let path: PathBuf = init_database_path("node_flags.db").unwrap();
        let secret = hash(b"secret");
        let conn = create_connection(&path, &secret, 1024, false).unwrap();
        prepare_connection(&conn).unwrap();

        let keypair = Ed2519KeyPair::new();
        let text = "Hello World";
        let mut node = Node {
            schema: "TEST".to_string(),
            cdate: now(),
            text: Some(text.to_string()),
            ..Default::default()
        };
        node.sign(&keypair).unwrap();
        node.write(&conn).unwrap();

        let mut stmt = conn.prepare("SELECT count(1) FROM node").unwrap();
        let mut fts_stmt = conn.prepare("SELECT count(1) FROM node_fts JOIN node ON node_fts.rowid=node.rowid WHERE node_fts MATCH 'Hello' ORDER BY rank;").unwrap();

        let results: i64 = stmt.query_row([], |row| row.get(0)).unwrap();
        assert_eq!(1, results);
        let results: i64 = fts_stmt.query_row([], |row| row.get(0)).unwrap();
        assert_eq!(1, results);

        node.write(&conn).unwrap();

        let results: i64 = stmt.query_row([], |row| row.get(0)).unwrap();
        assert_eq!(1, results);
        let results: i64 = fts_stmt.query_row([], |row| row.get(0)).unwrap();
        assert_eq!(1, results);

        // println!("flag: {:b}", node.flag);
        node.set_deleted();
        //  println!("flag: {:b}", node.flag);
        node.sign(&keypair).unwrap();
        node.write(&conn).unwrap();

        let results: i64 = stmt.query_row([], |row| row.get(0)).unwrap();
        assert_eq!(0, results);
        let results: i64 = fts_stmt.query_row([], |row| row.get(0)).unwrap();
        assert_eq!(0, results);

        node.flag = node.flag & !RowFlag::DELETED;
        //println!("flag: {:b}", node.flag);
        node.sign(&keypair).unwrap();
        node.write(&conn).unwrap();
        let results: i64 = stmt.query_row([], |row| row.get(0)).unwrap();
        assert_eq!(1, results);
        let results: i64 = fts_stmt.query_row([], |row| row.get(0)).unwrap();
        assert_eq!(0, results);

        node.text = Some(text.to_string());
        node.sign(&keypair).unwrap();
        node.write(&conn).unwrap();
        let results: i64 = stmt.query_row([], |row| row.get(0)).unwrap();
        assert_eq!(1, results);
        let results: i64 = fts_stmt.query_row([], |row| row.get(0)).unwrap();
        assert_eq!(1, results);

        node.flag = node.flag & !RowFlag::INDEX_ON_SAVE;
        //println!("flag: {:b}", node.flag);
        node.sign(&keypair).unwrap();
        node.write(&conn).unwrap();
        let results: i64 = stmt.query_row([], |row| row.get(0)).unwrap();
        assert_eq!(1, results);
        let results: i64 = fts_stmt.query_row([], |row| row.get(0)).unwrap();
        assert_eq!(0, results);

        node.flag = node.flag | RowFlag::INDEX_ON_SAVE;
        //println!("flag: {:b}", node.flag);
        node.sign(&keypair).unwrap();
        node.write(&conn).unwrap();
        let results: i64 = stmt.query_row([], |row| row.get(0)).unwrap();
        assert_eq!(1, results);
        let results: i64 = fts_stmt.query_row([], |row| row.get(0)).unwrap();
        assert_eq!(1, results);

        node.flag = node.flag | RowFlag::KEEP_HISTORY;
        //println!("flag: {:b}", node.flag);
        node.sign(&keypair).unwrap();
        node.write(&conn).unwrap();
        let results: i64 = stmt.query_row([], |row| row.get(0)).unwrap();
        assert_eq!(1, results);
        let results: i64 = fts_stmt.query_row([], |row| row.get(0)).unwrap();
        assert_eq!(1, results);

        node.mdate = node.mdate + 1;
        node.sign(&keypair).unwrap();
        node.write(&conn).unwrap();
        let results: i64 = stmt.query_row([], |row| row.get(0)).unwrap();
        assert_eq!(2, results);
        let results: i64 = fts_stmt.query_row([], |row| row.get(0)).unwrap();
        assert_eq!(1, results);
    }

    #[test]
    fn node_fts() {
        use crate::{cryptography::hash, database::database_service::create_connection};

        let path: PathBuf = init_database_path("node_fts.db").unwrap();
        let secret = hash(b"secret");
        let conn = create_connection(&path, &secret, 1024, false).unwrap();
        prepare_connection(&conn).unwrap();

        let keypair = Ed2519KeyPair::new();
        let text = "Lorem ipsum dolor sit amet";
        let mut node = Node {
            schema: "TEST".to_string(),
            cdate: now(),
            text: Some(text.to_string()),
            ..Default::default()
        };

        node.sign(&keypair).unwrap();
        node.write(&conn).unwrap();

        let mut stmt = conn.prepare("SELECT node.* FROM node_fts JOIN node ON node_fts.rowid=node.rowid WHERE node_fts MATCH ? ORDER BY rank;").unwrap();
        let results = stmt.query_map(["Lorem"], Node::from_row()).unwrap();
        let mut res = vec![];
        for node in results {
            let node = node.unwrap();
            node.verify().unwrap();
            res.push(node);
        }
        assert_eq!(1, res.len());

        let text = " ipsum dolor sit amet";
        node.text = Some(text.to_string());
        node.sign(&keypair).unwrap();
        node.write(&conn).unwrap();
        let results = stmt.query_map(["Lorem"], Node::from_row()).unwrap();
        assert_eq!(0, results.count());

        let json = r#"{
            "name": "Lorem ipsum"
        }"#;
        node.json = Some(json.to_string());
        node.sign(&keypair).unwrap();
        node.write(&conn).unwrap();
        let results = stmt.query_map(["Lorem"], Node::from_row()).unwrap();
        assert_eq!(1, results.count());

        node.set_deleted();
        node.sign(&keypair).unwrap();
        node.write(&conn).unwrap();
        let results = stmt.query_map(["Lorem"], Node::from_row()).unwrap();
        assert_eq!(0, results.count());
    }
}
