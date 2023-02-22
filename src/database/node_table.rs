use super::{
    database_service::{FromRow, Writable},
    datamodel::{
        database_timed_id, is_valid_id, is_valid_schema, now, RowFlag, MAX_ROW_LENTGH,
        MAX_SCHEMA_SIZE,
    },
    Error,
};
use crate::cryptography::{base64_decode, base64_encode, sign, verify};
use ed25519_dalek::{Keypair, PublicKey, Signature};
use rusqlite::{Connection, OptionalExtension, Row};

pub struct Node {
    pub id: Option<String>,
    pub schema: String,
    pub date: i64,
    pub text: Option<String>,
    pub json: Option<String>,
    pub pub_key: Option<String>,
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
            date INTEGER  NOT NULL,
            flag INTEGER DEFAULT 0,
            bin_text BLOB,
            bin_json BLOB,
            pub_key TEXT NOT NULL,
            signature BLOB NOT NULL,
            PRIMARY KEY(id, date)
        ) STRICT",
            [],
        )?;

        //node view is intended to be used for every SELECT,
        // decompress text and json on the fly
        // and filter deleted nodes
        conn.execute(
            " CREATE TEMP VIEW node AS SELECT    
                id,
                schema,
                date,
                flag,
                decompress_text(bin_text) as text,
                decompress_text(bin_json) as json ,
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
                date,
                flag,
                decompress_text(bin_text) as text,
                decompress_text(bin_json) as json ,
                pub_key,
                signature,
                rowid
            FROM node_sys",
            [],
        )?;

        conn.execute(
            "CREATE VIRTUAL TABLE node_fts USING fts5(fts_text, fts_json, content='' , prefix='2,3' , detail=none)",
            [],
        )?;

        Ok(())
    }
    fn len(&self) -> usize {
        let mut len = 0;
        if let Some(v) = &self.id {
            len += v.as_bytes().len();
        }
        len += self.schema.as_bytes().len();
        len += 8; //date
        len += 1; //flag

        if let Some(v) = &self.text {
            len += v.as_bytes().len();
        }

        if let Some(v) = &self.json {
            len += v.as_bytes().len();
        }

        if let Some(v) = &self.pub_key {
            len += v.as_bytes().len();
        }
        if let Some(v) = &self.signature {
            len += v.len();
        }
        len
    }

    fn hash(&self) -> blake3::Hash {
        let mut hasher = blake3::Hasher::new();
        if let Some(v) = &self.id {
            hasher.update(v.as_bytes());
        }

        hasher.update(self.schema.as_bytes());
        hasher.update(&self.date.to_le_bytes());
        hasher.update(&self.flag.to_le_bytes());

        if let Some(v) = &self.text {
            hasher.update(v.as_bytes());
        }

        if let Some(v) = &self.json {
            hasher.update(v.as_bytes());
        }

        if let Some(v) = &self.pub_key {
            hasher.update(v.as_bytes());
        }

        hasher.finalize()
    }

    // by design, only soft deletes are supported
    // hard deletes are too complex to sign and verify
    pub fn set_deleted(&mut self) {
        self.flag = self.flag | RowFlag::DELETED;
        self.text = None;
        self.json = None;
    }

    pub fn verify(&self) -> Result<(), Error> {
        if let Some(v) = &self.id {
            if !is_valid_id(v) {
                return Err(Error::InvalidDatabaseId());
            }
        }
        if !is_valid_schema(&self.schema) {
            return Err(Error::DatabaseSchemaTooLarge(MAX_SCHEMA_SIZE));
        }

        let size = self.len();
        if size > MAX_ROW_LENTGH {
            return Err(Error::DatabaseRowToLong(format!(
                "Node {} is too long {} bytes instead of {}",
                &self.id.clone().unwrap(),
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

        match &self.pub_key {
            Some(puk) => match &self.signature {
                Some(sig) => {
                    let signature = Signature::from_bytes(sig.as_slice())
                        .map_err(|_| Error::InvalidNode("Invalid Signature".to_string()))?;

                    let key = base64_decode(puk.as_bytes())?;

                    let pk = PublicKey::from_bytes(key.as_slice())
                        .map_err(|_| Error::InvalidNode("Invalid Public Key".to_string()))?;
                    verify(&pk, hash.as_bytes(), &signature)?;
                }
                None => return Err(Error::InvalidNode("Signature is empty".to_string())),
            },
            None => return Err(Error::InvalidNode("Public Key is empty".to_string())),
        }

        Ok(())
    }

    pub fn sign(&mut self, keypair: &Keypair) -> Result<(), Error> {
        let pubkey = base64_encode(keypair.public.as_bytes().as_slice());
        self.pub_key = Some(pubkey);

        if !is_valid_schema(&self.schema) {
            return Err(Error::DatabaseSchemaTooLarge(MAX_SCHEMA_SIZE));
        }

        match &self.id {
            Some(i) => {
                if !is_valid_id(i) {
                    return Err(Error::InvalidDatabaseId());
                }
            }
            None => {
                let hash = self.hash();
                self.id = Some(database_timed_id(self.date, hash.as_bytes()));
            }
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
        let signature = sign(keypair, hash.as_bytes());
        self.signature = Some(signature.to_bytes().into());
        let size = self.len();
        if size > MAX_ROW_LENTGH {
            return Err(Error::DatabaseRowToLong(format!(
                "Node {} is too long {} bytes instead of {}",
                &self.id.clone().unwrap(),
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
                date: row.get(2)?,
                flag: row.get(3)?,
                text: row.get(4)?,
                json: row.get(5)?,
                pub_key: row.get(6)?,
                signature: row.get(7)?,
                ..Default::default()
            }))
        }
    }
}
impl Writable for Node {
    //Updates needs to delete old data from the full text search index hence the retrieval of old data before updating
    fn write(&self, conn: &Connection) -> Result<(), Error> {
        let mut insert_stmt = conn.prepare_cached(
            "INSERT OR REPLACE INTO node_sys (id, schema, date, flag, bin_text, bin_json,pub_key, signature) 
                                VALUES (?, ?, ?, ?, compress(?), compress(?), ?, ?)")?;

        let mut insert_fts_stmt = conn.prepare_cached(
            "INSERT INTO node_fts (rowid, fts_text, fts_json) VALUES (?, ?,  json_data(?))",
        )?;

        let mut chek_stmt = conn
            .prepare_cached("SELECT node_all.rowid FROM node_all WHERE id=? ORDER BY date DESC")?;

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
                    &self.date,
                    &self.flag,
                    &self.text,
                    &self.json,
                    &self.pub_key,
                    &self.signature,
                ))?;
            } else {
                let mut update_node_stmt = conn.prepare_cached(
                    "
            UPDATE node_sys SET 
                id = ?,
                schema = ?,
                date = ?,
                flag = ?,
                bin_text = compress(?),
                bin_json = compress(?),
                pub_key = ?,
                signature = ?
            WHERE
                rowid = ? ",
                )?;

                update_node_stmt.execute((
                    &self.id,
                    &self.schema,
                    &self.date,
                    &self.flag,
                    &self.text,
                    &self.json,
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
                &self.date,
                &self.flag,
                &self.text,
                &self.json,
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
        Self {
            id: None,
            schema: "".to_string(),
            date: now(),
            flag: RowFlag::INDEX_ON_SAVE,
            text: None,
            json: None,
            pub_key: None,
            signature: None,
        }
    }
}

#[cfg(test)]
mod tests {

    use super::*;
    use crate::{cryptography::create_random_key_pair, database::datamodel::initialise_datamodel};
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
    fn node_signature() -> Result<(), Box<dyn Error>> {
        let keypair = create_random_key_pair();
        let mut node = Node {
            schema: "TEST".to_string(),
            ..Default::default()
        };
        node.sign(&keypair)?;
        node.verify()?;

        let id = node.id.clone().expect("");

        node.text = Some("hello world".to_string());
        node.verify().expect_err("");
        node.sign(&keypair)?;
        node.verify()?;

        let newid = node.id.clone().expect("");
        assert_eq!(id, newid);

        node.id = Some("key too short".to_string());
        node.verify().expect_err("");
        node.sign(&keypair).expect_err("");

        node.id = None;
        node.sign(&keypair)?;
        node.verify()?;

        node.schema = "re".to_string();
        node.verify().expect_err("");
        node.sign(&keypair)?;
        node.verify()?;

        node.date = node.date + 1;
        node.verify().expect_err("");
        node.sign(&keypair)?;
        node.verify()?;

        node.flag = 1;
        node.verify().expect_err("");
        node.sign(&keypair)?;
        node.verify()?;

        node.json = Some("f".to_string());
        node.verify().expect_err("");
        node.sign(&keypair).expect_err("");

        node.json = Some("{}".to_string());
        node.sign(&keypair)?;
        node.verify()?;

        node.pub_key = Some("badkey".to_string());
        node.verify().expect_err("");
        node.sign(&keypair)?;
        node.verify()?;

        let sq = &['a'; MAX_ROW_LENTGH];
        let big_string = String::from_iter(sq);
        node.schema = big_string;
        node.verify().expect_err("msg");

        node.sign(&keypair).expect_err("msg");

        Ok(())
    }

    #[test]
    fn node_limits() -> Result<(), Box<dyn Error>> {
        Ok(())
    }

    #[test]
    fn node_write_flags() -> Result<(), Box<dyn Error>> {
        let path: PathBuf = init_database_path("node_flags.db")?;
        let secret = hash(b"secret");
        let conn = create_connection(&path, &secret, 1024, false)?;
        initialise_datamodel(&conn)?;

        let keypair = create_random_key_pair();
        let text = "Hello World";
        let mut node = Node {
            schema: "TEST".to_string(),
            date: now(),
            text: Some(text.to_string()),
            ..Default::default()
        };
        node.sign(&keypair)?;
        node.write(&conn)?;

        let mut stmt = conn.prepare("SELECT count(1) FROM node")?;
        let mut fts_stmt = conn.prepare("SELECT count(1) FROM node_fts JOIN node ON node_fts.rowid=node.rowid WHERE node_fts MATCH 'Hello' ORDER BY rank;")?;

        let results: i64 = stmt.query_row([], |row| row.get(0))?;
        assert_eq!(1, results);
        let results: i64 = fts_stmt.query_row([], |row| row.get(0))?;
        assert_eq!(1, results);

        node.write(&conn)?;

        let results: i64 = stmt.query_row([], |row| row.get(0))?;
        assert_eq!(1, results);
        let results: i64 = fts_stmt.query_row([], |row| row.get(0))?;
        assert_eq!(1, results);

        // println!("flag: {:b}", node.flag);
        node.set_deleted();
        //  println!("flag: {:b}", node.flag);
        node.sign(&keypair)?;
        node.write(&conn)?;

        let results: i64 = stmt.query_row([], |row| row.get(0))?;
        assert_eq!(0, results);
        let results: i64 = fts_stmt.query_row([], |row| row.get(0))?;
        assert_eq!(0, results);

        node.flag = node.flag & !RowFlag::DELETED;
        //println!("flag: {:b}", node.flag);
        node.sign(&keypair)?;
        node.write(&conn)?;
        let results: i64 = stmt.query_row([], |row| row.get(0))?;
        assert_eq!(1, results);
        let results: i64 = fts_stmt.query_row([], |row| row.get(0))?;
        assert_eq!(0, results);

        node.text = Some(text.to_string());
        node.sign(&keypair)?;
        node.write(&conn)?;
        let results: i64 = stmt.query_row([], |row| row.get(0))?;
        assert_eq!(1, results);
        let results: i64 = fts_stmt.query_row([], |row| row.get(0))?;
        assert_eq!(1, results);

        node.flag = node.flag & !RowFlag::INDEX_ON_SAVE;
        //println!("flag: {:b}", node.flag);
        node.sign(&keypair)?;
        node.write(&conn)?;
        let results: i64 = stmt.query_row([], |row| row.get(0))?;
        assert_eq!(1, results);
        let results: i64 = fts_stmt.query_row([], |row| row.get(0))?;
        assert_eq!(0, results);

        node.flag = node.flag | RowFlag::INDEX_ON_SAVE;
        //println!("flag: {:b}", node.flag);
        node.sign(&keypair)?;
        node.write(&conn)?;
        let results: i64 = stmt.query_row([], |row| row.get(0))?;
        assert_eq!(1, results);
        let results: i64 = fts_stmt.query_row([], |row| row.get(0))?;
        assert_eq!(1, results);

        node.flag = node.flag | RowFlag::KEEP_HISTORY;
        //println!("flag: {:b}", node.flag);
        node.sign(&keypair)?;
        node.write(&conn)?;
        let results: i64 = stmt.query_row([], |row| row.get(0))?;
        assert_eq!(1, results);
        let results: i64 = fts_stmt.query_row([], |row| row.get(0))?;
        assert_eq!(1, results);

        node.date = node.date + 1;
        node.sign(&keypair)?;
        node.write(&conn)?;
        let results: i64 = stmt.query_row([], |row| row.get(0))?;
        assert_eq!(2, results);
        let results: i64 = fts_stmt.query_row([], |row| row.get(0))?;
        assert_eq!(1, results);

        Ok(())
    }

    #[test]
    fn node_fts() -> Result<(), Box<dyn Error>> {
        use crate::{cryptography::hash, database::database_service::create_connection};

        let path: PathBuf = init_database_path("node_fts.db")?;
        let secret = hash(b"secret");
        let conn = create_connection(&path, &secret, 1024, false)?;
        initialise_datamodel(&conn)?;

        let keypair = create_random_key_pair();
        let text = "Lorem ipsum dolor sit amet";
        let mut node = Node {
            schema: "TEST".to_string(),
            date: now(),
            text: Some(text.to_string()),
            ..Default::default()
        };

        node.sign(&keypair)?;
        node.write(&conn)?;

        let mut stmt = conn.prepare("SELECT node.* FROM node_fts JOIN node ON node_fts.rowid=node.rowid WHERE node_fts MATCH ? ORDER BY rank;")?;
        let results = stmt.query_map(["Lorem"], Node::from_row())?;
        let mut res = vec![];
        for node in results {
            let node = node?;
            node.verify()?;
            res.push(node);
        }
        assert_eq!(1, res.len());

        let text = " ipsum dolor sit amet";
        node.text = Some(text.to_string());
        node.sign(&keypair)?;
        node.write(&conn)?;
        let results = stmt.query_map(["Lorem"], Node::from_row())?;
        assert_eq!(0, results.count());

        let json = r#"{
            "name": "Lorem ipsum"
        }"#;
        node.json = Some(json.to_string());
        node.sign(&keypair)?;
        node.write(&conn)?;
        let results = stmt.query_map(["Lorem"], Node::from_row())?;
        assert_eq!(1, results.count());

        node.set_deleted();
        node.sign(&keypair)?;
        node.write(&conn)?;
        let results = stmt.query_map(["Lorem"], Node::from_row())?;
        assert_eq!(0, results.count());

        Ok(())
    }
}
