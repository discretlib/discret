use std::time::SystemTime;

use crate::{
    cryptography::{base64_decode, base64_encode, database_id, sign, verify},
    error::Error,
};

use ed25519_dalek::{Keypair, PublicKey, Signature};
use rusqlite::{Connection, OptionalExtension, Row};

use super::database::{FromRow, Writable};

const EDGE_TABLE: &str = "
CREATE TABLE edge (
	source TEXT NOT NULL,
	target TEXT NOT NULL,
	flag TEXT,
	schema TEXT NOT NULL,
	pub_key BLOB,
	signature BLOB,
	PRIMARY KEY (source,target)
) STRICT;

CREATE INDEX edge_target_source_idx(target, source);
";

const SYNCH_LOG_TABLE: &str = "
CREATE TABLE synch_log (
	source TEXT NOT NULL,
	target TEXT NOT NULL,
	schema TEXT NOT NULL,
	target_date INTEGER NOT NULL, 
	cdate INTEGER NOT NULL
) STRICT;

CREATE INDEX synch_log_idx  ON synch_log(source, schema, target_date );";

const DAILY_SYNCH_LOG_TABLE: &str = "
CREATE TABLE daily_synch_log (
	source TEXT NOT NULL,
	schema TEXT NOT NULL,
	day INTEGER NOT NULL,
	previous_day INTEGER,
	daily_hash BLOB,
	history_hash BLOB,
	PRIMARY KEY (source, schema, day)
)STRICT;

CREATE INDEX daily_synch_log_idx  ON synch_log(source, schema, day );
";

fn now() -> u64 {
    SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_millis()
        .try_into()
        .unwrap()
}

pub fn is_initialized(conn: &Connection) -> Result<bool, rusqlite::Error> {
    let initialised: Option<String> = conn
        .query_row(
            "SELECT name FROM sqlite_schema WHERE type IN ('table','view') AND name = 'node_sys'",
            [],
            |row| row.get(0),
        )
        .optional()?;
    Ok(initialised.is_some())
}

pub fn initialise(conn: &Connection) -> Result<(), rusqlite::Error> {
    if !is_initialized(conn)? {
        conn.execute("BEGIN TRANSACTION", [])?;
        println!("creating datamodel");
        Node::create_table(conn)?;

        // conn.execute(NODE_FTS_TABLE, [])?;
        //conn.execute(EDGE_TABLE, [])?;

        conn.execute("COMMIT", [])?;
    }
    Ok(())
}

pub struct Node {
    id: Option<String>,
    schema: String,
    cdate: u64,
    deleted: u64,
    text: Option<String>,
    json: Option<String>,
    pub_key: Option<String>,
    signature: Option<Vec<u8>>,
}
impl Node {
    fn create_table(conn: &Connection) -> Result<(), rusqlite::Error> {
        //system table stores compressed text and json
        conn.execute(
            "CREATE TABLE node_sys (
            id TEXT NOT NULL,
            schema TEXT  NOT NULL,
            cdate INTEGER  NOT NULL,
            deleted INTEGER DEFAULT 0,
            bin_text BLOB,
            bin_json BLOB,
            pub_key TEXT NOT NULL,
            signature BLOB NOT NULL,
            PRIMARY KEY (id)
        ) STRICT",
            [],
        )?;

        conn.execute(
            "CREATE UNIQUE INDEX node_idx  ON node_sys (id, schema, cdate)",
            [],
        )?;

        //node view intended to be used for SELECT, decompress text and json on the fly
        conn.execute(
            " CREATE TEMP VIEW node AS SELECT    
                id,
                schema,
                cdate,
                deleted,
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

    fn hash(&self) -> blake3::Hash {
        let mut hasher = blake3::Hasher::new();
        if let Some(v) = &self.id {
            hasher.update(v.as_bytes());
        }

        hasher.update(self.schema.as_bytes());
        hasher.update(&self.cdate.to_le_bytes());
        hasher.update(&self.deleted.to_le_bytes());

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
    pub fn set_deleted(&mut self){
        self.deleted = 1;
        self.text = None;
        self.json = None;        
    }

    pub fn verify(&mut self) -> Result<(), Error> {
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
        //ensure that the Json field is well formed
        if let Some(v) = &self.json {
            let v: Result<serde_json::Value, serde_json::Error> = serde_json::from_str(v);
            if v.is_err() {
                return Err(Error::from(v.expect_err("already checked")));
            }
        }
        let pubkey = base64_encode(keypair.public.as_bytes().as_slice().into());
        self.pub_key = Some(pubkey);

        if self.id.is_none() {
            let hash = self.hash();
            self.id = Some(database_id(hash));
        }
        let hash = self.hash();
        let signature = sign(keypair, hash.as_bytes());
        self.signature = Some(signature.to_bytes().into());

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
                deleted: row.get(3)?,
                text: row.get(4)?,
                json: row.get(5)?,
                pub_key: row.get(6)?,
                signature: row.get(7)?,
            }))
        }
    }
}
impl Writable for Node {
    //Updates needs to delete old data from the full text search index hence the retrieval of old data before updating
    fn write(&self, conn: &Connection) -> Result<(), Error> {
        let mut insert_fts_stmt = conn.prepare_cached(
            "INSERT INTO node_fts (rowid, fts_text, fts_json) VALUES (?, ?,  json_data(?))",
        )?;

        let mut chek_stmt = conn.prepare_cached("SELECT node.rowid FROM node WHERE id=? ")?;
        let existing_row: Option<i64> = chek_stmt
            .query_row([&self.id], |row| row.get(0))
            .optional()?;

        if let Some(rowid) = existing_row {
            let mut chek_statement =
                conn.prepare_cached("SELECT node.* FROM node WHERE rowid=? ")?;
            let old_node = chek_statement.query_row([&rowid], Node::from_row())?;

            let mut delete_fts_stmt = conn.prepare_cached("INSERT INTO node_fts (node_fts, rowid, fts_text, fts_json) VALUES('delete', ?, ?,  json_data(?))")?;
            delete_fts_stmt.execute((&rowid, &old_node.text, &old_node.json))?;

            let mut update_node_stmt = conn.prepare_cached(
                "
            UPDATE node_sys SET 
                id = ?,
                schema = ?,
                cdate = ?,
                deleted = ?,
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
                &self.cdate,
                &self.deleted,
                &self.text,
                &self.json,
                &self.pub_key,
                &self.signature,
                &rowid,
            ))?;

            insert_fts_stmt.execute((&rowid, &self.text, &self.json))?;
        } else {
            println!("row does not exist");
            let mut insert_stmt = conn.prepare_cached(
            "INSERT INTO node_sys (id, schema, cdate, deleted, bin_text, bin_json,pub_key, signature) 
                                VALUES (?, ?, ?, ?, compress(?), compress(?), ?, ?)")?;

            let rowid = insert_stmt.insert((
                &self.id,
                &self.schema,
                &self.cdate,
                &self.deleted,
                &self.text,
                &self.json,
                &self.pub_key,
                &self.signature,
            ))?;

            insert_fts_stmt.execute((&rowid, &self.text, &self.json))?;
        }

        Ok(())
    }
}

impl Default for Node {
    fn default() -> Self {
        Self {
            id: None,
            schema: "".to_string(),
            cdate: 0,
            deleted: 0,
            text: None,
            json: None,
            pub_key: None,
            signature: None,
        }
    }
}




pub struct Edge {}

#[cfg(test)]
mod tests {

    use crate::cryptography::create_random_key_pair;

    use super::*;
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
            id: None,
            schema: "TEST".to_string(),
            cdate: now(),
            deleted: 0,
            text: None,
            json: None,
            pub_key: None,
            signature: None,
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

        node.id = Some("randokey".to_string());
        node.verify().expect_err("");
        node.sign(&keypair)?;
        node.verify()?;

        node.schema = "re".to_string();
        node.verify().expect_err("");
        node.sign(&keypair)?;
        node.verify()?;

        node.cdate = node.cdate + 1;
        node.verify().expect_err("");
        node.sign(&keypair)?;
        node.verify()?;

        node.deleted = 1;
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

        Ok(())
    }

    #[test]
    fn node_save() -> Result<(), Box<dyn Error>> {
        use crate::{cryptography::hash, datalayer::database::create_connection};

        let path: PathBuf = init_database_path("node_save.db")?;
        let secret = hash(b"secret");
        let conn = create_connection(&path, &secret, 1024, false)?;
        initialise(&conn)?;

        let keypair = create_random_key_pair();
        let text = "Hello World";
        let mut node = Node {
            schema: "TEST".to_string(),
            cdate: now(),
            text: Some(text.to_string()),
            ..Default::default()
        };

        node.sign(&keypair)?;
        node.write(&conn)?;

        let mut stmt = conn.prepare("SELECT node.* FROM node")?;
        let results = stmt.query_map([], Node::from_row())?;
        for res in results {
            let n = *res?;
            assert_eq!(text, n.text.expect("").to_string());
        }
        Ok(())
    }

    #[test]
    fn node_update() -> Result<(), Box<dyn Error>> {
        use crate::{cryptography::hash, datalayer::database::create_connection};

        let path: PathBuf = init_database_path("node_update.db")?;
        let secret = hash(b"secret");
        let conn = create_connection(&path, &secret, 1024, false)?;
        initialise(&conn)?;

        let keypair = create_random_key_pair();
        let text = "Hello World";
        let mut node = Node {
            schema: "TEST".to_string(),
            cdate: now(),
            text: Some(text.to_string()),
            ..Default::default()
        };

        node.sign(&keypair)?;
        node.write(&conn)?;

        let mut stmt = conn.prepare("SELECT node.* FROM node")?;
        let text = "Hello Rust";
        node.text = Some(text.to_string());

        node.sign(&keypair)?;
        node.write(&conn)?;
        let results = stmt.query_map([], Node::from_row())?;
        for res in results {
            let n = *res?;
            assert_eq!(text, n.text.expect("").to_string());
        }
        Ok(())
    }

    #[test]
    fn node_fts() -> Result<(), Box<dyn Error>> {
        use crate::{cryptography::hash, datalayer::database::create_connection};

        let path: PathBuf = init_database_path("node_fts.db")?;
        let secret = hash(b"secret");
        let conn = create_connection(&path, &secret, 1024, false)?;
        initialise(&conn)?;

        let keypair = create_random_key_pair();
        let text = "Lorem ipsum dolor sit amet";
        let mut node = Node {
            schema: "TEST".to_string(),
            cdate: now(),
            text: Some(text.to_string()),
            ..Default::default()
        };

        node.sign(&keypair)?;
        node.write(&conn)?;

        let mut stmt = conn.prepare("SELECT node.* FROM node_fts JOIN node ON node_fts.rowid=node.rowid WHERE node_fts MATCH ? ORDER BY rank;")?;
        let results = stmt.query_map(["Lorem"], Node::from_row())?;
        assert_eq!(1, results.count());

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
