use super::{
    database_service::{FromRow, Writable},
    datamodel::{is_valid_id, now, RowFlag, MAX_ROW_LENTGH},
    Error,
};
use crate::cryptography::{
    base64_decode, base64_encode, Ed2519KeyPair, Ed2519PublicKey, KeyPair, PublicKey,
};
use rusqlite::{Connection, OptionalExtension, Row};

pub struct Edge {
    pub source: String,
    pub target: String,
    pub date: i64,
    pub flag: i8,
    pub json: Option<String>,
    pub pub_key: String,
    pub signature: Option<Vec<u8>>,
}
impl Edge {
    pub fn create_table(conn: &Connection) -> Result<(), rusqlite::Error> {
        conn.execute(
            " 
            CREATE TABLE edge_all (
                source TEXT NOT NULL,
                target TEXT NOT NULL,
                date INTEGER NOT NULL, 
                flag INTEGER DEFAULT 0,
                json TEXT,
                pub_key TEXT,
                signature BLOB,
                PRIMARY KEY (source,target,date)
            ) STRICT;
            ",
            [],
        )?;
        conn.execute(
            " 
            CREATE INDEX edge_target_source_idx ON edge_all(target, source, date)",
            [],
        )?;

        Ok(())
    }

    pub fn create_temporary_view(conn: &Connection) -> Result<(), rusqlite::Error> {
        //this view filter deleted edge
        conn.execute(
            " 
            CREATE TEMP VIEW edge AS SELECT edge_all.* 
            FROM edge_all 
            WHERE flag & 1 = 0",
            [],
        )?;

        Ok(())
    }

    fn len(&self) -> usize {
        let mut len = 0;
        len += &self.source.as_bytes().len();
        len += &self.target.as_bytes().len();

        len += 8; //date
        len += 1; //flag

        if let Some(v) = &self.json {
            len += v.as_bytes().len();
        }

        len += &self.pub_key.as_bytes().len();

        if let Some(v) = &self.signature {
            len += v.len();
        }
        len
    }

    fn hash(&self) -> blake3::Hash {
        let mut hasher = blake3::Hasher::new();
        hasher.update(self.source.as_bytes());
        hasher.update(self.target.as_bytes());
        hasher.update(&self.date.to_le_bytes());
        hasher.update(&self.flag.to_le_bytes());
        if let Some(v) = &self.json {
            hasher.update(v.as_bytes());
        }

        hasher.update(self.pub_key.as_bytes());
        hasher.finalize()
    }

    // by design, only soft deletes are supported
    // edges are kept to ensure that authorisation policy can be checked, even if an authorisation as been removed
    pub fn set_deleted(&mut self) {
        self.flag |= RowFlag::DELETED;
        self.json = None;
    }

    pub fn verify(&self) -> Result<(), Error> {
        let size = self.len();
        if size > MAX_ROW_LENTGH {
            return Err(Error::DatabaseRowToLong(format!(
                "Edge {}-{} is too long {} bytes instead of {}",
                &self.source, &self.target, size, MAX_ROW_LENTGH
            )));
        }

        if !is_valid_id(&self.source) {
            return Err(Error::InvalidDatabaseId());
        }

        if !is_valid_id(&self.target) {
            return Err(Error::InvalidDatabaseId());
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
        if !is_valid_id(&self.source) {
            return Err(Error::InvalidDatabaseId());
        }

        if !is_valid_id(&self.target) {
            return Err(Error::InvalidDatabaseId());
        }

        //ensure that the Json field is well formed
        if let Some(v) = &self.json {
            let v: Result<serde_json::Value, serde_json::Error> = serde_json::from_str(v);
            if v.is_err() {
                return Err(Error::from(v.expect_err("already checked")));
            }
        }

        let pubkey = base64_encode(&keypair.export_public());
        self.pub_key = pubkey;

        let hash = self.hash();

        let signature = keypair.sign(hash.as_bytes());
        self.signature = Some(signature);

        let size = self.len();
        if size > MAX_ROW_LENTGH {
            return Err(Error::DatabaseRowToLong(format!(
                "Edge {}-{} is too long {} bytes instead of {}",
                &self.source, &self.target, size, MAX_ROW_LENTGH
            )));
        }

        Ok(())
    }
}

impl FromRow for Edge {
    fn from_row() -> fn(&Row) -> Result<Box<Self>, rusqlite::Error> {
        |row| {
            Ok(Box::new(Edge {
                source: row.get(0)?,
                target: row.get(1)?,
                date: row.get(2)?,
                flag: row.get(3)?,
                json: row.get(4)?,
                pub_key: row.get(5)?,
                signature: row.get(6)?,
            }))
        }
    }
}

impl Writable for Edge {
    fn write(&self, conn: &Connection) -> Result<(), Error> {
        let mut insert_stmt = conn.prepare_cached(
            "INSERT OR REPLACE INTO edge_all (source, target, date, flag, json, pub_key, signature) 
                            VALUES (?, ?, ?, ?, ?, ?, ?)",
        )?;

        let mut chek_stmt =
            conn.prepare_cached("SELECT edge_all.rowid FROM edge_all WHERE source=? AND target=?")?;
        let existing_row: Option<i64> = chek_stmt
            .query_row([&self.source, &self.target], |row| row.get(0))
            .optional()?;

        if let Some(rowid) = existing_row {
            if RowFlag::is(RowFlag::KEEP_HISTORY, &self.flag) {
                insert_stmt.execute((
                    &self.source,
                    &self.target,
                    &self.date,
                    &self.flag,
                    &self.json,
                    &self.pub_key,
                    &self.signature,
                ))?;
            } else {
                let mut update_node_stmt = conn.prepare_cached(
                    "
            UPDATE edge_all SET 
                source = ?,
                target = ?,
                date = ?,
                flag = ?,
                json = ?,
                pub_key = ?,
                signature = ?
            WHERE
                rowid = ? ",
                )?;

                update_node_stmt.execute((
                    &self.source,
                    &self.target,
                    &self.date,
                    &self.flag,
                    &self.json,
                    &self.pub_key,
                    &self.signature,
                    &rowid,
                ))?;
            }
        } else {
            //    println!("row does not exist");

            insert_stmt.execute((
                &self.source,
                &self.target,
                &self.date,
                &self.flag,
                &self.json,
                &self.pub_key,
                &self.signature,
            ))?;
        }
        Ok(())
    }
}

impl Default for Edge {
    fn default() -> Self {
        Self {
            source: "".to_string(),
            target: "".to_string(),
            date: now(),
            flag: 0,
            json: None,
            pub_key: "".to_string(),
            signature: None,
        }
    }
}

#[cfg(test)]
mod tests {

    use crate::{
        cryptography::{hash, Ed2519KeyPair, KeyPair},
        database::{
            database_service::create_connection,
            datamodel::{new_id, prepare_connection, DB_ID_MAX_SIZE},
        },
    };

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
    fn edge_signature() {
        let keypair = Ed2519KeyPair::new();
        let source = new_id(10);
        let target = new_id(10);
        let mut e = Edge {
            source: source.clone(),
            target,
            ..Default::default()
        };

        e.sign(&keypair).unwrap();
        e.verify().unwrap();

        let bads = new_id(10);
        e.source = bads.clone();
        e.verify().expect_err("msg");
        e.source = source;
        e.verify().unwrap();

        e.target = bads;
        e.verify().expect_err("msg");
        e.sign(&keypair).unwrap();
        e.verify().unwrap();

        e.date = e.date + 1;
        e.verify().expect_err("msg");
        e.sign(&keypair).unwrap();
        e.verify().unwrap();

        e.flag = 5;
        e.verify().expect_err("msg");
        e.sign(&keypair).unwrap();
        e.verify().unwrap();
        let signature = e.signature.clone();

        e.json = Some("{}".to_string());
        e.verify().expect_err("msg");
        e.sign(&keypair).unwrap();
        e.verify().unwrap();

        let badk = Ed2519KeyPair::new();
        e.pub_key = base64_encode(&badk.export_public()[..]);
        e.verify().expect_err("msg");
        e.sign(&keypair).unwrap();

        e.signature = signature;
        e.verify().expect_err("msg");
    }

    #[test]
    fn edge_limit_test() {
        let keypair = Ed2519KeyPair::new();
        let source = new_id(10);

        let mut e = Edge {
            source: source.clone(),
            target: source.clone(),
            ..Default::default()
        };
        e.sign(&keypair).unwrap();
        e.verify().unwrap();

        e.source = "".to_string();
        e.verify().expect_err("msg");
        e.sign(&keypair).expect_err("msg");

        e.source = source.clone();
        e.target = "".to_string();
        e.verify().expect_err("msg");
        e.sign(&keypair).expect_err("msg");

        e.target = source.clone();
        e.sign(&keypair).unwrap();
        e.verify().unwrap();

        e.json = Some("{ezaeaz]".to_string());
        e.verify().expect_err("msg");
        e.sign(&keypair).expect_err("msg");

        e.json = Some("{}".to_string());
        e.sign(&keypair).unwrap();
        e.verify().unwrap();

        let arr = [0 as u8; DB_ID_MAX_SIZE];

        e.target = base64_encode(&arr);
        e.verify().expect_err("msg");
        e.sign(&keypair).expect_err("msg");

        let arr = [0 as u8; MAX_ROW_LENTGH];

        e.json = Some(format!("[\"{}\" ]", base64_encode(&arr)));
        e.verify().expect_err("msg");
        e.sign(&keypair).expect_err("msg");
    }

    #[test]
    fn edge_save() {
        let path: PathBuf = init_database_path("edge_save.db").unwrap();
        let secret = hash(b"secret");
        let conn = create_connection(&path, &secret, 1024, false).unwrap();
        prepare_connection(&conn).unwrap();

        let keypair = Ed2519KeyPair::new();
        let source = new_id(10);
        let target = new_id(10);
        let mut e = Edge {
            source: source.clone(),
            target,
            ..Default::default()
        };
        e.sign(&keypair).unwrap();
        e.write(&conn).unwrap();

        let mut stmt = conn.prepare("SELECT edge.* FROM edge").unwrap();
        let results = stmt.query_map([], Edge::from_row()).unwrap();
        let mut res = vec![];
        for ed in results {
            let edge = ed.unwrap();
            edge.verify().unwrap();
            res.push(edge);
        }
        assert_eq!(1, res.len());

        e.sign(&keypair).unwrap();
        e.write(&conn).unwrap();
        let results = stmt.query_map([], Edge::from_row()).unwrap();
        assert_eq!(1, results.count());
        e.set_deleted();
        e.sign(&keypair).unwrap();
        e.write(&conn).unwrap();

        let results = stmt.query_map([], Edge::from_row()).unwrap();
        assert_eq!(0, results.count());

        e.flag = e.flag & !RowFlag::DELETED;
        e.sign(&keypair).unwrap();
        e.write(&conn).unwrap();

        let results = stmt.query_map([], Edge::from_row()).unwrap();
        assert_eq!(1, results.count());

        e.flag = RowFlag::KEEP_HISTORY;
        e.sign(&keypair).unwrap();
        e.write(&conn).unwrap();
        let results = stmt.query_map([], Edge::from_row()).unwrap();
        assert_eq!(1, results.count());

        e.date = e.date + 1;
        e.sign(&keypair).unwrap();
        e.write(&conn).unwrap();
        let results = stmt.query_map([], Edge::from_row()).unwrap();
        assert_eq!(2, results.count());
    }
}
