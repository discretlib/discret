use super::{
    database_service::{FromRow, Writable},
    datamodel::{is_valid_id, now, RowFlag, DB_ID_MIN_SIZE, MAX_ROW_LENTGH},
};
use crate::{
    cryptography::{base64_decode, base64_encode, sign, verify},
    error::Error,
};
use ed25519_dalek::{Keypair, PublicKey, Signature};
use rusqlite::{Connection, OptionalExtension, Row};

pub struct Edge {
    pub source: String,
    pub target: String,
    pub date: i64,
    pub flag: i8,
    pub json: Option<String>,
    pub pub_key: Option<String>,
    pub signature: Option<Vec<u8>>,
}
impl Edge {
    pub fn create_table(conn: &Connection) -> Result<(), rusqlite::Error> {
        conn.execute(
            " 
            CREATE TABLE edge (
                source TEXT NOT NULL,
                target TEXT NOT NULL,
                date INTEGER NOT NULL, 
                flag INTEGER DEFAULT 0,
                json TEXT,
                pub_key BLOB,
                signature BLOB,
                PRIMARY KEY (source,target,date)
            ) STRICT;
            ",
            [],
        )?;
        conn.execute(
            " 
            CREATE INDEX edge_target_source_idx ON edge(target, source, date)",
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

        hasher.update(self.source.as_bytes());
        hasher.update(self.target.as_bytes());
        hasher.update(&self.date.to_le_bytes());
        hasher.update(&self.flag.to_le_bytes());
        if let Some(v) = &self.json {
            hasher.update(v.as_bytes());
        }

        if let Some(v) = &self.pub_key {
            hasher.update(v.as_bytes());
        }
        if let Some(v) = &self.signature {
            hasher.update(v);
        }

        hasher.finalize()
    }

    // by design, only soft deletes are supported
    // edges are kept to ensure that authorisation policy can be checked, even if an authorisation as been removed
    pub fn set_deleted(&mut self) {
        self.flag = self.flag | RowFlag::DELETED;
        self.json = None;
    }

    pub fn verify(&mut self) -> Result<(), Error> {
        let size = self.len();
        if size > MAX_ROW_LENTGH {
            return Err(Error::DatabaseRowToLong(format!(
                "Edge {}-{} is too long {} bytes instead of {}",
                &self.source, &self.target, size, MAX_ROW_LENTGH
            )));
        }

        if !is_valid_id(&self.source) {
            return Err(Error::DatabaseIdTooSmall(DB_ID_MIN_SIZE));
        }

        if !is_valid_id(&self.target) {
            return Err(Error::DatabaseIdTooSmall(DB_ID_MIN_SIZE));
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
        if !is_valid_id(&self.source) {
            return Err(Error::DatabaseIdTooSmall(DB_ID_MIN_SIZE));
        }

        if !is_valid_id(&self.target) {
            return Err(Error::DatabaseIdTooSmall(DB_ID_MIN_SIZE));
        }

        //ensure that the Json field is well formed
        if let Some(v) = &self.json {
            let v: Result<serde_json::Value, serde_json::Error> = serde_json::from_str(v);
            if v.is_err() {
                // println!("Error id:{}",self.text.clone().unwrap() );
                return Err(Error::from(v.expect_err("already checked")));
            }
        }

        let pubkey = base64_encode(keypair.public.as_bytes().as_slice());
        self.pub_key = Some(pubkey);
        let hash = self.hash();
        let signature = sign(keypair, hash.as_bytes());
        self.signature = Some(signature.to_bytes().into());

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
            "INSERT OR REPLACE INTO node_sys (source, target, date, flag, json, pub_key, signature) 
                            VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
        )?;

        let mut chek_stmt =
            conn.prepare_cached("SELECT edge.rowid FROM edge WHERE source=? AND target=?")?;
        let existing_row: Option<i64> = chek_stmt
            .query_row([&self.source, &self.target], |row| row.get(0))
            .optional()?;

        if let Some(rowid) = existing_row {
            let mut update_node_stmt = conn.prepare_cached(
                "
            UPDATE edge SET 
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
        } else {
            //    println!("row does not exist");

            insert_stmt.insert((
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
            pub_key: None,
            signature: None,
        }
    }
}

#[cfg(test)]
mod tests {

    use crate::{
        cryptography::{create_random_key_pair, hash},
        database::{database_service::create_connection, datamodel::initialise_datamodel},
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
    fn edge_signature() -> Result<(), Box<dyn Error>> {
        let _keypair = create_random_key_pair();
        let _e = Edge {
            ..Default::default()
        };
        Ok(())
    }

    #[test]
    fn edge_save() -> Result<(), Box<dyn Error>> {
        let path: PathBuf = init_database_path("edge_save.db")?;
        let secret = hash(b"secret");
        let conn = create_connection(&path, &secret, 1024, false)?;
        initialise_datamodel(&conn)?;

        let _keypair = create_random_key_pair();

        Ok(())
    }

    #[test]
    fn edge_update() -> Result<(), Box<dyn Error>> {
        let path: PathBuf = init_database_path("edge_update.db")?;
        let secret = hash(b"secret");
        let conn = create_connection(&path, &secret, 1024, false)?;
        initialise_datamodel(&conn)?;

        let _keypair = create_random_key_pair();

        Ok(())
    }
}