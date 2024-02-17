use super::{
    graph_database::{now, valid_id_len, FromRow, StatementResult, Writeable, MAX_ROW_LENTGH},
    Error, Result,
};
use crate::cryptography::{
    base64_encode, Ed2519PublicKey, Ed2519SigningKey, PublicKey, SigningKey,
};
use rusqlite::{Connection, OptionalExtension, Row};
use serde::{Deserialize, Serialize};

#[derive(Serialize, Deserialize, Debug)]
pub struct Edge {
    pub src: Vec<u8>,
    pub label: String,
    pub dest: Vec<u8>,
    pub cdate: i64,
    pub pub_key: Vec<u8>,
    pub signature: Vec<u8>,
}
impl Edge {
    pub fn create_table(conn: &Connection) -> Result<()> {
        conn.execute(
            " 
            CREATE TABLE _edge (
                src BLOB NOT NULL,
                label TEXT NOT NULL,
                dest BLOB NOT NULL,
                cdate INTEGER NOT NULL,
                pub_key BLOB NOT NULL,
                signature BLOB NOT NULL,
                PRIMARY KEY (src, label, dest)
            ) WITHOUT ROWID, STRICT;
            ",
            [],
        )?;

        conn.execute(
            " CREATE UNIQUE INDEX _edge_dest_label_src_idx ON _edge(src, label, dest)",
            [],
        )?;
        Ok(())
    }

    fn len(&self) -> usize {
        let mut len = 0;
        len += &self.src.len();
        len += &self.label.as_bytes().len();
        len += &self.dest.len();
        len += 8; //cdate
        len += &self.pub_key.len();
        len += &self.signature.len();
        len
    }

    fn hash(&self) -> blake3::Hash {
        let mut hasher = blake3::Hasher::new();
        hasher.update(&self.src);
        hasher.update(&self.label.as_bytes());
        hasher.update(&self.dest);
        hasher.update(&self.cdate.to_le_bytes());
        hasher.update(&self.pub_key);
        hasher.finalize()
    }

    pub fn verify(&self) -> Result<()> {
        let size = self.len();
        if size > MAX_ROW_LENTGH.try_into().unwrap() {
            return Err(Error::DatabaseRowToLong(format!(
                "Edge {}-{}-{} is too long {} bytes instead of {}",
                base64_encode(&self.src),
                &self.label,
                base64_encode(&self.dest),
                size,
                MAX_ROW_LENTGH
            )));
        }

        if !valid_id_len(&self.src) {
            return Err(Error::InvalidId());
        }

        if !valid_id_len(&self.dest) {
            return Err(Error::InvalidId());
        }
        let hash = self.hash();

        let pub_key = Ed2519PublicKey::import(&self.pub_key)?;
        pub_key.verify(hash.as_bytes(), &self.signature)?;
        Ok(())
    }

    pub fn sign(&mut self, keypair: &Ed2519SigningKey) -> Result<()> {
        if !valid_id_len(&self.src) {
            return Err(Error::InvalidId());
        }

        if !valid_id_len(&self.dest) {
            return Err(Error::InvalidId());
        }

        self.pub_key = keypair.export_public();

        let size = self.len();
        if size > MAX_ROW_LENTGH.try_into().unwrap() {
            return Err(Error::DatabaseRowToLong(format!(
                "Edge {}-{}-{} is too long {} bytes instead of {}",
                base64_encode(&self.src),
                &self.label,
                base64_encode(&self.dest),
                size,
                MAX_ROW_LENTGH
            )));
        }
        let hash = self.hash();

        let signature = keypair.sign(hash.as_bytes());
        self.signature = signature;

        Ok(())
    }

    fn write(&self, conn: &Connection) -> std::result::Result<StatementResult, rusqlite::Error> {
        let mut insert_stmt = conn.prepare_cached(
            "INSERT OR REPLACE INTO _edge (src, label, dest, cdate, pub_key, signature) 
                            VALUES (?, ?, ?, ?, ?, ?)",
        )?;
        insert_stmt.execute((
            &self.src,
            &self.label,
            &self.dest,
            &self.cdate,
            &self.pub_key,
            &self.signature,
        ))?;

        Ok(StatementResult::String(String::from("ok")))
    }

    pub fn get(
        src: Vec<u8>,
        label: String,
        dest: Vec<u8>,
        conn: &Connection,
    ) -> Result<Option<Box<Edge>>> {
        let mut get_stmt = conn.prepare_cached(
            "SELECT  src, label, dest, cdate, pub_key, signature 
            FROM _edge
            WHERE 
                src = ? AND
                label = ? AND
                dest = ?",
        )?;

        let edge = get_stmt.query_row((src, label, dest), Edge::from_row())?;
        Ok(Some(edge))
    }

    pub fn exists(src: Vec<u8>, label: String, dest: Vec<u8>, conn: &Connection) -> Result<bool> {
        let mut exists_stmt = conn.prepare_cached(
            "SELECT  1
            FROM _edge
            WHERE 
                src = ? AND
                label = ? AND
                dest = ?",
        )?;
        let node: Option<i64> = exists_stmt
            .query_row((src, label, dest), |row| Ok(row.get(0)?))
            .optional()?;

        Ok(node.is_some())
    }

    pub fn has_edge(src: Vec<u8>, label: String, conn: &Connection) -> Result<bool> {
        let mut exists_stmt = conn.prepare_cached(
            "SELECT  1
            FROM _edge
            WHERE 
                src = ? AND
                label = ? ",
        )?;
        let node: Option<i64> = exists_stmt
            .query_row((src, label), |row| Ok(row.get(0)?))
            .optional()?;

        Ok(node.is_some())
    }

    pub fn get_edges(src: Vec<u8>, label: String, conn: &Connection) -> Result<Vec<Box<Edge>>> {
        let mut edges_stmt = conn.prepare_cached(
            "SELECT  src, label, dest, cdate, pub_key, signature 
            FROM _edge
            WHERE 
                src = ? AND
                label = ? ",
        )?;
        let edges = edges_stmt.query_map((src, label), Edge::from_row())?;
        let mut rows = vec![];
        for edge in edges {
            rows.push(edge?);
        }

        Ok(rows)
    }
}

impl FromRow for Edge {
    fn from_row() -> fn(&Row) -> std::result::Result<Box<Self>, rusqlite::Error> {
        |row| {
            Ok(Box::new(Edge {
                src: row.get(0)?,
                label: row.get(1)?,
                dest: row.get(2)?,
                cdate: row.get(3)?,
                pub_key: row.get(4)?,
                signature: row.get(5)?,
            }))
        }
    }
}

impl Default for Edge {
    fn default() -> Self {
        Self {
            src: vec![],
            label: String::from(""),
            dest: vec![],
            cdate: now(),
            pub_key: vec![],
            signature: vec![],
        }
    }
}

#[cfg(test)]
mod tests {

    use crate::{
        cryptography::{Ed2519SigningKey, SigningKey},
        database::graph_database::{new_id, DB_ID_MAX_SIZE},
    };

    use super::*;

    #[test]
    fn edge_signature() {
        let keypair = Ed2519SigningKey::new();
        let from = new_id(10);
        let to = new_id(10);
        let mut e = Edge {
            src: from.clone(),
            label: String::from("Test"),
            dest: to.clone(),
            ..Default::default()
        };

        e.sign(&keypair).unwrap();
        e.verify().unwrap();

        let bad_id = new_id(10);
        e.src = bad_id.clone();
        e.verify()
            .expect_err("'from' has changed, verification must fail");
        e.src = from.clone();
        e.verify().unwrap();

        e.dest = bad_id.clone();
        e.verify()
            .expect_err("'to' has changed, verification must fail");
        e.sign(&keypair).unwrap();
        e.verify().unwrap();

        e.cdate = e.cdate + 1;
        e.verify()
            .expect_err("'cdate' has changed, verification must fail");
        e.sign(&keypair).unwrap();
        e.verify().unwrap();

        let badk = Ed2519SigningKey::new();
        e.pub_key = badk.export_public();
        e.verify()
            .expect_err("'public key' has changed, verification must fail");
        e.sign(&keypair).unwrap();

        e.signature = bad_id;
        e.verify()
            .expect_err("wrong signature, verification must fail");
    }

    #[test]
    fn edge_limit_test() {
        let keypair = Ed2519SigningKey::new();
        let source = new_id(10);

        let mut e = Edge {
            src: source.clone(),
            dest: source.clone(),
            ..Default::default()
        };
        e.sign(&keypair).unwrap();
        e.verify().unwrap();

        e.src = vec![];
        e.verify().expect_err("'from' is too short");
        e.sign(&keypair).expect_err("'from' is too short");

        e.src = source.clone();
        e.dest = vec![];
        e.verify().expect_err("'to' is too short");
        e.sign(&keypair).expect_err("'to' is too short");

        e.dest = source.clone();
        e.sign(&keypair).unwrap();
        e.verify().unwrap();

        let arr = [0 as u8; DB_ID_MAX_SIZE + 1];

        e.src = arr.to_vec();
        e.verify().expect_err("'from' is too long");
        e.sign(&keypair).expect_err("'from' is too long");

        e.dest = arr.to_vec();
        e.verify().expect_err("'to' is too long");
        e.sign(&keypair).expect_err("'to' is too long");
    }
}
