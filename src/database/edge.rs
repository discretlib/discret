use super::{
    sqlite_database::{is_valid_id_len, RowMappingFn, MAX_ROW_LENTGH},
    Error, Result,
};
use crate::cryptography::{base64_encode, import_verifying_key, now, SigningKey};
use rusqlite::{Connection, OptionalExtension};
use serde::{Deserialize, Serialize};

///
/// Edge object stores relations between Nodes
///
/// One of the two tables that defines the graph database
///
#[derive(Serialize, Deserialize, Debug)]
pub struct Edge {
    pub src: Vec<u8>,
    pub label: String,
    pub dest: Vec<u8>,
    pub cdate: i64,
    pub verifying_key: Vec<u8>,
    pub signature: Vec<u8>,
}
impl Edge {
    ///
    /// Creates the required tables and indexes
    /// Edge can be efficiently queried in the two directions: src->dest and dest->src
    /// rowid is is useless for this table
    ///
    pub fn create_table(conn: &Connection) -> Result<()> {
        conn.execute(
            " 
            CREATE TABLE _edge (
                src BLOB NOT NULL,
                label TEXT NOT NULL,
                dest BLOB NOT NULL,
                cdate INTEGER NOT NULL,
                verifying_key BLOB NOT NULL,
                signature BLOB NOT NULL,
                PRIMARY KEY (src, label, dest)
            ) WITHOUT ROWID, STRICT;
            ",
            [],
        )?;

        conn.execute(
            " CREATE UNIQUE INDEX _edge_dest_label_src_idx ON _edge(dest, label, src )",
            [],
        )?;
        Ok(())
    }

    pub const EDGE_QUERY: &'static str = "
    SELECT  src, label, dest, cdate, verifying_key, signature 
        FROM _edge
    WHERE 
        src = ? AND
        label = ? AND
        dest = ?";

    pub const EDGE_MAPPING: RowMappingFn<Self> = |row| {
        Ok(Box::new(Edge {
            src: row.get(0)?,
            label: row.get(1)?,
            dest: row.get(2)?,
            cdate: row.get(3)?,
            verifying_key: row.get(4)?,
            signature: row.get(5)?,
        }))
    };

    fn len(&self) -> usize {
        let mut len = 0;
        len += &self.src.len();
        len += &self.label.as_bytes().len();
        len += &self.dest.len();
        len += 8; //cdate
        len += &self.verifying_key.len();
        len += &self.signature.len();
        len
    }

    fn hash(&self) -> blake3::Hash {
        let mut hasher = blake3::Hasher::new();
        hasher.update(&self.src);
        hasher.update(&self.label.as_bytes());
        hasher.update(&self.dest);
        hasher.update(&self.cdate.to_le_bytes());
        hasher.update(&self.verifying_key);
        hasher.finalize()
    }

    ///
    /// verify the edge after performing some checks
    ///
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

        if !is_valid_id_len(&self.src) {
            return Err(Error::InvalidId());
        }

        if !is_valid_id_len(&self.dest) {
            return Err(Error::InvalidId());
        }
        let hash = self.hash();

        let verifying_key = import_verifying_key(&self.verifying_key)?;
        verifying_key.verify(hash.as_bytes(), &self.signature)?;
        Ok(())
    }

    ///
    /// sign the edge after performing some checks
    ///
    pub fn sign(&mut self, signing_key: &impl SigningKey) -> Result<()> {
        if !is_valid_id_len(&self.src) {
            return Err(Error::InvalidId());
        }

        if !is_valid_id_len(&self.dest) {
            return Err(Error::InvalidId());
        }

        self.verifying_key = signing_key.export_verifying_key();

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

        let signature = signing_key.sign(hash.as_bytes());
        self.signature = signature;

        Ok(())
    }

    ///
    /// write the edge
    ///
    pub fn write(&self, conn: &Connection) -> std::result::Result<(), rusqlite::Error> {
        let mut insert_stmt = conn.prepare_cached(
            "INSERT OR REPLACE INTO _edge (src, label, dest, cdate, verifying_key, signature) 
                            VALUES (?, ?, ?, ?, ?, ?)",
        )?;
        insert_stmt.execute((
            &self.src,
            &self.label,
            &self.dest,
            &self.cdate,
            &self.verifying_key,
            &self.signature,
        ))?;

        Ok(())
    }

    ///
    /// Low level method to hard delete an edge.
    ///
    /// This method is intended to be used in the write thread wich perform operations in larges batches.
    /// This method does not check for data integrity to avoid any errors that would cause the rollback of a potentially large number of write queries
    ///
    pub fn delete(&self, conn: &Connection) -> std::result::Result<(), rusqlite::Error> {
        let mut delete_stmt = conn.prepare_cached(
            "DELETE FROM _edge
            WHERE 
                src = ? AND
                label = ? AND
                dest = ?
            ",
        )?;
        delete_stmt.execute((&self.src, &self.label, &self.dest))?;
        Ok(())
    }

    pub fn delete_edge(
        src: &Vec<u8>,
        label: &str,
        dest: &Vec<u8>,
        conn: &Connection,
    ) -> std::result::Result<(), rusqlite::Error> {
        let mut delete_stmt = conn.prepare_cached(
            "DELETE FROM _edge
            WHERE 
                src = ? AND
                label = ? AND
                dest = ?
            ",
        )?;
        delete_stmt.execute((&src, &label, &dest))?;
        Ok(())
    }

    ///
    /// retrieve an edge
    ///
    pub fn get(
        src: &Vec<u8>,
        label: &str,
        dest: &Vec<u8>,
        conn: &Connection,
    ) -> Result<Option<Box<Edge>>> {
        let mut get_stmt = conn.prepare_cached(Self::EDGE_QUERY)?;

        let edge = get_stmt.query_row((src, label, dest), Self::EDGE_MAPPING)?;
        Ok(Some(edge))
    }

    ///
    /// verify the existence of an edge
    ///
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

    ///
    /// retrieve all edges from a specific source and label
    ///
    pub fn get_edges(src: &Vec<u8>, label: &str, conn: &Connection) -> Result<Vec<Box<Edge>>> {
        let mut edges_stmt = conn.prepare_cached(
            "SELECT  src, label, dest, cdate, verifying_key, signature 
            FROM _edge
            WHERE 
                src = ? AND
                label = ? ",
        )?;
        let edges = edges_stmt.query_map((src, label), Self::EDGE_MAPPING)?;
        let mut rows = vec![];
        for edge in edges {
            rows.push(edge?);
        }

        Ok(rows)
    }
}

/// Query used in conjunction with the from_row() method to easily retrieve an edge

impl Default for Edge {
    fn default() -> Self {
        Self {
            src: vec![],
            label: String::from(""),
            dest: vec![],
            cdate: now(),
            verifying_key: vec![],
            signature: vec![],
        }
    }
}

#[cfg(test)]
mod tests {

    use crate::{
        cryptography::{new_id, Ed25519SigningKey, SigningKey},
        database::sqlite_database::{prepare_connection, DB_ID_MAX_SIZE},
    };

    use super::*;

    #[test]
    fn edge_signature() {
        let keypair = Ed25519SigningKey::new();
        let from = new_id();
        let to = new_id();
        let mut e = Edge {
            src: from.clone(),
            label: String::from("Test"),
            dest: to.clone(),
            ..Default::default()
        };

        e.sign(&keypair).unwrap();
        e.verify().unwrap();

        let bad_id = new_id();
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

        let badk = Ed25519SigningKey::new();
        e.verifying_key = badk.export_verifying_key();
        e.verify()
            .expect_err("'public key' has changed, verification must fail");
        e.sign(&keypair).unwrap();

        e.signature = bad_id;
        e.verify()
            .expect_err("wrong signature, verification must fail");
    }

    #[test]
    fn edge_limit() {
        let keypair = Ed25519SigningKey::new();
        let source = new_id();

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

    #[test]
    fn edge_database() {
        let signing_key = Ed25519SigningKey::new();
        let conn = Connection::open_in_memory().unwrap();
        prepare_connection(&conn).unwrap();
        let label = "pet";
        let from = new_id();
        let to = new_id();
        let mut e = Edge {
            src: from.clone(),
            label: String::from(label),
            dest: to.clone(),
            ..Default::default()
        };

        e.sign(&signing_key).unwrap();
        e.write(&conn).unwrap();

        let mut new_edge = Edge::get(&from, label, &to, &conn).unwrap().unwrap();
        new_edge.sign(&signing_key).unwrap();
        new_edge.write(&conn).unwrap();

        let edges = Edge::get_edges(&from, label, &conn).unwrap();
        assert_eq!(1, edges.len());

        new_edge.dest = new_id();
        new_edge.sign(&signing_key).unwrap();
        new_edge.write(&conn).unwrap();

        let edges = Edge::get_edges(&from, label, &conn).unwrap();
        assert_eq!(2, edges.len());

        new_edge.delete(&conn).unwrap();
        let edges = Edge::get_edges(&from, label, &conn).unwrap();
        assert_eq!(1, edges.len());
    }
}
