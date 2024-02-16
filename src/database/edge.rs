use super::{
    graph_database::{now, valid_id_len, FromRow, Statement, MAX_ROW_LENTGH},
    Error, Result,
};
use crate::cryptography::{
    base64_encode, Ed2519PublicKey, Ed2519SigningKey, PublicKey, SigningKey,
};
use rusqlite::{Connection, Row};

pub struct Edge {
    pub from: Vec<u8>,
    pub label: String,
    pub to: Vec<u8>,
    pub cdate: i64,
    pub pub_key: Vec<u8>,
    pub signature: Vec<u8>,
}
impl Edge {
    pub fn create_table(conn: &Connection) -> Result<()> {
        conn.execute(
            " 
            CREATE TABLE _edge (
                from BLOB NOT NULL,
                label TEXT NOT NULL,
                to BLOB NOT NULL,
                cdate INTEGER NOT NULL,
                pub_key BLOB NOT NULL,
                signature BLOB NOT NULL,
                PRIMARY KEY (from, label, to)
            ) WITHOUT ROWID, STRICT;
            ",
            [],
        )?;

        conn.execute(
            " CREATE UNIQUE INDEX _edge_to_label_from_idx ON _edge(to, label, from)",
            [],
        )?;
        Ok(())
    }

    fn len(&self) -> usize {
        let mut len = 0;
        len += &self.from.len();
        len += &self.label.as_bytes().len();
        len += &self.to.len();
        len += 8; //cdate
        len += &self.pub_key.len();
        len += &self.signature.len();
        len
    }

    fn hash(&self) -> blake3::Hash {
        let mut hasher = blake3::Hasher::new();
        hasher.update(&self.from);
        hasher.update(&self.label.as_bytes());
        hasher.update(&self.to);
        hasher.update(&self.cdate.to_le_bytes());
        hasher.update(&self.pub_key);
        hasher.finalize()
    }

    pub fn verify(&self) -> Result<()> {
        let size = self.len();
        if size > MAX_ROW_LENTGH.try_into().unwrap() {
            return Err(Error::DatabaseRowToLong(format!(
                "Edge {}-{}-{} is too long {} bytes instead of {}",
                base64_encode(&self.from),
                &self.label,
                base64_encode(&self.to),
                size,
                MAX_ROW_LENTGH
            )));
        }

        if !valid_id_len(&self.from) {
            return Err(Error::InvalidId());
        }

        if !valid_id_len(&self.to) {
            return Err(Error::InvalidId());
        }
        let hash = self.hash();

        let pub_key = Ed2519PublicKey::import(&self.pub_key)?;
        pub_key.verify(hash.as_bytes(), &self.signature)?;
        Ok(())
    }

    pub fn sign(&mut self, keypair: &Ed2519SigningKey) -> Result<()> {
        if !valid_id_len(&self.from) {
            return Err(Error::InvalidId());
        }

        if !valid_id_len(&self.to) {
            return Err(Error::InvalidId());
        }

        self.pub_key = keypair.export_public();

        let size = self.len();
        if size > MAX_ROW_LENTGH.try_into().unwrap() {
            return Err(Error::DatabaseRowToLong(format!(
                "Edge {}-{}-{} is too long {} bytes instead of {}",
                base64_encode(&self.from),
                &self.label,
                base64_encode(&self.to),
                size,
                MAX_ROW_LENTGH
            )));
        }
        let hash = self.hash();

        let signature = keypair.sign(hash.as_bytes());
        self.signature = signature;

        Ok(())
    }
}

impl FromRow for Edge {
    fn from_row() -> fn(&Row) -> std::result::Result<Box<Self>, rusqlite::Error> {
        |row| {
            Ok(Box::new(Edge {
                from: row.get(0)?,
                label: row.get(1)?,
                to: row.get(2)?,
                cdate: row.get(3)?,
                pub_key: row.get(4)?,
                signature: row.get(5)?,
            }))
        }
    }
}

impl Statement for Edge {
    fn execute(&self, conn: &Connection) -> Result<Vec<String>> {
        let mut insert_stmt = conn.prepare_cached(
            "INSERT OR REPLACE INTO edge_all (from, label, to, cdate, pub_key, signature) 
                            VALUES (?, ?, ?, ?, ?, ?)",
        )?;
        insert_stmt.execute((
            &self.from,
            &self.label,
            &self.to,
            &self.cdate,
            &self.pub_key,
            &self.signature,
        ))?;

        Ok(Vec::new())
    }
}

impl Default for Edge {
    fn default() -> Self {
        Self {
            from: vec![],
            label: String::from(""),
            to: vec![],
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
            from: from.clone(),
            label: String::from("Test"),
            to: to.clone(),
            ..Default::default()
        };

        e.sign(&keypair).unwrap();
        e.verify().unwrap();

        let bad_id = new_id(10);
        e.from = bad_id.clone();
        e.verify()
            .expect_err("'from' has changed, verification must fail");
        e.from = from.clone();
        e.verify().unwrap();

        e.to = bad_id.clone();
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
            from: source.clone(),
            to: source.clone(),
            ..Default::default()
        };
        e.sign(&keypair).unwrap();
        e.verify().unwrap();

        e.from = vec![];
        e.verify().expect_err("'from' is too short");
        e.sign(&keypair).expect_err("'from' is too short");

        e.from = source.clone();
        e.to = vec![];
        e.verify().expect_err("'to' is too short");
        e.sign(&keypair).expect_err("'to' is too short");

        e.to = source.clone();
        e.sign(&keypair).unwrap();
        e.verify().unwrap();

        let arr = [0 as u8; DB_ID_MAX_SIZE + 1];

        e.from = arr.to_vec();
        e.verify().expect_err("'from' is too long");
        e.sign(&keypair).expect_err("'from' is too long");

        e.to = arr.to_vec();
        e.verify().expect_err("'to' is too long");
        e.sign(&keypair).expect_err("'to' is too long");
    }
}
