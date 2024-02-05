use super::{
    database_service::{FromRow, Writable},
    datamodel::{is_valid_id, now, RowFlag, MAX_ROW_LENTGH},
    Error, Result,
};
use crate::cryptography::{
    base64_encode, Ed2519PublicKey, Ed2519SigningKey, PublicKey, SigningKey,
};
use rusqlite::{Connection, OptionalExtension, Row};

pub struct Edge {
    pub source: Vec<u8>,
    pub target: Vec<u8>,
    pub date: i64,
    pub flag: i8,
    pub json: Option<String>,
    pub pub_key: Vec<u8>,
    pub signature: Vec<u8>,
    pub size: i32,
}
impl Edge {
    pub fn create_table(conn: &Connection) -> Result<()> {
        conn.execute(
            " 
            CREATE TABLE edge_all (
                source BLOB NOT NULL,
                target BLOB NOT NULL,
                date INTEGER NOT NULL, 
                flag INTEGER DEFAULT 0,
                json TEXT,
                pub_key BLOB NOT NULL,
                signature BLOB NOT NULL,
                size INTEGER DEFAULT 0,
                PRIMARY KEY (source,target,date)
            ) WITHOUT ROWID, STRICT;
            ",
            [],
        )?;

        conn.execute(
            " CREATE UNIQUE INDEX edge_target_source_date_idx ON edge_all(target, source, date)",
            [],
        )?;
        Ok(())
    }

    pub fn create_temporary_view(conn: &Connection) -> Result<()> {
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

    fn len(&self) -> i32 {
        let mut len = 0;
        len += &self.source.len();
        len += &self.target.len();

        len += 8; //date
        len += 1; //flag

        if let Some(v) = &self.json {
            len += v.as_bytes().len();
        }

        len += &self.pub_key.len();

        len += &self.signature.len();
        len += 4; //size

        len.try_into().unwrap()
    }

    fn hash(&self) -> blake3::Hash {
        let mut hasher = blake3::Hasher::new();
        hasher.update(&self.source);
        hasher.update(&self.target);
        hasher.update(&self.date.to_le_bytes());
        hasher.update(&self.flag.to_le_bytes());
        if let Some(v) = &self.json {
            hasher.update(v.as_bytes());
        }

        hasher.update(&self.pub_key);
        hasher.update(&self.size.to_le_bytes());
        hasher.finalize()
    }

    // by design, only soft deletes are supported
    // edges are kept to ensure that authorisation policy can be checked, even if an authorisation as been removed
    pub fn set_deleted(&mut self) {
        self.flag |= RowFlag::DELETED;
        self.json = None;
    }

    pub fn verify(&self) -> Result<()> {
        let size = self.len();
        if size > MAX_ROW_LENTGH.try_into().unwrap() {
            return Err(Error::DatabaseRowToLong(format!(
                "Edge {}-{} is too long {} bytes instead of {}",
                base64_encode(&self.source),
                base64_encode(&self.target),
                size,
                MAX_ROW_LENTGH
            )));
        }

        if !is_valid_id(&self.source) {
            return Err(Error::InvalidId());
        }

        if !is_valid_id(&self.target) {
            return Err(Error::InvalidId());
        }

        //ensure that the Json field is well formed
        if let Some(v) = &self.json {
            let v: std::result::Result<serde_json::Value, serde_json::Error> =
                serde_json::from_str(v);
            if v.is_err() {
                return Err(Error::from(v.expect_err("this is a valid error")));
            }
        }
        let hash = self.hash();

        let pub_key = Ed2519PublicKey::import(&self.pub_key)?;
        pub_key.verify(hash.as_bytes(), &self.signature)?;

        Ok(())
    }

    pub fn sign(&mut self, keypair: &Ed2519SigningKey) -> Result<()> {
        if !is_valid_id(&self.source) {
            return Err(Error::InvalidId());
        }

        if !is_valid_id(&self.target) {
            return Err(Error::InvalidId());
        }

        //ensure that the Json field is well formed
        if let Some(v) = &self.json {
            let v: std::result::Result<serde_json::Value, serde_json::Error> =
                serde_json::from_str(v);
            if v.is_err() {
                return Err(Error::from(v.expect_err("this is a valid error")));
            }
        }

        self.pub_key = keypair.export_public();

        self.size = self.len();
        if self.size > MAX_ROW_LENTGH.try_into().unwrap() {
            return Err(Error::DatabaseRowToLong(format!(
                "Edge {}-{} is too long {} bytes instead of {}",
                base64_encode(&self.source),
                base64_encode(&self.target),
                self.size,
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
                source: row.get(0)?,
                target: row.get(1)?,
                date: row.get(2)?,
                flag: row.get(3)?,
                json: row.get(4)?,
                pub_key: row.get(5)?,
                signature: row.get(6)?,
                size: row.get(7)?,
            }))
        }
    }
}

impl Writable for Edge {
    fn write(&self, conn: &Connection) -> Result<()> {
        let mut insert_stmt = conn.prepare_cached(
            "INSERT OR REPLACE INTO edge_all (source, target, date, flag, json, pub_key, signature, size) 
                            VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
        )?;

        let mut chek_stmt =
            conn.prepare_cached("SELECT 1 FROM edge_all WHERE source=? AND target=?")?;
        let existing_row: Option<i64> = chek_stmt
            .query_row([&self.source, &self.target], |row| row.get(0))
            .optional()?;

        if existing_row.is_some() {
            if RowFlag::is(RowFlag::KEEP_HISTORY, &self.flag) {
                insert_stmt.execute((
                    &self.source,
                    &self.target,
                    &self.date,
                    &self.flag,
                    &self.json,
                    &self.pub_key,
                    &self.signature,
                    &self.size,
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
                signature = ?,
                size = ?
            WHERE 
                source=? 
                AND target=?",
                )?;

                update_node_stmt.execute((
                    &self.source,
                    &self.target,
                    &self.date,
                    &self.flag,
                    &self.json,
                    &self.pub_key,
                    &self.signature,
                    &self.size,
                    &self.source,
                    &self.target,
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
                &self.size,
            ))?;
        }
        Ok(())
    }
}

impl Default for Edge {
    fn default() -> Self {
        Self {
            source: vec![],
            target: vec![],
            date: now(),
            flag: 0,
            json: None,
            pub_key: vec![],
            signature: vec![],
            size: 0,
        }
    }
}

#[cfg(test)]
mod tests {

    use crate::{
        cryptography::{Ed2519SigningKey, SigningKey},
        database::{
            datamodel::{new_id, prepare_connection, DB_ID_MAX_SIZE},
            node_table::Node,
            security_policy::{PolicyNode, PolicyRight, PEER_SCHEMA, POLICY_GROUP_SCHEMA},
        },
    };

    use super::*;

    #[test]
    fn edge_signature() {
        let keypair = Ed2519SigningKey::new();
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

        let badk = Ed2519SigningKey::new();
        e.pub_key = badk.export_public();
        e.verify().expect_err("msg");
        e.sign(&keypair).unwrap();

        e.signature = signature;
        e.verify().expect_err("msg");
    }

    #[test]
    fn edge_limit_test() {
        let keypair = Ed2519SigningKey::new();
        let source = new_id(10);

        let mut e = Edge {
            source: source.clone(),
            target: source.clone(),
            ..Default::default()
        };
        e.sign(&keypair).unwrap();
        e.verify().unwrap();

        e.source = vec![];
        e.verify().expect_err("msg");
        e.sign(&keypair).expect_err("msg");

        e.source = source.clone();
        e.target = vec![];
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

        let arr = [0 as u8; DB_ID_MAX_SIZE + 1];

        e.target = arr.to_vec();
        e.verify().expect_err("msg");
        e.sign(&keypair).expect_err("msg");

        let arr = [0 as u8; MAX_ROW_LENTGH];

        e.json = Some(format!("[\"{}\" ]", base64_encode(&arr)));
        e.verify().expect_err("msg");
        e.sign(&keypair).expect_err("msg");
    }

    #[test]
    fn edge_save() {
        let conn = Connection::open_in_memory().unwrap();
        prepare_connection(&conn).unwrap();

        let keypair = Ed2519SigningKey::new();

        let mut policy_group = Node {
            schema: POLICY_GROUP_SCHEMA.to_string(),
            flag: RowFlag::KEEP_HISTORY,
            text: Some("Some Policy Group".to_string()),
            ..Default::default()
        };
        policy_group.sign(&keypair).unwrap();
        policy_group.write(&conn).unwrap();

        let mut peer = Node {
            id: keypair.export_public(),
            schema: PEER_SCHEMA.to_string(),
            cdate: policy_group.mdate,
            mdate: policy_group.mdate,
            ..Default::default()
        };
        peer.sign(&keypair).unwrap();
        peer.write(&conn).unwrap();

        let mut policy_group_peer = Edge {
            source: policy_group.id.clone(),
            target: peer.id.clone(),
            date: policy_group.mdate,
            flag: RowFlag::KEEP_HISTORY,
            ..Default::default()
        };
        policy_group_peer.sign(&keypair).unwrap();
        policy_group_peer.write(&conn).unwrap();

        let mut policy = PolicyNode {
            ..Default::default()
        };
        policy.node.mdate = policy_group.mdate;
        policy.node.cdate = policy_group.mdate;
        let chat_schema = "chat";
        let message_schema = "msg";
        policy
            .policy
            .set_right(chat_schema, PolicyRight::READ | PolicyRight::CREATE);
        policy
            .policy
            .set_right(message_schema, PolicyRight::READ | PolicyRight::CREATE);

        policy.policy.add_edge_policy(message_schema, chat_schema);
        policy.sign(&keypair).unwrap();
        policy.node.write(&conn).unwrap();

        let mut policy_policygr_edge = Edge {
            source: policy_group.id.clone(),
            target: policy.node.id.clone(),
            date: policy_group.mdate,
            flag: RowFlag::KEEP_HISTORY,
            ..Default::default()
        };
        policy_policygr_edge.sign(&keypair).unwrap();
        policy_policygr_edge.write(&conn).unwrap();

        let mut policy_peer = Edge {
            source: policy.node.id.clone(),
            target: peer.id.clone(),
            date: policy_group.mdate,
            flag: RowFlag::KEEP_HISTORY,
            ..Default::default()
        };
        policy_peer.sign(&keypair).unwrap();
        policy_peer.write(&conn).unwrap();

        let mut chat_group = Node {
            schema: chat_schema.to_string(),
            cdate: policy_group.mdate,
            mdate: policy_group.mdate,
            ..Default::default()
        };
        chat_group.sign(&keypair).unwrap();
        chat_group.write(&conn).unwrap();

        let mut message = Node {
            schema: message_schema.to_string(),
            cdate: policy_group.mdate,
            mdate: policy_group.mdate,
            text: Some("Hello world".to_string()),
            ..Default::default()
        };
        message.sign(&keypair).unwrap();
        message.write(&conn).unwrap();

        let mut e = Edge {
            source: message.id.clone(),
            target: policy_group.id.clone(),
            ..Default::default()
        };
        e.sign(&keypair).unwrap();
        e.write(&conn).unwrap();

        let mut e = Edge {
            source: chat_group.id.clone(),
            target: policy_group.id.clone(),
            ..Default::default()
        };
        e.sign(&keypair).unwrap();
        e.write(&conn).unwrap();

        let mut e = Edge {
            source: message.id.clone(),
            target: chat_group.id.clone(),
            ..Default::default()
        };
        e.sign(&keypair).unwrap();
        e.write(&conn).unwrap();

        let mut stmt = conn
            .prepare("SELECT edge.* FROM edge WHERE edge.source=? AND edge.target=?")
            .unwrap();
        let results = stmt
            .query_map(
                [message.id.clone(), chat_group.id.clone()],
                Edge::from_row(),
            )
            .unwrap();
        let mut res = vec![];
        for ed in results {
            let edge = ed.unwrap();
            edge.verify().unwrap();
            res.push(edge);
        }
        assert_eq!(1, res.len());

        e.sign(&keypair).unwrap();
        e.write(&conn).unwrap();
        let results = stmt
            .query_map(
                [message.id.clone(), chat_group.id.clone()],
                Edge::from_row(),
            )
            .unwrap();
        assert_eq!(1, results.count());
        e.set_deleted();
        e.sign(&keypair).unwrap();
        e.write(&conn).unwrap();

        let results = stmt
            .query_map(
                [message.id.clone(), chat_group.id.clone()],
                Edge::from_row(),
            )
            .unwrap();
        assert_eq!(0, results.count());

        e.flag = e.flag & !RowFlag::DELETED;
        e.sign(&keypair).unwrap();
        e.write(&conn).unwrap();

        let results = stmt
            .query_map(
                [message.id.clone(), chat_group.id.clone()],
                Edge::from_row(),
            )
            .unwrap();
        assert_eq!(1, results.count());

        e.flag = RowFlag::KEEP_HISTORY;
        e.sign(&keypair).unwrap();
        e.write(&conn).unwrap();
        let results = stmt
            .query_map(
                [message.id.clone(), chat_group.id.clone()],
                Edge::from_row(),
            )
            .unwrap();
        assert_eq!(1, results.count());

        e.date = e.date + 1;
        e.sign(&keypair).unwrap();
        e.write(&conn).unwrap();
        let results = stmt
            .query_map(
                [message.id.clone(), chat_group.id.clone()],
                Edge::from_row(),
            )
            .unwrap();
        assert_eq!(2, results.count());
    }
}
