use super::{
    daily_log::DailyMutations,
    sqlite_database::{RowMappingFn, Writeable},
    Error, Result, VEC_OVERHEAD,
};
use crate::{
    date_utils::{date, date_next_day},
    security::{import_verifying_key, SigningKey, Uid},
};

use rusqlite::{Connection, OptionalExtension};
use serde::{Deserialize, Serialize};
use tokio::sync::mpsc;
///
/// Maximum allowed size for a row
/// set to a relatively low value to avoid large rows that would eats lots of ram and bandwith during synchronisation
///
pub const MAX_EDGE_LENTGH: usize = 1024; //1kb

///
/// Edge object stores relations between Nodes
///
/// One of the two tables that defines the graph database
///
#[derive(Serialize, Deserialize, Debug, Clone, Default)]
pub struct Edge {
    pub src: Uid,
    pub src_entity: String,
    pub label: String,
    pub dest: Uid,
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
    pub fn create_tables(conn: &Connection) -> Result<()> {
        conn.execute(
            " 
            CREATE TABLE _edge (
                src BLOB NOT NULL,
                src_entity TEXT NOT NULL,
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
        //reverse search
        conn.execute(
            " CREATE UNIQUE INDEX _edge_dest_label_src_idx ON _edge(dest, label, src )",
            [],
        )?;

        //usefull for daily log creation
        conn.execute(
            " CREATE INDEX _edge_src_cdate_idx ON _edge(src, cdate )",
            [],
        )?;

        conn.execute(
            "CREATE TABLE _edge_deletion_log (
            room_id BLOB NOT NULL,
            src BLOB NOT NULL,
            src_entity TEXT NOT NULL, 
            dest BLOB NOT NULL,
            label TEXT NOT NULL,
            cdate INTEGER NOT NULL,
            deletion_date INTEGER NOT NULL,
            verifying_key BLOB NOT NULL,
            signature BLOB NOT NULL,
            PRIMARY KEY(room_id, deletion_date, src, label, dest )
        ) WITHOUT ROWID, STRICT",
            [],
        )?;

        Ok(())
    }

    pub const EDGE_QUERY: &'static str = "
    SELECT src, src_entity, label, dest, cdate, verifying_key, signature 
        FROM _edge
    WHERE 
        src = ? AND
        label = ? AND
        dest = ?";

    pub const EDGE_MAPPING: RowMappingFn<Self> = |row| {
        Ok(Box::new(Edge {
            src: row.get(0)?,
            src_entity: row.get(1)?,
            label: row.get(2)?,
            dest: row.get(3)?,
            cdate: row.get(4)?,
            verifying_key: row.get(5)?,
            signature: row.get(6)?,
        }))
    };

    fn len(&self) -> usize {
        let mut len = 0;
        len += &self.src.len();
        len += &self.src_entity.len();
        len += &self.label.as_bytes().len();
        len += &self.dest.len();
        len += 8; //cdate
        len += &self.verifying_key.len();
        len += &self.signature.len();
        len
    }

    pub fn eq(&self, edg: &Edge) -> bool {
        self.src.eq(&edg.src)
            && self.src_entity.eq(&edg.src_entity)
            && self.label.eq(&edg.label)
            && self.dest.eq(&edg.dest)
            && self.cdate.eq(&edg.cdate)
            && self.verifying_key.eq(&edg.verifying_key)
    }

    fn hash(&self) -> blake3::Hash {
        let mut hasher = blake3::Hasher::new();
        hasher.update(&self.src);
        hasher.update(self.src_entity.as_bytes());
        hasher.update(self.label.as_bytes());
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
        if size > MAX_EDGE_LENTGH {
            return Err(Error::EdgeTooBig(size, MAX_EDGE_LENTGH));
        }
        if self.src_entity.is_empty() {
            return Err(Error::EmptyNodeEntity());
        }

        if self.label.is_empty() {
            return Err(Error::EmptyEdgeLabel());
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
        if self.src_entity.is_empty() {
            return Err(Error::EmptyNodeEntity());
        }

        if self.label.is_empty() {
            return Err(Error::EmptyEdgeLabel());
        }

        self.verifying_key = signing_key.export_verifying_key();

        let size = self.len();
        if size > MAX_EDGE_LENTGH {
            return Err(Error::EdgeTooBig(size, MAX_EDGE_LENTGH));
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
            "INSERT OR REPLACE INTO _edge (src, src_entity, label, dest, cdate, verifying_key, signature) 
                            VALUES (?, ?, ?, ?, ?, ?, ?)",
        )?;

        insert_stmt.execute((
            &self.src,
            &self.src_entity,
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

    ///
    /// Delete all edges the same source
    ///
    ///
    pub fn delete_src(src: &Uid, conn: &Connection) -> std::result::Result<(), rusqlite::Error> {
        let mut delete_stmt = conn.prepare_cached(
            "DELETE FROM _edge
            WHERE 
                src = ? 
            ",
        )?;
        delete_stmt.execute([src])?;
        Ok(())
    }

    ///
    /// Delete all edges the same source
    ///
    ///
    pub fn delete_dest(dest: &Uid, conn: &Connection) -> std::result::Result<(), rusqlite::Error> {
        let mut delete_stmt = conn.prepare_cached(
            "DELETE FROM _edge
            WHERE 
                dest = ? 
            ",
        )?;
        delete_stmt.execute([dest])?;
        Ok(())
    }

    ///
    /// retrieve an edge
    ///
    pub fn get(src: &Uid, label: &str, dest: &Uid, conn: &Connection) -> Result<Option<Box<Edge>>> {
        let mut get_stmt = conn.prepare_cached(Self::EDGE_QUERY)?;

        let edge = get_stmt
            .query_row((src, label, dest), Self::EDGE_MAPPING)
            .optional()?;
        Ok(edge)
    }

    ///
    /// verify the existence of an edge
    ///
    pub fn exists(src: Uid, label: String, dest: Uid, conn: &Connection) -> Result<bool> {
        let mut exists_stmt = conn.prepare_cached(
            "SELECT  1
            FROM _edge
            WHERE 
                src = ? AND
                label = ? AND
                dest = ?",
        )?;
        let node: Option<i64> = exists_stmt
            .query_row((src, label, dest), |row| row.get(0))
            .optional()?;

        Ok(node.is_some())
    }

    ///
    /// retrieve all edges from a specific source and label
    ///
    pub fn get_edges(
        src: &Uid,
        label: &str,
        conn: &Connection,
    ) -> std::result::Result<Vec<Edge>, rusqlite::Error> {
        let mut edges_stmt = conn.prepare_cached(
            "SELECT  src, src_entity, label, dest, cdate, verifying_key, signature 
            FROM _edge
            WHERE 
                src = ? AND
                label = ? ",
        )?;
        let edges = edges_stmt.query_map((src, label), Self::EDGE_MAPPING)?;
        let mut rows = vec![];
        for edge in edges {
            rows.push(*edge?);
        }

        Ok(rows)
    }

    pub fn filtered_by_room(
        room_id: &Uid,
        node_ids: Vec<(Uid, i64)>,
        batch_size: usize,
        sender: &mpsc::Sender<Result<Vec<Edge>>>,
        conn: &Connection,
    ) -> Result<()> {
        let mut query = conn.prepare_cached(
            "SELECT _edge.src, _edge.src_entity, _edge.label, _edge.dest, _edge.cdate, _edge.verifying_key, _edge.signature 
            FROM _edge JOIN _node ON  _edge.src = _node.id
            WHERE 
                _edge.src = ? AND
                _edge.cdate >= ? AND
                _node.room_id = ?",
        )?;

        let mut len = 0;
        let mut res = Vec::new();
        for (src, cdate) in &node_ids {
            let edges = query.query_map((src, cdate, room_id), Self::EDGE_MAPPING)?;

            for edge in edges {
                let edge = *edge?;
                let size = bincode::serialized_size(&edge)?;
                let insert_len = len + size + VEC_OVERHEAD;
                if insert_len > batch_size as u64 {
                    let ready = res;
                    res = Vec::new();
                    len = 0;
                    let s = sender.blocking_send(Ok(ready));
                    if s.is_err() {
                        break;
                    }
                } else {
                    len = insert_len;
                }
                res.push(edge);
            }
        }

        if !res.is_empty() {
            let _ = sender.blocking_send(Ok(res));
        }
        Ok(())
    }
}

#[derive(Debug, Serialize, Deserialize)]
pub struct EdgeDeletionEntry {
    pub room_id: Uid,
    pub src: Uid,
    pub src_entity: String,
    pub dest: Uid,
    pub label: String,
    pub cdate: i64,
    pub deletion_date: i64,
    pub verifying_key: Vec<u8>,
    pub signature: Vec<u8>,
    //used for synchronisation authorisation
    #[serde(skip)]
    pub entity_name: Option<String>,
}
impl EdgeDeletionEntry {
    pub fn build(
        room_id: Uid,
        edge: &Edge,
        deletion_date: i64,
        signing_key: &impl SigningKey,
    ) -> Self {
        let verifying_key = signing_key.export_verifying_key();
        let signature = Self::sign(&room_id, edge, deletion_date, &verifying_key, signing_key);
        Self {
            room_id,
            src: edge.src,
            src_entity: edge.src_entity.clone(),
            label: edge.label.clone(),
            dest: edge.dest,
            cdate: edge.cdate,
            deletion_date,
            verifying_key,
            signature,
            entity_name: None,
        }
    }

    pub fn sign(
        room_id: &[u8],
        edge: &Edge,
        deletion_date: i64,
        verifying_key: &[u8],
        signing_key: &impl SigningKey,
    ) -> Vec<u8> {
        let mut hasher = blake3::Hasher::new();
        hasher.update(room_id);
        hasher.update(&edge.src);
        hasher.update(edge.src_entity.as_bytes());
        hasher.update(edge.label.as_bytes());
        hasher.update(&edge.dest);
        hasher.update(&edge.cdate.to_le_bytes());
        hasher.update(&deletion_date.to_le_bytes());
        hasher.update(verifying_key);
        let hash = hasher.finalize();
        signing_key.sign(hash.as_bytes())
    }

    pub fn verify(&self) -> Result<()> {
        let mut hasher = blake3::Hasher::new();
        hasher.update(&self.room_id);
        hasher.update(&self.src);
        hasher.update(self.src_entity.as_bytes());
        hasher.update(self.label.as_bytes());
        hasher.update(&self.dest);
        hasher.update(&self.cdate.to_le_bytes());
        hasher.update(&self.deletion_date.to_le_bytes());
        hasher.update(&self.verifying_key);
        let hash = hasher.finalize();
        let pub_key = import_verifying_key(&self.verifying_key)?;
        pub_key.verify(hash.as_bytes(), &self.signature)?;
        Ok(())
    }

    pub fn get_entries(
        room_id: &Uid,
        entity: String,
        del_date: i64,
        batch_size: usize,
        sender: &mpsc::Sender<Result<Vec<EdgeDeletionEntry>>>,
        conn: &Connection,
    ) -> Result<()> {
        let mut stmt = conn.prepare_cached(
            "
            SELECT 
                room_id ,
                src ,
                src_entity , 
                dest ,
                label ,
                cdate ,
                deletion_date ,
                verifying_key ,
                signature 
            FROM _edge_deletion_log
            WHERE 
                room_id = ? AND
                src_entity = ? AND
                deletion_date >= ? AND deletion_date < ? 
        ",
        )?;

        let mut rows = stmt.query((room_id, entity, date(del_date), date_next_day(del_date)))?;
        let mut res = Vec::new();
        let mut len = 0;
        while let Some(row) = rows.next()? {
            let deletion_lo = Self {
                room_id: row.get(0)?,
                src: row.get(1)?,
                src_entity: row.get(2)?,
                dest: row.get(3)?,
                label: row.get(4)?,
                cdate: row.get(5)?,
                deletion_date: row.get(6)?,
                verifying_key: row.get(7)?,
                signature: row.get(8)?,
                entity_name: None,
            };
            let size = bincode::serialized_size(&deletion_lo)?;
            let insert_len = len + size + VEC_OVERHEAD;
            if insert_len > batch_size as u64 {
                let ready = res;
                res = Vec::new();
                len = 0;
                let s = sender.blocking_send(Ok(ready));
                if s.is_err() {
                    break;
                }
            } else {
                len = insert_len;
            }
            res.push(deletion_lo);
        }
        if !res.is_empty() {
            let _ = sender.blocking_send(Ok(res));
        }
        Ok(())
    }

    ///
    /// find the edge author to verify authorisation before deletion
    ///
    pub fn with_source_authors(
        edges: Vec<Self>,
        conn: &Connection,
    ) -> Result<Vec<(Self, Option<Vec<u8>>)>> {
        let mut result = Vec::new();

        let query = "
        SELECT verifying_key  
        FROM _edge WHERE 
            src=? AND 
            src_entity=? AND 
            label=? AND 
            dest=? AND 
            cdate=?";
        let mut stmt = conn.prepare_cached(query)?;
        for e in edges {
            let rs: Option<Vec<u8>> = stmt
                .query_row(
                    (&e.src, &e.src_entity, &e.label, &e.dest, &e.cdate),
                    |row| row.get(0),
                )
                .optional()?;

            result.push((e, rs));
        }
        Ok(result)
    }

    ///
    /// Delete every entry
    ///
    pub fn delete_all(
        edges: &mut Vec<Self>,
        daily_log: &mut DailyMutations,
        conn: &Connection,
    ) -> std::result::Result<(), rusqlite::Error> {
        let query = "
        DELETE FROM _edge WHERE 
            src=? AND 
            src_entity=? AND 
            label=? AND 
            dest=? AND 
            cdate=?
        ";
        let mut stmt = conn.prepare_cached(query)?;
        for e in edges {
            stmt.execute((&e.src, &e.src_entity, &e.label, &e.dest, &e.cdate))?;
            daily_log.set_need_update(e.room_id, &e.src_entity, e.deletion_date);
            e.write(conn)?;
        }
        Ok(())
    }
}
impl Writeable for EdgeDeletionEntry {
    fn write(&mut self, conn: &Connection) -> std::result::Result<(), rusqlite::Error> {
        let mut insert_stmt = conn.prepare_cached(
            "INSERT OR REPLACE INTO _edge_deletion_log (
            room_id,
            src,
            src_entity, 
            dest,
            label,
            cdate,
            deletion_date,
            verifying_key,
            signature
        ) VALUES (?,?,?,?,?,?,?,?,?)",
        )?;

        insert_stmt.execute((
            &self.room_id,
            &self.src,
            &self.src_entity,
            &self.dest,
            &self.label,
            &self.cdate,
            &self.deletion_date,
            &self.verifying_key,
            &self.signature,
        ))?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {

    use crate::{
        database::sqlite_database::prepare_connection,
        date_utils::now,
        security::{new_uid, Ed25519SigningKey, SigningKey},
    };

    use super::*;

    #[test]
    fn edge_signature() {
        let keypair = Ed25519SigningKey::new();
        let from = new_uid();
        let to = new_uid();
        let mut e = Edge {
            src: from.clone(),
            src_entity: "0".to_string(),
            label: String::from("Test"),
            dest: to.clone(),
            ..Default::default()
        };

        e.sign(&keypair).unwrap();
        e.verify().unwrap();

        let bad_id = new_uid();
        e.src = bad_id;
        e.verify()
            .expect_err("'from' has changed, verification must fail");
        e.src = from.clone();
        e.verify().unwrap();

        e.dest = bad_id;
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

        e.signature = bad_id.to_vec();
        e.verify()
            .expect_err("wrong signature, verification must fail");
    }

    #[test]
    fn edge_database() {
        let signing_key = Ed25519SigningKey::new();
        let conn = Connection::open_in_memory().unwrap();
        prepare_connection(&conn).unwrap();
        let label = "pet";
        let from = new_uid();
        let to = new_uid();
        let mut e = Edge {
            src: from.clone(),
            src_entity: "0".to_string(),
            label: String::from(label),
            dest: to.clone(),
            ..Default::default()
        };

        e.sign(&signing_key).unwrap();
        e.write(&conn).unwrap();

        let mut new_edge = Edge::get(&from, label, &to, &conn).unwrap().unwrap();
        new_edge.sign(&signing_key).unwrap();
        new_edge
            .write(&conn)
            .expect("edge allready exist and has been replaced");

        let edges = Edge::get_edges(&from, label, &conn).unwrap();
        assert_eq!(1, edges.len());

        new_edge.dest = new_uid();
        new_edge.sign(&signing_key).unwrap();
        new_edge.write(&conn).unwrap();

        let edges = Edge::get_edges(&from, label, &conn).unwrap();
        assert_eq!(2, edges.len());

        new_edge.delete(&conn).unwrap();
        let edges = Edge::get_edges(&from, label, &conn).unwrap();
        assert_eq!(1, edges.len());
    }

    #[test]
    fn deletion_log() {
        let signing_key = Ed25519SigningKey::new();
        let conn = Connection::open_in_memory().unwrap();
        prepare_connection(&conn).unwrap();
        let label = "pet";
        let from = new_uid();
        let to = new_uid();
        let mut e = Edge {
            src: from.clone(),
            src_entity: "0".to_string(),
            label: String::from(label),
            dest: to.clone(),
            ..Default::default()
        };

        e.sign(&signing_key).unwrap();
        e.write(&conn).unwrap();
        e.delete(&conn).unwrap();
        let room_id = new_uid();
        let mut log = EdgeDeletionEntry::build(room_id, &e, now(), &signing_key);

        log.write(&conn).unwrap();

        let batch_size = 4096;
        let (reply, mut receive) = mpsc::channel::<Result<Vec<EdgeDeletionEntry>>>(1);

        EdgeDeletionEntry::get_entries(
            &room_id,
            e.src_entity.clone(),
            now(),
            batch_size,
            &reply,
            &conn,
        )
        .unwrap();
        let entries = receive.blocking_recv().unwrap().unwrap();
        assert_eq!(1, entries.len());
        let entry = &entries[0];
        entry.verify().unwrap();

        assert_eq!(&e.src, &entry.src);
        assert_eq!(&e.src_entity, &entry.src_entity);
        assert_eq!(&e.label, &entry.label);
        assert_eq!(&e.dest, &entry.dest);
    }

    #[test]
    fn delete_edge_from_log() {
        let signing_key = Ed25519SigningKey::new();
        let conn = Connection::open_in_memory().unwrap();
        prepare_connection(&conn).unwrap();
        let label = "pet";
        let from = new_uid();
        let to = new_uid();
        let mut e = Edge {
            src: from.clone(),
            src_entity: "0".to_string(),
            label: String::from(label),
            dest: to.clone(),
            ..Default::default()
        };
        e.sign(&signing_key).unwrap();
        e.write(&conn).unwrap();

        let room_id = new_uid();
        let mut log = EdgeDeletionEntry::build(room_id, &e, now(), &signing_key);
        log.write(&conn).unwrap();

        let batch_size = 4096;
        let (reply, mut receive) = mpsc::channel::<Result<Vec<EdgeDeletionEntry>>>(1);

        EdgeDeletionEntry::get_entries(
            &room_id,
            e.src_entity.clone(),
            now(),
            batch_size,
            &reply,
            &conn,
        )
        .unwrap();
        let entries = receive.blocking_recv().unwrap().unwrap();
        assert_eq!(1, entries.len());
        let entry = &entries[0];
        entry.verify().unwrap();

        assert_eq!(&e.src, &entry.src);
        assert_eq!(&e.src_entity, &entry.src_entity);
        assert_eq!(&e.label, &entry.label);
        assert_eq!(&e.dest, &entry.dest);

        let with_author = EdgeDeletionEntry::with_source_authors(entries, &conn).unwrap();
        assert_eq!(1, with_author.len());
        let entry = &with_author[0];
        assert!(entry.1.is_some());

        let edge = Edge::get(&e.src, &e.label, &e.dest, &conn).unwrap();
        assert!(edge.is_some());

        let (reply, mut receive) = mpsc::channel::<Result<Vec<EdgeDeletionEntry>>>(1);

        EdgeDeletionEntry::get_entries(
            &room_id,
            e.src_entity.clone(),
            now(),
            batch_size,
            &reply,
            &conn,
        )
        .unwrap();
        let mut entries = receive.blocking_recv().unwrap().unwrap();
        EdgeDeletionEntry::delete_all(&mut entries, &mut DailyMutations::new(), &conn).unwrap();

        let edge = Edge::get(&e.src, &e.label, &e.dest, &conn).unwrap();
        assert!(edge.is_none());
    }
}
