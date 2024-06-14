use std::collections::HashMap;

use crate::database::VEC_OVERHEAD;
use crate::security::{base64_decode, Uid};

use crate::database::{
    daily_log::DailyMutations,
    edge::Edge,
    node::{extract_json, Node},
    query_language::{data_model_parser::Entity, FieldType},
    sqlite_database::Writeable,
    Error, Result,
};

use rusqlite::{params_from_iter, Connection};
use serde::{Deserialize, Serialize};
use tokio::sync::mpsc;

///
/// data structure to get a node and all its edges
/// used during synchronisation
/// only node and edges are sent, the rest is used by the receiver to synchronise data
///
#[derive(Serialize, Deserialize, Debug, Clone, Default)]
pub struct FullNode {
    pub node: Node,
    pub edges: Vec<Edge>,
    #[serde(skip)]
    pub entity_name: Option<String>,
    #[serde(skip)]
    pub index: bool,
    #[serde(skip)]
    pub old_room_id: Option<Uid>,
    #[serde(skip)]
    pub old_mdate: i64,
    #[serde(skip)]
    pub old_verifying_key: Option<Vec<u8>>,
    #[serde(skip)]
    pub old_fts_str: Option<String>,
    #[serde(skip)]
    pub node_fts_str: Option<String>,
}
impl FullNode {
    pub fn get_nodes_filtered_by_room(
        room_id: &Uid,
        node_ids: Vec<Uid>,
        batch_size: usize,
        sender: &mpsc::Sender<Result<Vec<FullNode>>>,
        conn: &Connection,
    ) -> Result<()> {
        let it = &mut node_ids.iter().peekable();
        let mut q = String::new();
        while let Some(_) = it.next() {
            q.push('?');
            if it.peek().is_some() {
                q.push(',');
            }
        }

        let query = format!("
        SELECT 
            _node.id , _node.room_id, _node.cdate, _node.mdate, _node._entity, _node._json, _node._binary, _node.verifying_key, _node._signature, rowid,
            _edge.src, _edge.src_entity, _edge.label, _edge.dest, _edge.cdate, _edge.verifying_key, _edge.signature
        FROM _node
        LEFT JOIN _edge ON _node.id = _edge.src 
        WHERE 
            _node.id in ({}) 
        ", q);

        let mut stmt = conn.prepare(&query)?;
        let mut rows = stmt.query(params_from_iter(node_ids.iter()))?;

        let mut map: HashMap<Uid, Self> = HashMap::new();
        while let Some(row) = rows.next()? {
            let id: Uid = row.get(0)?;

            if !map.contains_key(&id) {
                let db_room_id: Option<Uid> = row.get(1)?;
                match &db_room_id {
                    Some(rid) => {
                        if !rid.eq(room_id) {
                            continue;
                        }
                    }
                    None => {
                        continue;
                    }
                }
                let node = Node {
                    id: id,
                    room_id: db_room_id,
                    cdate: row.get(2)?,
                    mdate: row.get(3)?,
                    _entity: row.get(4)?,
                    _json: row.get(5)?,
                    _binary: row.get(6)?,
                    verifying_key: row.get(7)?,
                    _signature: row.get(8)?,
                    _local_id: row.get(9)?,
                };

                map.insert(
                    id,
                    FullNode {
                        node,
                        edges: Vec::new(),
                        ..Default::default()
                    },
                );
            }

            let entry = map.get_mut(&id).unwrap(); //a new value as been inserted just before

            let src_opt: Option<Uid> = row.get(10)?;
            if let Some(src) = src_opt {
                let edge = Edge {
                    src,
                    src_entity: row.get(11)?,
                    label: row.get(12)?,
                    dest: row.get(13)?,
                    cdate: row.get(14)?,
                    verifying_key: row.get(15)?,
                    signature: row.get(16)?,
                };
                entry.edges.push(edge);
            }
        }

        let mut res: Vec<FullNode> = Vec::new();
        let mut len = 0;
        for entry in map {
            let node = entry.1;
            let size = bincode::serialized_size(&node)?;
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
            res.push(node);
        }
        if !res.is_empty() {
            let _ = sender.blocking_send(Ok(res));
        }
        Ok(())
    }

    pub fn get_local_nodes(node_ids: Vec<Uid>, conn: &Connection) -> Result<Vec<FullNode>> {
        let it = &mut node_ids.iter().peekable();
        let mut q = String::new();
        while let Some(_) = it.next() {
            q.push('?');
            if it.peek().is_some() {
                q.push(',');
            }
        }

        let query = format!("
        SELECT 
            _node.id , _node.room_id, _node.cdate, _node.mdate, _node._entity, _node._json, _node._binary, _node.verifying_key, _node._signature, rowid,
            _edge.src, _edge.src_entity, _edge.label, _edge.dest, _edge.cdate, _edge.verifying_key, _edge.signature
        FROM _node
        LEFT JOIN _edge ON _node.id = _edge.src 
        WHERE 
            _node.id in ({}) 
        ", q);

        let mut stmt = conn.prepare(&query)?;
        let mut rows = stmt.query(params_from_iter(node_ids.iter()))?;

        let mut map: HashMap<Uid, Self> = HashMap::new();
        while let Some(row) = rows.next()? {
            let id: Uid = row.get(0)?;

            if !map.contains_key(&id) {
                let db_room_id: Option<Uid> = row.get(1)?;
                let node = Node {
                    id: id,
                    room_id: db_room_id,
                    cdate: row.get(2)?,
                    mdate: row.get(3)?,
                    _entity: row.get(4)?,
                    _json: row.get(5)?,
                    _binary: row.get(6)?,
                    verifying_key: row.get(7)?,
                    _signature: row.get(8)?,
                    _local_id: row.get(9)?,
                };

                map.insert(
                    id,
                    FullNode {
                        node,
                        edges: Vec::new(),
                        ..Default::default()
                    },
                );
            }

            let entry = map.get_mut(&id).unwrap(); //a new value as been inserted just before

            let src_opt: Option<Uid> = row.get(10)?;
            if let Some(src) = src_opt {
                let edge = Edge {
                    src,
                    src_entity: row.get(11)?,
                    label: row.get(12)?,
                    dest: row.get(13)?,
                    cdate: row.get(14)?,
                    verifying_key: row.get(15)?,
                    signature: row.get(16)?,
                };
                entry.edges.push(edge);
            }
        }

        let res: Vec<FullNode> = map.into_iter().map(|(_, node)| node).collect();
        Ok(res)
    }

    //
    // This check ignores additional field because two clients might have different versions of the data model
    //  and the datamodel is designed to be backward compatible
    //
    pub fn entity_validation(&mut self, entity: &Entity) -> Result<()> {
        self.index = entity.enable_full_text;
        self.entity_name = Some(entity.name.to_string());
        for edge in &self.edges {
            if !edge.src.eq(&self.node.id) {
                return Err(Error::InvalidFullNode(
                    "Edge.src and Node.id missmatch".to_string(),
                ));
            }
        }

        if let Some(json_str) = &self.node._json {
            let json: serde_json::Value = serde_json::from_str(json_str)?;
            if !json.is_object() {
                return Err(Error::InvalidJsonObject("in NodeFull".to_string()));
            }
            let json = json.as_object().unwrap();
            for f in &entity.fields {
                let name = f.0;
                let field = f.1;
                let short_name = &field.short_name;
                if !field.is_system {
                    match field.field_type {
                        FieldType::Boolean => {
                            match json.get(short_name) {
                                Some(value) => {
                                    if value.as_bool().is_none() {
                                        return Err(Error::InvalidJsonFieldValue(
                                            name.to_string(),
                                            "Boolean".to_string(),
                                        ));
                                    }
                                }
                                None => {
                                    if !field.nullable && field.default_value.is_none() {
                                        return Err(Error::MissingJsonField(name.to_string()));
                                    }
                                }
                            };
                        }
                        FieldType::Float => {
                            match json.get(short_name) {
                                Some(value) => {
                                    if value.as_f64().is_none() {
                                        return Err(Error::InvalidJsonFieldValue(
                                            name.to_string(),
                                            "Float".to_string(),
                                        ));
                                    }
                                }
                                None => {
                                    if !field.nullable && field.default_value.is_none() {
                                        return Err(Error::MissingJsonField(name.to_string()));
                                    }
                                }
                            };
                        }
                        FieldType::Base64 => {
                            match json.get(short_name) {
                                Some(value) => {
                                    match value.as_str() {
                                        Some(str) => base64_decode(str.as_bytes())?,
                                        None => {
                                            return Err(Error::InvalidJsonFieldValue(
                                                name.to_string(),
                                                "Base64".to_string(),
                                            ))
                                        }
                                    };
                                }
                                None => {
                                    if !field.nullable && field.default_value.is_none() {
                                        return Err(Error::MissingJsonField(name.to_string()));
                                    };
                                }
                            };
                        }
                        FieldType::Integer => {
                            match json.get(short_name) {
                                Some(value) => {
                                    if value.as_i64().is_none() {
                                        return Err(Error::InvalidJsonFieldValue(
                                            name.to_string(),
                                            "Integer".to_string(),
                                        ));
                                    }
                                }
                                None => {
                                    if !field.nullable && field.default_value.is_none() {
                                        return Err(Error::MissingJsonField(name.to_string()));
                                    }
                                }
                            };
                        }
                        FieldType::String => {
                            match json.get(short_name) {
                                Some(value) => {
                                    if value.as_str().is_none() {
                                        return Err(Error::InvalidJsonFieldValue(
                                            name.to_string(),
                                            "String".to_string(),
                                        ));
                                    }
                                }
                                None => {
                                    if !field.nullable && field.default_value.is_none() {
                                        return Err(Error::MissingJsonField(name.to_string()));
                                    }
                                }
                            };
                        }
                        FieldType::Json => {
                            match json.get(short_name) {
                                Some(value) => {
                                    if !value.is_object() && !value.is_array() {
                                        return Err(Error::InvalidJsonFieldValue(
                                            name.to_string(),
                                            "Json".to_string(),
                                        ));
                                    }
                                }
                                None => {
                                    if !field.nullable && field.default_value.is_none() {
                                        return Err(Error::MissingJsonField(name.to_string()));
                                    }
                                }
                            };
                        }
                        FieldType::Array(_) | FieldType::Entity(_) => {}
                    };
                }
            }
        }
        Ok(())
    }

    pub fn prepare_for_insert(
        room_id: &Uid,
        nodes: Vec<FullNode>,
        conn: &Connection,
    ) -> Result<Vec<FullNode>> {
        let mut node_ids = Vec::new();
        let mut node_map = HashMap::new();

        for node in nodes {
            //
            // filter invalid room_id
            // It comes from a peer so let's be prudent
            //
            match &node.node.room_id {
                Some(rid) => {
                    if !room_id.eq(rid) {
                        continue;
                    }
                }
                None => continue,
            }

            node_ids.push(node.node.id);
            node_map.insert(node.node.id, node);
        }

        let existing_nodes = Self::get_local_nodes(node_ids, conn)?;

        let mut result: Vec<FullNode> = Vec::new();
        //process existing nodes
        for existing in existing_nodes {
            let id: Uid = existing.node.id;
            if let Some(mut new_node) = node_map.remove(&id) {
                let old_date: i64 = existing.node.mdate;
                if new_node.node.mdate > old_date {
                    let old_json_opt = &existing.node._json;
                    if let Some(json_str) = old_json_opt {
                        let json: serde_json::Value = serde_json::from_str(&json_str)?;
                        let mut old_tfs = String::new();
                        extract_json(&json, &mut old_tfs)?;
                        new_node.old_fts_str = Some(old_tfs);
                    }

                    if let Some(json_str) = &new_node.node._json {
                        let json: serde_json::Value = serde_json::from_str(&json_str)?;
                        let mut old_tfs = String::new();
                        extract_json(&json, &mut old_tfs)?;
                        new_node.node_fts_str = Some(old_tfs);
                    }
                    let rowid: i64 = existing.node._local_id.unwrap();
                    new_node.node._local_id = Some(rowid);
                    new_node.old_verifying_key = Some(existing.node.verifying_key.clone());
                    new_node.old_mdate = existing.node.mdate;
                    new_node.old_room_id = existing.node.room_id;
                    //filter existing edges
                    let mut new_edges: Vec<Edge> = Vec::new();
                    for new_edge in new_node.edges {
                        let old_edge_opt = existing.edges.iter().find(|old_edge| {
                            new_edge.src.eq(&old_edge.src)
                                && new_edge.label.eq(&old_edge.label)
                                && new_edge.dest.eq(&old_edge.dest)
                        });

                        if let Some(old_edge) = old_edge_opt {
                            if new_edge.cdate > old_edge.cdate {
                                new_edges.push(new_edge);
                            }
                        } else {
                            new_edges.push(new_edge);
                        }
                    }
                    new_node.edges = new_edges;
                    result.push(new_node);
                }
            };
        }
        //add new node
        for entry in node_map {
            result.push(entry.1);
        }
        Ok(result)
    }

    pub fn update_daily_logs(&self, daily_log: &mut DailyMutations) {
        if let Some(room_id) = &self.node.room_id {
            if let Some(old_id) = &self.old_room_id {
                if !room_id.eq(old_id) {
                    daily_log.set_need_update(old_id.clone(), &self.node._entity, self.old_mdate);
                }
            }
            daily_log.set_need_update(room_id.clone(), &self.node._entity, self.node.mdate);
        }
    }
}

impl Writeable for FullNode {
    fn write(&mut self, conn: &Connection) -> std::result::Result<(), rusqlite::Error> {
        self.node
            .write(conn, self.index, &self.old_fts_str, &self.node_fts_str)?;

        for edge in &self.edges {
            edge.write(conn)?;
        }
        Ok(())
    }
}
