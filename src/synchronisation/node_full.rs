use std::collections::HashMap;

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
        conn: &Connection,
    ) -> Result<Vec<FullNode>> {
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

        let res: Vec<FullNode> = map.into_iter().map(|(_, node)| node).collect();
        Ok(res)
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

#[cfg(test)]
mod tests {

    use std::{collections::HashSet, fs, path::PathBuf};

    use crate::{
        configuration::Configuration,
        database::{
            graph_database::GraphDatabaseService,
            node::NodeIdentifier,
            query_language::parameter::{Parameters, ParametersAdd},
            room_node::RoomNode,
        },
        date_utils::now,
        event_service::EventService,
        security::{base64_encode, new_uid, random32, Ed25519SigningKey},
    };

    use super::*;

    const DATA_PATH: &str = "test_data/database/node_full/";
    fn init_database_path() {
        let path: PathBuf = DATA_PATH.into();
        fs::create_dir_all(&path).unwrap();
    }

    #[test]
    fn get_full_node() {
        let conn = Connection::open_in_memory().unwrap();
        Node::create_tables(&conn).unwrap();
        Edge::create_tables(&conn).unwrap();

        let signing_key = Ed25519SigningKey::new();
        let entity = "Pet";
        let room_id1 = new_uid();
        let date = 1000;
        let mut raw_node = Node {
            room_id: Some(room_id1.clone()),
            _entity: String::from(entity),
            mdate: date,
            ..Default::default()
        };
        raw_node.sign(&signing_key).unwrap();
        raw_node.write(&conn, false, &None, &None).unwrap();

        let mut node_ids = Vec::new();
        node_ids.push(raw_node.id);
        let nodes = FullNode::get_nodes_filtered_by_room(&room_id1, node_ids, &conn).unwrap();
        assert_eq!(1, nodes.len());
        assert_eq!(raw_node.id, nodes[0].node.id);

        let mut node_with_one_edge = Node {
            room_id: Some(room_id1.clone()),
            _entity: String::from(entity),
            mdate: date,
            ..Default::default()
        };
        node_with_one_edge.sign(&signing_key).unwrap();
        node_with_one_edge
            .write(&conn, false, &None, &None)
            .unwrap();

        let mut edge = Edge {
            src: node_with_one_edge.id,
            src_entity: String::from(entity),
            label: "afield".to_string(),
            cdate: date,
            dest: raw_node.id,
            verifying_key: Vec::new(),
            signature: Vec::new(),
        };
        edge.sign(&signing_key).unwrap();
        edge.write(&conn).unwrap();

        let mut node_ids = Vec::new();
        node_ids.push(node_with_one_edge.id);

        let nodes = FullNode::get_nodes_filtered_by_room(&room_id1, node_ids, &conn).unwrap();
        assert_eq!(1, nodes.len());
        let full = &nodes[0];
        assert_eq!(node_with_one_edge.id, full.node.id);
        assert_eq!(1, full.edges.len());
        assert_eq!(edge.src, full.edges[0].src);

        let mut node_with_two_edge = Node {
            room_id: Some(room_id1.clone()),
            _entity: String::from(entity),
            mdate: date,
            ..Default::default()
        };
        node_with_two_edge.sign(&signing_key).unwrap();
        node_with_two_edge
            .write(&conn, false, &None, &None)
            .unwrap();

        let mut edge = Edge {
            src: node_with_two_edge.id,
            src_entity: String::from(entity),
            label: "afield".to_string(),
            cdate: date,
            dest: raw_node.id,
            verifying_key: Vec::new(),
            signature: Vec::new(),
        };
        edge.sign(&signing_key).unwrap();
        edge.write(&conn).unwrap();

        let mut edge = Edge {
            src: node_with_two_edge.id,
            src_entity: String::from(entity),
            label: "another_field".to_string(),
            cdate: date,
            dest: raw_node.id,
            verifying_key: Vec::new(),
            signature: Vec::new(),
        };
        edge.sign(&signing_key).unwrap();
        edge.write(&conn).unwrap();

        let mut node_ids = Vec::new();
        node_ids.push(node_with_two_edge.id);

        let nodes = FullNode::get_nodes_filtered_by_room(&room_id1, node_ids, &conn).unwrap();
        assert_eq!(1, nodes.len());
        let full = &nodes[0];
        assert_eq!(node_with_two_edge.id, full.node.id);
        assert_eq!(2, full.edges.len());

        let mut node_ids = Vec::new();
        node_ids.push(raw_node.id);
        node_ids.push(node_with_one_edge.id);
        node_ids.push(node_with_two_edge.id);

        let nodes = FullNode::get_nodes_filtered_by_room(&room_id1, node_ids, &conn).unwrap();
        assert_eq!(3, nodes.len());
    }

    #[test]
    fn prepare_full_node() {
        let conn = Connection::open_in_memory().unwrap();
        Node::create_tables(&conn).unwrap();
        Edge::create_tables(&conn).unwrap();

        let signing_key = Ed25519SigningKey::new();
        let entity = "Pet";
        let room_id1 = new_uid();
        let date = 1000;

        let json = r#"{
            "key": "value"
        }"#;

        let mut node1 = Node {
            room_id: Some(room_id1.clone()),
            _entity: String::from(entity),
            mdate: date,
            _json: Some(json.to_string()),
            ..Default::default()
        };
        node1.sign(&signing_key).unwrap();
        node1.write(&conn, false, &None, &None).unwrap();

        let mut node2 = Node {
            room_id: Some(room_id1.clone()),
            _entity: String::from(entity),
            mdate: date,
            ..Default::default()
        };
        node2.sign(&signing_key).unwrap();
        node2.write(&conn, false, &None, &None).unwrap();

        let mut node1_new = node1.clone();
        node1_new.mdate = now();
        node1_new._local_id = None;
        node1_new.sign(&signing_key).unwrap();

        node1_new._json = Some(
            r#"{
            "key": "another"
        }"#
            .to_string(),
        );

        let mut node2_new = node2.clone();
        node2_new._local_id = None;
        node2_new.sign(&signing_key).unwrap();

        let mut full_nodes = Vec::new();
        full_nodes.push(FullNode {
            node: node1_new,
            edges: Vec::new(),
            ..Default::default()
        });

        full_nodes.push(FullNode {
            node: node2_new,
            edges: Vec::new(),
            ..Default::default()
        });

        let prepared = FullNode::prepare_for_insert(&room_id1, full_nodes, &conn).unwrap();
        assert_eq!(1, prepared.len());
        let node = &prepared[0];
        assert!(node.node._local_id.is_some());
        assert!(node.old_fts_str.is_some());
        assert!(node.node_fts_str.is_some());
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn synchronize_full_node() {
        init_database_path();
        let data_model = "
        {
            Person{ 
                name:String, 
                parents:[Person]
            }
        }   
        ";

        let secret = random32();
        let path: PathBuf = DATA_PATH.into();
        let (first_app, verifying_key, _) = GraphDatabaseService::start(
            "app",
            data_model,
            &secret,
            &random32(),
            path,
            &Configuration::default(),
            EventService::new(),
        )
        .await
        .unwrap();

        let first_user_id = base64_encode(&verifying_key);

        let secret = random32();
        let path: PathBuf = DATA_PATH.into();
        let (second_app, verifying_key, _) = GraphDatabaseService::start(
            "app",
            data_model,
            &secret,
            &random32(),
            path,
            &Configuration::default(),
            EventService::new(),
        )
        .await
        .unwrap();

        let second_user_id = base64_encode(&verifying_key);

        let mut param = Parameters::default();
        param.add("first_user_id", first_user_id.clone()).unwrap();
        param.add("second_user_id", second_user_id.clone()).unwrap();

        let room = first_app
            .mutate_raw(
                r#"mutate mut {
                    sys.Room{
                        admin: [{
                            verif_key:$first_user_id
                        }]
                        authorisations:[{
                            name:"admin"
                            rights:[{
                                entity:"Person"
                                mutate_self:true
                                mutate_all:true
                            }]
                            users: [{
                                verif_key:$first_user_id
                            },{
                                verif_key:$second_user_id
                            }]
                        }]
                    }

                }"#,
                Some(param),
            )
            .await
            .unwrap();

        let room_insert = &room.mutate_entities[0];
        let room_id = &room_insert.node_to_mutate.id;
        let room_id_b64 = base64_encode(room_id);

        let mut param = Parameters::default();
        param.add("room_id", room_id_b64.clone()).unwrap();
        let mutat = first_app
            .mutate_raw(
                r#"mutate mut {
                P1: Person{
                    room_id: $room_id
                    name: "me"
                    parents:[{name:"father"},{name:"mother"}]
                }
            }"#,
                Some(param),
            )
            .await
            .expect("can insert");

        let ent = &mutat.mutate_entities[0];
        assert_eq!("P1", ent.name);
        let _id1 = base64_encode(&ent.node_to_mutate.id);

        let node = first_app
            .get_room_node(room_id.clone())
            .await
            .unwrap()
            .unwrap();

        //room sent over network
        let ser = bincode::serialize(&node).unwrap();
        let node: RoomNode = bincode::deserialize(&ser).unwrap();
        second_app.add_room_node(node.clone()).await.unwrap();

        let node_ids = first_app
            .get_room_daily_nodes(room_id.clone(), now())
            .await
            .unwrap();
        assert_eq!(3, node_ids.len());

        //node_ids sent over network
        let ser = bincode::serialize(&node_ids).unwrap();
        let node_ids: HashSet<NodeIdentifier> = bincode::deserialize(&ser).unwrap();

        let filtered_nodes = second_app
            .filter_existing_node(node_ids, now())
            .await
            .unwrap();
        assert_eq!(3, filtered_nodes.len());

        //filtered_nodes sent over network
        let ser = bincode::serialize(&filtered_nodes).unwrap();
        let filtered_nodes: HashSet<NodeIdentifier> = bincode::deserialize(&ser).unwrap();

        let filtered_id: Vec<Uid> = filtered_nodes.into_iter().map(|e| e.id).collect();
        let full_nodes: Vec<FullNode> = first_app
            .get_full_nodes(room_id.clone(), filtered_id)
            .await
            .unwrap();
        assert_eq!(3, full_nodes.len());

        //full_nodes sent over network
        let ser = bincode::serialize(&full_nodes).unwrap();
        let full_nodes: Vec<FullNode> = bincode::deserialize(&ser).unwrap();

        let v = second_app
            .add_full_nodes(room_id.clone(), full_nodes)
            .await
            .unwrap();
        assert_eq!(0, v.len());

        let result = second_app
            .query(
                "query q{
                Person{
                    name
                    parents(order_by(name desc)){name}
                }
            }",
                None,
            )
            .await
            .unwrap();

        assert_eq!(result, "{\n\"Person\":[{\"name\":\"me\",\"parents\":[{\"name\":\"mother\"},{\"name\":\"father\"}]}]\n}");
    }
}
