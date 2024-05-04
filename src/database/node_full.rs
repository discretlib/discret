use std::collections::{HashMap, HashSet};

use crate::cryptography::base64_decode;

use super::{
    edge::Edge,
    node::{extract_json, Node, ARCHIVED_CHAR},
    query_language::{data_model_parser::Entity, FieldType},
    sqlite_database::Writeable,
    Error, Result,
};

use rusqlite::{params_from_iter, Connection};
use serde::{Deserialize, Serialize};

//
// data structure to get a node and all its edges
// used during synchronisation
// index,  old_fts_str, node_fts_str is intended to be filled by the reciever
//
#[derive(Serialize, Deserialize, Debug, Clone, Default)]
pub struct FullNode {
    pub node: Node,
    pub edges: Vec<Edge>,
    #[serde(skip)]
    pub entity_name: Option<String>,
    #[serde(skip)]
    pub index: bool,
    #[serde(skip)]
    pub old_verifying_key: Option<Vec<u8>>,
    #[serde(skip)]
    pub old_fts_str: Option<String>,
    #[serde(skip)]
    pub node_fts_str: Option<String>,
}
impl FullNode {
    pub fn get_nodes(node_ids: HashSet<Vec<u8>>, conn: &Connection) -> Result<Vec<FullNode>> {
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
            _node.id , _node.room_id, _node.cdate, _node.mdate, _node._entity, _node._json, _node._binary, _node._verifying_key, _node._signature, 
            _edge.src, _edge.src_entity, _edge.label, _edge.dest, _edge.cdate, _edge.verifying_key, _edge.signature
        FROM _node
        LEFT JOIN _edge ON _node.id = _edge.src 
        WHERE 
            substr(_node._entity,1,1) != '{}' AND
            _node.id in ({}) 
        ",ARCHIVED_CHAR, q);

        let mut stmt = conn.prepare(&query)?;
        let mut rows = stmt.query(params_from_iter(node_ids.iter()))?;

        let mut map: HashMap<Vec<u8>, Self> = HashMap::new();
        while let Some(row) = rows.next()? {
            let id: Vec<u8> = row.get(0)?;
            let entry = map.entry(id.clone()).or_insert({
                let node = Node {
                    id: id.clone(),
                    room_id: row.get(1)?,
                    cdate: row.get(2)?,
                    mdate: row.get(3)?,
                    _entity: row.get(4)?,
                    _json: row.get(5)?,
                    _binary: row.get(6)?,
                    _verifying_key: row.get(7)?,
                    _signature: row.get(8)?,
                    _local_id: None,
                };

                FullNode {
                    node,
                    edges: Vec::new(),
                    ..Default::default()
                }
            });

            let src_opt: Option<Vec<u8>> = row.get(9)?;
            if let Some(src) = src_opt {
                let edge = Edge {
                    src,
                    src_entity: row.get(10)?,
                    label: row.get(11)?,
                    dest: row.get(12)?,
                    cdate: row.get(13)?,
                    verifying_key: row.get(14)?,
                    signature: row.get(15)?,
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

    pub fn prepare_for_insert(nodes: Vec<FullNode>, conn: &Connection) -> Result<Vec<FullNode>> {
        let mut node_map = HashMap::new();
        let it = &mut nodes.into_iter().peekable();
        let mut q = String::new();
        while let Some(node) = it.next() {
            q.push('?');
            if it.peek().is_some() {
                q.push(',');
            }
            node_map.insert(node.node.id.clone(), node);
        }
        let query = format!(
            "
        SELECT 
            id , mdate, _json, rowid 
        FROM _node
        WHERE 
            substr(_node._entity,1,1) != '{}' AND
            id in ({}) 
        ",
            ARCHIVED_CHAR, q
        );
        let mut stmt = conn.prepare(&query)?;
        let ids: Vec<&Vec<u8>> = node_map.iter().map(|node| node.0).collect();
        let mut rows = stmt.query(params_from_iter(ids.iter()))?;

        while let Some(row) = rows.next()? {
            let id: Vec<u8> = row.get(0)?;
            if let Some(new_node) = node_map.get_mut(&id) {
                let mdate: i64 = row.get(1)?;
                if mdate < new_node.node.mdate {
                    let old_json_opt: Option<String> = row.get(2)?;
                    if let Some(json_str) = old_json_opt {
                        let json: serde_json::Value = serde_json::from_str(&json_str)?;
                        let mut old_tfs = String::new();
                        extract_json(&json, &mut old_tfs)?;
                        new_node.old_fts_str = Some(old_tfs);
                    }
                    let rowid: i64 = row.get(3)?;
                    if let Some(json_str) = &new_node.node._json {
                        let json: serde_json::Value = serde_json::from_str(&json_str)?;
                        let mut old_tfs = String::new();
                        extract_json(&json, &mut old_tfs)?;
                        new_node.node_fts_str = Some(old_tfs);
                    }
                    new_node.node._local_id = Some(rowid);
                } else {
                    //a more recent version exists
                    node_map.remove(&id);
                }
            };
        }
        let result: Vec<FullNode> = node_map.into_iter().map(|entry| entry.1).collect();
        Ok(result)
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

    use std::{fs, path::PathBuf};

    use crate::{
        cryptography::{base64_encode, random32, Ed25519SigningKey},
        database::{
            authorisation_sync::RoomNode,
            configuration::Configuration,
            graph_database::GraphDatabaseService,
            query_language::parameter::{Parameters, ParametersAdd},
        },
        date_utils::now,
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
        let room_id1 = random32();
        let date = 1000;
        let mut raw_node = Node {
            room_id: Some(room_id1.to_vec()),
            _entity: String::from(entity),
            mdate: date,
            ..Default::default()
        };
        raw_node.sign(&signing_key).unwrap();
        raw_node.write(&conn, false, &None, &None).unwrap();

        let mut node_ids = HashSet::new();
        node_ids.insert(raw_node.id.clone());
        let nodes = FullNode::get_nodes(node_ids, &conn).unwrap();
        assert_eq!(1, nodes.len());
        assert_eq!(raw_node.id, nodes[0].node.id);

        let mut node_with_one_edge = Node {
            room_id: Some(room_id1.to_vec()),
            _entity: String::from(entity),
            mdate: date,
            ..Default::default()
        };
        node_with_one_edge.sign(&signing_key).unwrap();
        node_with_one_edge
            .write(&conn, false, &None, &None)
            .unwrap();

        let mut edge = Edge {
            src: node_with_one_edge.id.clone(),
            src_entity: String::from(entity),
            label: "afield".to_string(),
            cdate: date,
            dest: raw_node.id.clone(),
            verifying_key: Vec::new(),
            signature: Vec::new(),
        };
        edge.sign(&signing_key).unwrap();
        edge.write(&conn).unwrap();

        let mut node_ids = HashSet::new();
        node_ids.insert(node_with_one_edge.id.clone());
        let nodes = FullNode::get_nodes(node_ids, &conn).unwrap();
        assert_eq!(1, nodes.len());
        let full = &nodes[0];
        assert_eq!(node_with_one_edge.id, full.node.id);
        assert_eq!(1, full.edges.len());
        assert_eq!(edge.src, full.edges[0].src);

        let mut node_with_two_edge = Node {
            room_id: Some(room_id1.to_vec()),
            _entity: String::from(entity),
            mdate: date,
            ..Default::default()
        };
        node_with_two_edge.sign(&signing_key).unwrap();
        node_with_two_edge
            .write(&conn, false, &None, &None)
            .unwrap();

        let mut edge = Edge {
            src: node_with_two_edge.id.clone(),
            src_entity: String::from(entity),
            label: "afield".to_string(),
            cdate: date,
            dest: raw_node.id.clone(),
            verifying_key: Vec::new(),
            signature: Vec::new(),
        };
        edge.sign(&signing_key).unwrap();
        edge.write(&conn).unwrap();

        let mut edge = Edge {
            src: node_with_two_edge.id.clone(),
            src_entity: String::from(entity),
            label: "another_field".to_string(),
            cdate: date,
            dest: raw_node.id.clone(),
            verifying_key: Vec::new(),
            signature: Vec::new(),
        };
        edge.sign(&signing_key).unwrap();
        edge.write(&conn).unwrap();

        let mut node_ids = HashSet::new();
        node_ids.insert(node_with_two_edge.id.clone());
        let nodes = FullNode::get_nodes(node_ids, &conn).unwrap();
        assert_eq!(1, nodes.len());
        let full = &nodes[0];
        assert_eq!(node_with_two_edge.id, full.node.id);
        assert_eq!(2, full.edges.len());

        let mut node_ids = HashSet::new();
        node_ids.insert(raw_node.id.clone());
        node_ids.insert(node_with_one_edge.id.clone());
        node_ids.insert(node_with_two_edge.id.clone());
        let nodes = FullNode::get_nodes(node_ids, &conn).unwrap();
        assert_eq!(3, nodes.len());
    }

    #[test]
    fn prepare_full_node() {
        let conn = Connection::open_in_memory().unwrap();
        Node::create_tables(&conn).unwrap();
        Edge::create_tables(&conn).unwrap();

        let signing_key = Ed25519SigningKey::new();
        let entity = "Pet";
        let room_id1 = random32();
        let date = 1000;

        let json = r#"{
            "key": "value"
        }"#;

        let mut node1 = Node {
            room_id: Some(room_id1.to_vec()),
            _entity: String::from(entity),
            mdate: date,
            _json: Some(json.to_string()),
            ..Default::default()
        };
        node1.sign(&signing_key).unwrap();
        node1.write(&conn, false, &None, &None).unwrap();

        let mut node2 = Node {
            room_id: Some(room_id1.to_vec()),
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

        let prepared = FullNode::prepare_for_insert(full_nodes, &conn).unwrap();
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
        Person{ 
            name:String, 
            parents:[Person]
        }   
        ";

        let secret = random32();
        let path: PathBuf = DATA_PATH.into();
        let first_app =
            GraphDatabaseService::start("app", data_model, &secret, path, Configuration::default())
                .await
                .unwrap();

        let first_user_id = base64_encode(first_app.verifying_key());

        let secret = random32();
        let path: PathBuf = DATA_PATH.into();
        let second_app =
            GraphDatabaseService::start("app", data_model, &secret, path, Configuration::default())
                .await
                .unwrap();

        let second_user_id = base64_encode(second_app.verifying_key());

        let mut param = Parameters::default();
        param.add("first_user_id", first_user_id.clone()).unwrap();
        param.add("second_user_id", second_user_id.clone()).unwrap();

        let room = first_app
            .mutate(
                r#"mutation mut {
                    _Room{
                        admin: [{
                            verifying_key:$first_user_id
                        }]
                        user_admin: [{
                            verifying_key:$first_user_id
                        }]
                        authorisations:[{
                            name:"admin"
                            rights:[{
                                entity:"Person"
                                mutate_self:true
                                delete_all:true
                                mutate_all:true
                            }]
                            users: [{
                                verifying_key:$first_user_id
                            },{
                                verifying_key:$second_user_id
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
        let room_id_b64 = base64_encode(&room_id);

        let mut param = Parameters::default();
        param.add("room_id", room_id_b64.clone()).unwrap();
        let mutat = first_app
            .mutate(
                r#"mutation mut {
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
            .get_daily_id_for_room(room_id.clone(), now())
            .await
            .unwrap();
        assert_eq!(3, node_ids.len());

        //node_ids sent over network
        let ser = bincode::serialize(&node_ids).unwrap();
        let node_ids: HashSet<Vec<u8>> = bincode::deserialize(&ser).unwrap();

        let filtered_nodes = second_app
            .filter_existing_node(node_ids, now())
            .await
            .unwrap();
        assert_eq!(3, filtered_nodes.len());

        //filtered_nodes sent over network
        let ser = bincode::serialize(&filtered_nodes).unwrap();
        let filtered_nodes: HashSet<Vec<u8>> = bincode::deserialize(&ser).unwrap();

        let full_nodes: Vec<FullNode> = first_app.get_full_nodes(filtered_nodes).await.unwrap();
        assert_eq!(3, full_nodes.len());

        //full_nodes sent over network
        let ser = bincode::serialize(&full_nodes).unwrap();
        let full_nodes: Vec<FullNode> = bincode::deserialize(&ser).unwrap();

        let v = second_app.add_full_node(full_nodes).await.unwrap();
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

        // println!("{:?}", result);
        assert_eq!(result, "{\n\"Person\":[{\"name\":\"me\",\"parents\":[{\"name\":\"mother\"},{\"name\":\"father\"}]}]\n}");
    }
}
