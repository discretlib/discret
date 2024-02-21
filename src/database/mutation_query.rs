use rusqlite::{Connection, OptionalExtension};

use crate::{base64_decode, base64_encode, Ed25519SigningKey};

use super::{
    edge::Edge,
    graph_database::{now, FromRow, QueryResult, Readable, Writeable},
    node::Node,
    query_language::{
        data_model::ID_FIELD,
        mutation_parser::{EntityMutation, MutationFieldValue, MutationParser},
        parameter::Parameters,
        FieldType,
    },
    Error, Result,
};
use std::{collections::HashMap, sync::Arc};

//
// used during the insertion of nodes to retrieve a previous node with its rowid
// the rowid will be used during the insertion to update the full text search table
//

#[derive(Debug)]
pub struct NodeInsert {
    pub id: Vec<u8>,
    pub rowid: Option<i64>,
    pub index: bool,
    pub previous_fts_str: Option<String>,
    pub current_fts_str: Option<String>,
    pub node: Option<Node>,
}
impl NodeInsert {
    pub fn write(&self, conn: &Connection) -> std::result::Result<(), rusqlite::Error> {
        if let Some(node) = &self.node {
            node.write(
                conn,
                self.index,
                &self.rowid,
                &self.previous_fts_str,
                &self.previous_fts_str,
            )?;
        }
        Ok(())
    }

    pub fn sign(&mut self, signing_key: &Ed25519SigningKey) -> std::result::Result<(), Error> {
        if let Some(node) = &mut self.node {
            node.sign(signing_key)?;
        }
        Ok(())
    }
}
impl Default for NodeInsert {
    fn default() -> Self {
        Self {
            id: Vec::new(),
            rowid: None,
            index: true,
            previous_fts_str: None,
            current_fts_str: None,
            node: None,
        }
    }
}

const NODE_INSERT_QUERY: &'static str = "SELECT id, cdate, mdate, _entity, _json_data, _binary_data, _pub_key, _signature, rowid FROM _node WHERE id=? AND _entity=?";
impl FromRow for NodeInsert {
    fn from_row() -> super::graph_database::MappingFn<Self> {
        |row| {
            Ok(Box::new(NodeInsert {
                id: row.get(0)?,
                rowid: row.get(8)?,
                index: true,
                previous_fts_str: None,
                current_fts_str: None,
                node: Some(Node {
                    id: row.get(0)?,
                    cdate: row.get(1)?,
                    mdate: row.get(2)?,
                    _entity: row.get(3)?,
                    _json_data: row.get(4)?,
                    _binary_data: row.get(5)?,
                    _pub_key: row.get(6)?,
                    _signature: row.get(7)?,
                }),
            }))
        }
    }
}

#[derive(Debug)]
pub struct MutationQuery {
    insert_enties: Vec<InsertEntity>,
}
impl Writeable for MutationQuery {
    fn write(&self, conn: &Connection) -> std::result::Result<QueryResult, rusqlite::Error> {
        for insert in &self.insert_enties {
            insert.write(conn)?;
        }
        Ok(QueryResult::None)
    }
}
impl MutationQuery {
    pub fn to_json(&self, mutation: &MutationParser) -> Result<serde_json::Value> {
        let mutas = &mutation.mutations;
        let inserts = &self.insert_enties;

        if mutas.len() != inserts.len() {
            return Err(Error::QueryError(String::from(
                "mutation query and InsertEntity result lenght are not equal",
            )));
        }
        let mut vec = Vec::new();
        for i in 0..mutas.len() {
            let ent_mut = &mutas[i];
            let insert_entity = &inserts[i];
            let js = insert_entity.to_json(ent_mut)?;
            vec.push(js);
        }

        Ok(serde_json::Value::Array(vec))
    }

    pub fn sign_all(&mut self, signing_key: &Ed25519SigningKey) -> Result<()> {
        for insert in &mut self.insert_enties {
            insert.sign_all(signing_key)?;
        }
        Ok(())
    }
}

#[derive(Debug)]
pub struct InsertEntity {
    pub name: String,
    pub node: NodeInsert,
    pub edge_deletions: Vec<Edge>,
    pub edge_insertions: Vec<Edge>,
    pub sub_nodes: HashMap<String, Vec<InsertEntity>>,
}

impl InsertEntity {
    fn write(&self, conn: &Connection) -> std::result::Result<QueryResult, rusqlite::Error> {
        for query in &self.sub_nodes {
            for insert in query.1 {
                insert.write(conn)?;
            }
        }
        self.node.write(conn)?;

        for edge in &self.edge_deletions {
            edge.delete(conn)?
        }
        for edge in &self.edge_insertions {
            edge.write(conn)?;
        }

        Ok(QueryResult::None)
    }

    pub fn sign_all(&mut self, signing_key: &Ed25519SigningKey) -> Result<()> {
        for query in &mut self.sub_nodes {
            for insert in query.1 {
                insert.sign_all(signing_key)?;
            }
        }

        self.node.sign(signing_key)?;

        for edge in &mut self.edge_insertions {
            edge.sign(signing_key)?;
        }

        Ok(())
    }

    pub fn to_json(&self, mutation: &EntityMutation) -> Result<serde_json::Value> {
        let mut map: serde_json::Map<String, serde_json::Value> = serde_json::Map::new();
        Self::fill_json(self, &mutation, &mut map)?;

        let mut final_map: serde_json::Map<String, serde_json::Value> = serde_json::Map::new();
        final_map.insert(String::from(&self.name), serde_json::Value::Object(map));

        Ok(serde_json::Value::Object(final_map))
    }

    fn fill_json(
        query: &Self,
        mutation: &EntityMutation,
        json_map: &mut serde_json::Map<String, serde_json::Value>,
    ) -> Result<()> {
        let node = &query.node;

        json_map.insert(
            String::from(ID_FIELD),
            serde_json::Value::String(base64_encode(&node.id)),
        );
        if let Some(node) = &node.node {
            if let Some(json_string) = &node._json_data {
                let json: serde_json::Value = serde_json::from_str(json_string)?;
                if let serde_json::Value::Object(obj) = json {
                    for field_tuple in &mutation.fields {
                        let field = field_tuple.1;
                        if !field.is_default_filled {
                            let val_opt = obj.get(&field.short_name);
                            if let Some(val) = val_opt {
                                json_map.insert(String::from(&field.name), val.clone());
                            }
                        }
                    }
                }
            }
        }
        for sub in &query.sub_nodes {
            let field_opt = mutation.fields.get(sub.0);
            if let Some(field) = field_opt {
                match &field.field_value {
                    MutationFieldValue::Array(mutations) => {
                        if sub.1.len() != mutations.len() {
                            return Err(Error::QueryError(String::from(
                                "inserts tree does not match with mutation tree",
                            )));
                        }
                        let mut arr = Vec::new();
                        for i in 0..mutations.len() {
                            let mut sub_map: serde_json::Map<String, serde_json::Value> =
                                serde_json::Map::new();
                            let mutation = &mutations[i];
                            let insert_entity = &sub.1[i];
                            Self::fill_json(insert_entity, mutation, &mut sub_map)?;
                            arr.push(serde_json::Value::Object(sub_map));
                        }
                        json_map.insert(sub.0.to_string(), serde_json::Value::Array(arr));
                    }
                    MutationFieldValue::Entity(mutation) => {
                        let mut sub_map: serde_json::Map<String, serde_json::Value> =
                            serde_json::Map::new();
                        if sub.1.len() != 1 {
                            return Err(Error::QueryError(String::from(
                                "inserts tree does not match with mutation tree",
                            )));
                        }
                        Self::fill_json(&sub.1[0], mutation, &mut sub_map)?;
                        json_map.insert(sub.0.to_string(), serde_json::Value::Object(sub_map));
                    }
                    _ => unreachable!(),
                }
            }
        }
        Ok(())
    }
}

impl Default for InsertEntity {
    fn default() -> Self {
        Self {
            name: String::from(""),
            node: NodeInsert {
                ..Default::default()
            },
            edge_deletions: Vec::new(),
            edge_insertions: Vec::new(),
            sub_nodes: HashMap::new(),
        }
    }
}

fn extract_json(val: &serde_json::Value, buff: &mut String) -> Result<()> {
    match val {
        serde_json::Value::String(v) => {
            buff.push_str(&v);
            buff.push('\n');
            Ok(())
        }
        serde_json::Value::Array(arr) => {
            for v in arr {
                extract_json(v, buff)?;
            }
            Ok(())
        }
        serde_json::Value::Object(map) => {
            for v in map {
                extract_json(v.1, buff)?;
            }
            Ok(())
        }
        _ => Ok(()),
    }
}

pub struct PrepareMutation {
    pub parameters: Parameters,
    pub mutation: Arc<MutationParser>,
}
impl Readable for PrepareMutation {
    fn read(&self, conn: &rusqlite::Connection) -> Result<QueryResult> {
        self.mutation.variables.validate_params(&self.parameters)?;
        let mut insert_queries = vec![];
        for entity in &self.mutation.mutations {
            let query = self.get_insert_query(entity, conn)?;

            insert_queries.push(query);
        }
        let query = MutationQuery {
            insert_enties: insert_queries,
        };

        Ok(QueryResult::MutationQuery(query))
    }
}

impl PrepareMutation {
    fn retrieve_id(
        &self,
        id_field: &super::query_language::mutation_parser::MutationField,
    ) -> Result<Option<Vec<u8>>> {
        Ok(match &id_field.field_value {
            MutationFieldValue::Variable(var) => {
                let value = self.parameters.params.get(var).unwrap();

                match value.as_string() {
                    Some(e) => Some(base64_decode(e.as_bytes())?),
                    None => None,
                }
            }
            MutationFieldValue::Value(value) => match value.as_string() {
                Some(e) => Some(base64_decode(e.as_bytes())?),
                None => None,
            },
            _ => unreachable!(),
        })
    }

    fn get_insert_query(&self, entity: &EntityMutation, conn: &Connection) -> Result<InsertEntity> {
        let mut node_insert = self.create_node_insert(entity, conn)?;

        let mut query = InsertEntity {
            name: entity.aliased_name(),
            ..Default::default()
        };

        if let Some(node) = &mut node_insert.node {
            let mut json: serde_json::Value = match &node._json_data {
                Some(e) => serde_json::from_str(e)?,
                None => serde_json::Value::Object(serde_json::Map::new()),
            };

            let mut previous = String::new();
            extract_json(&json, &mut previous)?;

            if previous.len() > 0 {
                node_insert.previous_fts_str = Some(previous);
            }

            let obj = match json.as_object_mut() {
                Some(e) => e,
                None => return Err(Error::InvalidJsonObject(json.to_string())),
            };

            let mut node_uptaded = false;
            for field_entry in &entity.fields {
                let field = field_entry.1;
                if !field.name.eq(ID_FIELD) {
                    match &field.field_type {
                        FieldType::Array(_) => match &field.field_value {
                            MutationFieldValue::Array(mutations) => {
                                let mut insert_queries = vec![];
                                for mutation in mutations {
                                    let insert_query = self.get_insert_query(mutation, conn)?;

                                    let target_id = insert_query.node.id.clone();

                                    if !Edge::exists(
                                        node_insert.id.clone(),
                                        field.short_name.to_string(),
                                        target_id.clone(),
                                        &conn,
                                    )? {
                                        let edge = Edge {
                                            src: node_insert.id.clone(),
                                            label: field.short_name.to_string(),
                                            dest: target_id,
                                            cdate: now(),
                                            ..Default::default()
                                        };
                                        query.edge_insertions.push(edge);
                                    }
                                    insert_queries.push(insert_query);
                                }
                                query
                                    .sub_nodes
                                    .insert(String::from(&field.name), insert_queries);
                            }
                            MutationFieldValue::Value(_) => {
                                //always a null value
                                let edges =
                                    Edge::get_edges(&node_insert.id, &field.short_name, conn)?;
                                for e in edges {
                                    query.edge_deletions.push(*e);
                                }
                            }
                            _ => unreachable!(),
                        },
                        FieldType::Entity(_) => match &field.field_value {
                            MutationFieldValue::Entity(mutation) => {
                                let edges =
                                    Edge::get_edges(&node_insert.id, &field.short_name, conn)?;
                                for e in edges {
                                    query.edge_deletions.push(*e);
                                }
                                let insert_query = self.get_insert_query(mutation, conn)?;

                                let target_id = insert_query.node.id.clone();
                                let edge = Edge {
                                    src: node_insert.id.clone(),
                                    label: field.short_name.to_string(),
                                    dest: target_id,
                                    cdate: now(),
                                    ..Default::default()
                                };
                                query.edge_insertions.push(edge);
                                query
                                    .sub_nodes
                                    .insert(String::from(&field.name), vec![insert_query]);
                            }
                            MutationFieldValue::Value(_) => {
                                //always a null value
                                let edges =
                                    Edge::get_edges(&node_insert.id, &field.short_name, conn)?;
                                for e in edges {
                                    query.edge_deletions.push(*e);
                                }
                            }
                            _ => unreachable!(),
                        },
                        FieldType::Boolean
                        | FieldType::Float
                        | FieldType::Base64
                        | FieldType::Integer
                        | FieldType::String => {
                            let value = match &field.field_value {
                                MutationFieldValue::Variable(v) => {
                                    let value = self.parameters.params.get(v).unwrap();
                                    value.as_serde_json_value()?
                                }
                                MutationFieldValue::Value(v) => v.as_serde_json_value()?,
                                _ => unreachable!(),
                            };
                            obj.insert(String::from(&field.short_name), value);
                            node_uptaded = true;
                        }
                    }
                }
            }
            if !node_uptaded {
                node_insert.node = None;
            } else {
                let json_data = serde_json::to_string(&json)?;
                node._json_data = Some(json_data);
                node.mdate = now();
            }
            //let mut node_opt =
        }
        query.node = node_insert;
        Ok(query)
    }

    fn create_node_insert(&self, entity: &EntityMutation, conn: &Connection) -> Result<NodeInsert> {
        let entity_name = &entity.name;
        let entity_short = &entity.short_name;
        match entity.fields.get(ID_FIELD) {
            Some(id_field) => {
                let id: Vec<u8> = self.retrieve_id(id_field)?.unwrap();
                if entity.fields.len() == 1 {
                    if Node::exist(&id, entity_short, &conn)? {
                        Ok(NodeInsert {
                            id,
                            ..Default::default()
                        })
                    } else {
                        return Err(Error::UnknownEntity(
                            String::from(entity_name),
                            base64_encode(&id),
                        ));
                    }
                } else {
                    let mut stmt = conn.prepare(NODE_INSERT_QUERY)?;
                    let results = stmt
                        .query_row((&id, entity_short), NodeInsert::from_row())
                        .optional()?;
                    let node: NodeInsert = match results {
                        Some(node) => *node,
                        None => {
                            return Err(Error::UnknownEntity(
                                String::from(entity_name),
                                base64_encode(&id),
                            ))
                        }
                    };
                    Ok(node)
                }
            }
            None => {
                let node = Node {
                    _entity: String::from(entity_short),
                    ..Default::default()
                };
                Ok(NodeInsert {
                    id: node.id.clone(),
                    node: Some(node),
                    ..Default::default()
                })
            }
        }
    }
}

#[cfg(test)]
mod tests {

    use std::{
        fs,
        path::{Path, PathBuf},
    };

    use rusqlite::Connection;

    use crate::database::{
        graph_database::prepare_connection,
        query_language::{data_model::DataModel, Value},
    };

    use super::*;

    const DATA_PATH: &str = "test/data/database/mutation_query";
    fn init_database_path(file: &str) -> Result<PathBuf> {
        let mut path: PathBuf = DATA_PATH.into();
        fs::create_dir_all(&path)?;
        path.push(file);
        if Path::exists(&path) {
            fs::remove_file(&path)?;
        }
        Ok(path)
    }

    #[test]
    fn prepare_simple_scalar() {
        let data_model = DataModel::parse(
            "
            Person {
                name : String ,
                age : Integer,
                weight : Float,
                is_human : Boolean, 
                some_nullable : String nullable,
                some_default : Integer default 2 
            }
        ",
        )
        .unwrap();

        let mutation = MutationParser::parse(
            r#"
            mutation mutmut {
                Person {
                    name : $name
                    age: $age
                    weight: $weight
                    is_human : $human
                    some_nullable : $null
                }
            } "#,
            &data_model,
        )
        .unwrap();

        let mut param = Parameters::new();
        param
            .add(String::from("name"), Value::String(String::from("John")))
            .unwrap();
        param.add(String::from("age"), Value::Integer(100)).unwrap();
        param
            .add(String::from("weight"), Value::Float(42.2))
            .unwrap();
        param
            .add(String::from("human"), Value::Boolean(true))
            .unwrap();
        param.add(String::from("null"), Value::Null).unwrap();

        let conn = Connection::open_in_memory().unwrap();
        prepare_connection(&conn).unwrap();

        let prep_mut = PrepareMutation {
            parameters: param,
            mutation: Arc::new(mutation),
        };

        let to_insert = prep_mut.read(&conn).unwrap();

        if let QueryResult::MutationQuery(mutation_query) = to_insert {
            let _js = mutation_query.to_json(&*prep_mut.mutation).unwrap();
            //println!("{}", serde_json::to_string_pretty(&js).unwrap());

            assert_eq!(1, mutation_query.insert_enties.len());

            //println!("{:#?}", mutation_query);
        }
    }

    #[test]
    fn prepare_double_mutation() {
        let data_model = DataModel::parse(
            "
            Person {
                name : String ,
            }
        ",
        )
        .unwrap();

        let mutation = MutationParser::parse(
            r#"
            mutation mutmut {
                Person {
                    name : $name
                }
                second : Person {
                    name : $name
                }

            } "#,
            &data_model,
        )
        .unwrap();

        let mut param = Parameters::new();
        param
            .add(String::from("name"), Value::String(String::from("John")))
            .unwrap();

        let conn = Connection::open_in_memory().unwrap();
        prepare_connection(&conn).unwrap();

        let prep_mut = PrepareMutation {
            parameters: param,
            mutation: Arc::new(mutation),
        };

        let to_insert = prep_mut.read(&conn).unwrap();

        if let QueryResult::MutationQuery(mutation_query) = to_insert {
            let js = mutation_query.to_json(&*prep_mut.mutation).unwrap();
            println!("{}", serde_json::to_string_pretty(&js).unwrap());
            assert_eq!(2, mutation_query.insert_enties.len());
            // let insert_ent = mutation_query.insert_enties[0];

            //println!("{:#?}", mutation_query);
        }
    }

    #[test]
    fn prepare_sub_entities() {
        let data_model = DataModel::parse(
            "
            Person {
                name : String ,
                parents : [Person] nullable,
                pet: Pet nullable,
                siblings : [Person] nullable
            }

            Pet {
                name : String
            }
        ",
        )
        .unwrap();

        let mutation = MutationParser::parse(
            r#"
            mutation mutmut {
                Person {
                    name : $name
                    parents : [
                        {name : $mother} 
                        ,{
                            name:$father
                            pet:{ name:"kiki" }
                        }
                    ]
                    pet: {name:$pet_name}
                    siblings:[{name:"Wallis"},{ name : $sibling }]
                }
            } "#,
            &data_model,
        )
        .unwrap();

        let mut param = Parameters::new();
        param
            .add(String::from("name"), Value::String(String::from("John")))
            .unwrap();
        param
            .add(String::from("mother"), Value::String(String::from("Hello")))
            .unwrap();
        param
            .add(String::from("father"), Value::String(String::from("World")))
            .unwrap();
        param
            .add(
                String::from("pet_name"),
                Value::String(String::from("Truffle")),
            )
            .unwrap();
        param
            .add(
                String::from("sibling"),
                Value::String(String::from("Futuna")),
            )
            .unwrap();

        let conn = Connection::open_in_memory().unwrap();
        prepare_connection(&conn).unwrap();

        let prep_mut = PrepareMutation {
            parameters: param,
            mutation: Arc::new(mutation),
        };

        let to_insert = prep_mut.read(&conn).unwrap();
        if let QueryResult::MutationQuery(mutation_query) = to_insert {
            let _js = mutation_query.to_json(&*prep_mut.mutation).unwrap();
            //println!("{}", serde_json::to_string_pretty(&js).unwrap());

            let insert_ent = &mutation_query.insert_enties[0];
            assert_eq!(5, insert_ent.edge_insertions.len());
            assert_eq!(3, insert_ent.sub_nodes.len());
        }
    }
}
