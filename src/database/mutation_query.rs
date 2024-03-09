use rusqlite::{Connection, OptionalExtension};

use crate::{
    cryptography::{base64_decode, base64_encode, now, SigningKey},
    database::configuration::ROOMS_FIELD,
};

use super::{
    configuration::{ID_FIELD, ROOMS_FIELD_SHORT},
    edge::Edge,
    node::Node,
    query_language::{
        mutation_parser::{EntityMutation, MutationField, MutationFieldValue, MutationParser},
        parameter::Parameters,
        FieldType,
    },
    sqlite_database::{RowMappingFn, Writeable},
    Error, Result,
};
use std::{
    collections::{HashMap, HashSet},
    sync::Arc,
};

#[derive(Debug)]
pub struct NodeToInsert {
    pub id: Vec<u8>,
    pub entity: String,
    pub node: Option<Node>,
    pub node_fts_str: Option<String>,
    pub old_node: Option<Node>,
    pub rooms: HashSet<Vec<u8>>,
    pub old_rowid: Option<i64>,
    pub old_fts_str: Option<String>,
    pub enable_archives: bool,
    pub enable_full_text: bool,
}
impl NodeToInsert {
    pub fn write(&self, conn: &Connection) -> std::result::Result<(), rusqlite::Error> {
        if let Some(node) = &self.node {
            // println!("{}", self.enable_full_text);
            node.write(
                conn,
                self.enable_full_text,
                &self.old_rowid,
                &self.old_fts_str,
                &self.node_fts_str,
            )?;
            //archive the old node
            if let Some(old_node) = &self.old_node {
                if self.enable_archives {
                    old_node.archive(conn)?;
                }
            }
        }
        Ok(())
    }

    pub fn sign(&mut self, signing_key: &impl SigningKey) -> std::result::Result<(), Error> {
        if let Some(node) = &mut self.node {
            node.sign(signing_key)?;
        }
        Ok(())
    }

    const NODE_INSERT_QUERY: &'static str = "SELECT id, cdate, mdate, _entity, _json, _binary, _verifying_key, _signature, rowid FROM _node WHERE id=? AND _entity=?";
    const NODE_INSERT_MAPPING: RowMappingFn<Self> = |row| {
        Ok(Box::new(NodeToInsert {
            id: row.get(0)?,
            entity: "".to_string(),
            node_fts_str: None,
            node: None,
            old_fts_str: None,
            rooms: HashSet::new(),
            enable_archives: true,
            enable_full_text: true,
            old_rowid: row.get(8)?,
            old_node: Some(Node {
                id: row.get(0)?,
                cdate: row.get(1)?,
                mdate: row.get(2)?,
                _entity: row.get(3)?,
                _json: row.get(4)?,
                _binary: row.get(5)?,
                _verifying_key: row.get(6)?,
                _signature: row.get(7)?,
            }),
        }))
    };
}
impl Default for NodeToInsert {
    fn default() -> Self {
        Self {
            id: Vec::new(),
            entity: "".to_string(),
            old_rowid: None,
            old_fts_str: None,
            node_fts_str: None,
            node: None,
            old_node: None,
            rooms: HashSet::new(),
            enable_archives: true,
            enable_full_text: true,
        }
    }
}

#[derive(Debug)]
pub struct MutationQuery {
    pub insert_entities: Vec<InsertEntity>,
}
impl Writeable for MutationQuery {
    fn write(&self, conn: &Connection) -> std::result::Result<(), rusqlite::Error> {
        for insert in &self.insert_entities {
            insert.write(conn)?;
        }
        Ok(())
    }
}
impl MutationQuery {
    pub fn build(
        parameters: &Parameters,
        mutation: Arc<MutationParser>,
        conn: &rusqlite::Connection,
    ) -> Result<MutationQuery> {
        mutation.variables.validate_params(parameters)?;
        let mut insert_queries = vec![];
        for entity in &mutation.mutations {
            let query = Self::get_insert_query(entity, parameters, conn)?;
            insert_queries.push(query);
        }
        let query = MutationQuery {
            insert_entities: insert_queries,
        };

        Ok(query)
    }
    fn retrieve_id(id_field: &MutationField, parameters: &Parameters) -> Result<Option<Vec<u8>>> {
        Ok(match &id_field.field_value {
            MutationFieldValue::Variable(var) => {
                let value = parameters.params.get(var).unwrap();

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

    fn get_insert_query(
        entity: &EntityMutation,
        parameters: &Parameters,
        conn: &Connection,
    ) -> Result<InsertEntity> {
        let mut query = InsertEntity {
            name: entity.aliased_name(),
            ..Default::default()
        };

        let mut node_insert = Self::create_node_to_insert(entity, parameters, conn)?;
        let mut json = if let Some(old_node) = &mut node_insert.old_node {
            match &old_node._json {
                Some(e) => {
                    let val = serde_json::from_str(e)?;
                    let mut previous = String::new();
                    extract_json(&val, &mut previous)?;
                    if !previous.is_empty() {
                        node_insert.old_fts_str = Some(previous);
                    }

                    val
                }
                None => serde_json::Value::Object(serde_json::Map::new()),
            }
        } else {
            serde_json::Value::Object(serde_json::Map::new())
        };

        {
            //bracket is needed to clean the mut reference on the json variable before inserting it in the node
            let obj = match json.as_object_mut() {
                Some(e) => e,
                None => return Err(Error::InvalidJsonObject(json.to_string())),
            };

            let mut node_updated = false;
            for field_entry in &entity.fields {
                let field = field_entry.1;
                if !field.name.eq(ID_FIELD) {
                    match &field.field_type {
                        FieldType::Array(_) => match &field.field_value {
                            MutationFieldValue::Array(mutations) => {
                                let mut insert_queries = vec![];
                                for mutation in mutations {
                                    let insert_query =
                                        Self::get_insert_query(mutation, parameters, conn)?;

                                    let target_id = insert_query.node_insert.id.clone();

                                    if !Edge::exists(
                                        node_insert.id.clone(),
                                        field.short_name.to_string(),
                                        target_id.clone(),
                                        conn,
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
                                    if field.name.eq(ROOMS_FIELD) {
                                        node_insert
                                            .rooms
                                            .insert(insert_query.node_insert.id.clone());
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
                                let insert_query =
                                    Self::get_insert_query(mutation, parameters, conn)?;

                                let target_id = insert_query.node_insert.id.clone();
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
                                    let value = parameters.params.get(v).unwrap();
                                    value.as_serde_json_value()?
                                }
                                MutationFieldValue::Value(v) => v.as_serde_json_value()?,
                                _ => unreachable!(),
                            };
                            obj.insert(String::from(&field.short_name), value);

                            node_updated = true;
                        }
                        FieldType::Json => {
                            let value = match &field.field_value {
                                MutationFieldValue::Variable(v) => {
                                    let value = parameters.params.get(v).unwrap();

                                    serde_json::from_str(value.as_string().unwrap())?
                                }
                                MutationFieldValue::Value(v) => {
                                    serde_json::from_str(v.as_string().unwrap())?
                                }
                                _ => unreachable!(),
                            };
                            obj.insert(String::from(&field.short_name), value);
                            node_updated = true;
                        }
                    }
                }
            }
            if !node_updated {
                node_insert.node = None;
            } else if let Some(node) = &mut node_insert.node {
                let json_data = serde_json::to_string(&json)?;
                node._json = Some(json_data);
                node.mdate = now();
                let mut current = String::new();
                extract_json(&json, &mut current)?;
                node_insert.node_fts_str = Some(current);
            }
        }
        query.node_insert = node_insert;
        Ok(query)
    }

    fn create_node_to_insert(
        entity: &EntityMutation,
        parameters: &Parameters,
        conn: &Connection,
    ) -> Result<NodeToInsert> {
        let entity_name = &entity.name;
        let entity_short = &entity.short_name;

        match entity.fields.get(ID_FIELD) {
            Some(id_field) => {
                let id: Vec<u8> = Self::retrieve_id(id_field, parameters)?.unwrap();
                if entity.fields.len() == 1 {
                    if Node::exist(&id, entity_short, conn)? {
                        Ok(NodeToInsert {
                            id,
                            entity: entity_name.clone(),
                            enable_archives: entity.enable_archives,
                            enable_full_text: entity.enable_full_text,
                            ..Default::default()
                        })
                    } else {
                        Err(Error::UnknownEntity(
                            String::from(entity_name),
                            base64_encode(&id),
                        ))
                    }
                } else {
                    let mut stmt = conn.prepare(NodeToInsert::NODE_INSERT_QUERY)?;
                    let results = stmt
                        .query_row((&id, entity_short), NodeToInsert::NODE_INSERT_MAPPING)
                        .optional()?;
                    let mut node: NodeToInsert = match results {
                        Some(mut node) => {
                            let rooms_query = format!(
                                "SELECT dest FROM _edge WHERE src=? AND label='{}'",
                                ROOMS_FIELD_SHORT
                            );
                            let mut rooms_stmt = conn.prepare_cached(&rooms_query)?;
                            let par = base64_encode(&node.id);
                            let mut rows = rooms_stmt.query([par])?;
                            let mut rooms = HashSet::new();
                            while let Some(row) = rows.next()? {
                                rooms.insert(row.get(0)?);
                            }
                            node.node = node.old_node.clone();
                            node.rooms = rooms;
                            *node
                        }
                        None => {
                            return Err(Error::UnknownEntity(
                                String::from(entity_name),
                                base64_encode(&id),
                            ))
                        }
                    };
                    node.entity = entity_name.clone();
                    node.enable_archives = entity.enable_archives;
                    node.enable_full_text = entity.enable_full_text;
                    Ok(node)
                }
            }
            None => {
                let node = Node {
                    _entity: String::from(entity_short),
                    ..Default::default()
                };
                Ok(NodeToInsert {
                    id: node.id.clone(),
                    entity: entity_name.clone(),
                    enable_archives: entity.enable_archives,
                    enable_full_text: entity.enable_full_text,
                    node: Some(node),
                    ..Default::default()
                })
            }
        }
    }

    pub fn to_json(&self, mutation: &MutationParser) -> Result<serde_json::Value> {
        let mutas = &mutation.mutations;
        let inserts = &self.insert_entities;

        if mutas.len() != inserts.len() {
            return Err(Error::Query(String::from(
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

    pub fn sign_all(&mut self, signing_key: &impl SigningKey) -> Result<()> {
        for insert in &mut self.insert_entities {
            insert.sign_all(signing_key)?;
        }
        Ok(())
    }
}

#[derive(Debug)]
pub struct InsertEntity {
    pub name: String,
    pub node_insert: NodeToInsert,
    pub edge_deletions: Vec<Edge>,
    pub edge_insertions: Vec<Edge>,
    pub sub_nodes: HashMap<String, Vec<InsertEntity>>,
}
impl InsertEntity {
    fn write(&self, conn: &Connection) -> std::result::Result<(), rusqlite::Error> {
        for query in &self.sub_nodes {
            for insert in query.1 {
                insert.write(conn)?;
            }
        }
        self.node_insert.write(conn)?;

        for edge in &self.edge_deletions {
            edge.delete(conn)?
        }
        for edge in &self.edge_insertions {
            edge.write(conn)?;
        }

        Ok(())
    }

    pub fn sign_all(&mut self, signing_key: &impl SigningKey) -> Result<()> {
        for query in &mut self.sub_nodes {
            for insert in query.1 {
                insert.sign_all(signing_key)?;
            }
        }

        self.node_insert.sign(signing_key)?;

        for edge in &mut self.edge_insertions {
            edge.sign(signing_key)?;
        }

        Ok(())
    }

    pub fn to_json(&self, mutation: &EntityMutation) -> Result<serde_json::Value> {
        let mut map: serde_json::Map<String, serde_json::Value> = serde_json::Map::new();
        Self::fill_json(self, mutation, &mut map)?;

        let mut final_map: serde_json::Map<String, serde_json::Value> = serde_json::Map::new();
        final_map.insert(String::from(&self.name), serde_json::Value::Object(map));

        Ok(serde_json::Value::Object(final_map))
    }

    fn fill_json(
        query: &Self,
        mutation: &EntityMutation,
        json_map: &mut serde_json::Map<String, serde_json::Value>,
    ) -> Result<()> {
        let node = &query.node_insert;

        json_map.insert(
            String::from(ID_FIELD),
            serde_json::Value::String(base64_encode(&node.id)),
        );
        if let Some(node) = &node.node {
            if let Some(json_string) = &node._json {
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
                            return Err(Error::Query(String::from(
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
                            return Err(Error::Query(String::from(
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
            node_insert: NodeToInsert {
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
            buff.push_str(v);
            buff.push(' ');
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

#[cfg(test)]
mod tests {

    use std::{
        fs,
        path::{Path, PathBuf},
    };

    use rusqlite::Connection;

    use crate::database::{
        query::{PreparedQueries, Query},
        query_language::{
            data_model_parser::DataModel, parameter::ParametersAdd, query_parser::QueryParser,
        },
        sqlite_database::prepare_connection,
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
        let mut data_model = DataModel::new();
        data_model
            .update(
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
        param.add("name", String::from("John")).unwrap();
        param.add("age", 100).unwrap();
        param.add("weight", 42.2).unwrap();
        param.add("human", true).unwrap();
        param.add_null("null").unwrap();

        let conn = Connection::open_in_memory().unwrap();
        prepare_connection(&conn).unwrap();

        let mutation = Arc::new(mutation);
        let mutation_query = MutationQuery::build(&param, mutation.clone(), &conn).unwrap();

        let _js = mutation_query.to_json(&*mutation).unwrap();
        assert_eq!(1, mutation_query.insert_entities.len());
    }

    #[test]
    fn prepare_double_mutation() {
        let mut data_model = DataModel::new();
        data_model
            .update(
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
        param.add("name", String::from("John")).unwrap();

        let conn = Connection::open_in_memory().unwrap();
        prepare_connection(&conn).unwrap();

        let mutation = Arc::new(mutation);
        let mutation_query = MutationQuery::build(&param, mutation.clone(), &conn).unwrap();

        let js = mutation_query.to_json(&*mutation).unwrap();
        println!("{}", serde_json::to_string_pretty(&js).unwrap());
        assert_eq!(2, mutation_query.insert_entities.len());
        // let insert_ent = mutation_query.insert_enties[0];

        //println!("{:#?}", mutation_query);
    }

    #[test]
    fn prepare_sub_entities() {
        let mut data_model = DataModel::new();
        data_model
            .update(
                "
            Person {
                name : String ,
                parents : [Person] ,
                pet: Pet ,
                siblings : [Person] 
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
        param.add("name", String::from("John")).unwrap();
        param.add("mother", String::from("Hello")).unwrap();
        param.add("father", String::from("World")).unwrap();
        param.add("pet_name", String::from("Truffle")).unwrap();
        param.add("sibling", String::from("Futuna")).unwrap();

        let conn = Connection::open_in_memory().unwrap();
        prepare_connection(&conn).unwrap();

        let mutation = Arc::new(mutation);
        let mutation_query = MutationQuery::build(&param, mutation.clone(), &conn).unwrap();

        let _js = mutation_query.to_json(&*mutation).unwrap();
        //println!("{}", serde_json::to_string_pretty(&js).unwrap());

        let insert_ent = &mutation_query.insert_entities[0];
        assert_eq!(5, insert_ent.edge_insertions.len());
        assert_eq!(3, insert_ent.sub_nodes.len());
    }

    #[test]
    fn update_sub_entity() {
        let mut data_model = DataModel::new();
        data_model
            .update(
                "
            Person {
                name : String ,
                pet: [Pet] ,
            }

            Pet {
                name : String,
                age: Integer
            }
        ",
            )
            .unwrap();

        let mutation = MutationParser::parse(
            r#"
            mutation mutmut {
                Person {
                    name : "Me"
                    pet: [  
                        {name:"kiki" age:12} 
                    ]
                }
            } "#,
            &data_model,
        )
        .unwrap();

        let param = Parameters::new();
        let conn = Connection::open_in_memory().unwrap();
        prepare_connection(&conn).unwrap();

        let mutation = Arc::new(mutation);
        let mutation_query = MutationQuery::build(&param, mutation, &conn).unwrap();

        mutation_query.write(&conn).unwrap();

        let insert_entity = &mutation_query.insert_entities[0];

        let person_id = base64_encode(&insert_entity.node_insert.id);
        //println!("{}", person_id);
        let pet_id = base64_encode(
            &insert_entity.sub_nodes.get("pet").unwrap()[0]
                .node_insert
                .id,
        );
        // println!("{}", pet_id);

        let mut param = Parameters::new();
        param.add("person_id", person_id).unwrap();
        param.add("pet_id", pet_id).unwrap();

        let mutation = MutationParser::parse(
            r#"
            mutation mutmut {
                Person {
                    id:$person_id
                    pet: [  
                        {
                            id:$pet_id
                            name:"koko"
                        } 
                    ]
                }
            } "#,
            &data_model,
        )
        .unwrap();

        let mutation = Arc::new(mutation);
        let mutation_query = MutationQuery::build(&param, mutation, &conn).unwrap();
        //  println!("{:#?}", mutation_query);
        mutation_query.write(&conn).unwrap();

        let query_parser = QueryParser::parse(
            r#"
            query sample{
                Person (
                        name = "Me",
                    ) {
                    name
                    pet {name age}
                }                
            }
        "#,
            &data_model,
        )
        .unwrap();

        let query = PreparedQueries::build(&query_parser).unwrap();
        let param = Parameters::new();
        let sql = Query {
            parameters: param,
            parser: Arc::new(query_parser),
            sql_queries: Arc::new(query),
        };
        // println!("{}", sql.sql_queries.sql_queries[0].sql_query);

        let result = sql.read(&conn).unwrap();
        let expected =
            "{\n\"Person\":[{\"name\":\"Me\",\"pet\":[{\"name\":\"koko\",\"age\":12}]}]\n}";
        assert_eq!(expected, result);

        //println!("{:#?}", result);
    }
}
