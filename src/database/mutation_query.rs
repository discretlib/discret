use rusqlite::Connection;

use crate::{
    date_utils::now,
    security::{base64_decode, base64_encode, default_uid, uid_from, SigningKey, Uid},
};

use super::{
    daily_log::DailyMutations,
    edge::{Edge, EdgeDeletionEntry},
    node::{extract_json, Node},
    query_language::{
        mutation_parser::{EntityMutation, MutationField, MutationFieldValue, MutationParser},
        parameter::Parameters,
        FieldType,
    },
    sqlite_database::Writeable,
    system_entities::{ID_FIELD, ROOM_ID_FIELD},
    Error, Result,
};
use std::{collections::HashMap, sync::Arc};

#[derive(Debug)]
pub struct NodeToMutate {
    pub id: Uid,
    pub date: i64,
    pub entity: String,
    pub room_id: Option<Uid>,
    pub node: Option<Node>,
    pub node_fts_str: Option<String>,
    pub old_node: Option<Node>,
    pub old_fts_str: Option<String>,
    pub enable_full_text: bool,
}
impl NodeToMutate {
    pub fn write(&mut self, conn: &Connection) -> std::result::Result<(), rusqlite::Error> {
        if let Some(node) = &mut self.node {
            node.write(
                conn,
                self.enable_full_text,
                &self.old_fts_str,
                &self.node_fts_str,
            )?;
        }
        Ok(())
    }

    pub fn sign(&mut self, signing_key: &impl SigningKey) -> std::result::Result<(), Error> {
        if let Some(node) = &mut self.node {
            node.sign(signing_key)?;
        }
        Ok(())
    }
}
impl Default for NodeToMutate {
    fn default() -> Self {
        Self {
            id: default_uid(),
            room_id: None,
            entity: "".to_string(),
            date: now(),
            old_fts_str: None,
            node_fts_str: None,
            node: None,
            old_node: None,
            enable_full_text: true,
        }
    }
}

#[derive(Debug)]
pub struct MutationQuery {
    pub mutate_entities: Vec<InsertEntity>,
    pub mutation_parser: Arc<MutationParser>,
    pub date: i64,
}
impl Writeable for MutationQuery {
    fn write(&mut self, conn: &Connection) -> std::result::Result<(), rusqlite::Error> {
        for insert in &mut self.mutate_entities {
            insert.write(conn)?;
        }
        Ok(())
    }
}
impl MutationQuery {
    pub fn update_daily_logs(&self, daily_log: &mut DailyMutations) {
        for insert in &self.mutate_entities {
            insert.update_daily_logs(daily_log);
        }
    }

    pub fn execute(
        parameters: &mut Parameters,
        mutation_parser: Arc<MutationParser>,
        conn: &rusqlite::Connection,
    ) -> Result<MutationQuery> {
        mutation_parser.variables.validate_params(parameters)?;
        let mut mutate_queries = vec![];

        //make sure that everything is mutated at the same exact date
        let date = now();
        for entity in &mutation_parser.mutations {
            let query = Self::get_mutate_query(entity, parameters, conn, date)?;
            mutate_queries.push(query);
        }
        let query = MutationQuery {
            date,
            mutate_entities: mutate_queries,
            mutation_parser,
        };

        Ok(query)
    }
    fn base64_field(id_field: &MutationField, parameters: &Parameters) -> Result<Option<Vec<u8>>> {
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

    fn get_mutate_query(
        entity: &EntityMutation,
        parameters: &Parameters,
        conn: &Connection,
        date: i64,
    ) -> Result<InsertEntity> {
        let mut query = InsertEntity {
            name: entity.aliased_name(),
            ..Default::default()
        };

        let mut node_to_mutate = Self::create_node_to_mutate(entity, parameters, conn, date)?;

        let mut json = if let Some(old_node) = &mut node_to_mutate.old_node {
            match &old_node._json {
                Some(e) => {
                    let val = serde_json::from_str(e)?;
                    let mut previous = String::new();
                    extract_json(&val, &mut previous)?;
                    if !previous.is_empty() {
                        node_to_mutate.old_fts_str = Some(previous);
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

            let mut is_update = false;
            let mut field_updated = false;
            for field_entry in &entity.fields {
                let field: &MutationField = field_entry.1;
                if field.name.eq(ID_FIELD) {
                    is_update = true;
                }
                if !field.name.eq(ID_FIELD) && !field.name.eq(ROOM_ID_FIELD) {
                    match &field.field_type {
                        FieldType::Array(_) => match &field.field_value {
                            MutationFieldValue::Array(mutations) => {
                                let mut insert_queries = vec![];
                                for mutation in mutations {
                                    let insert_query =
                                        Self::get_mutate_query(mutation, parameters, conn, date)?;

                                    let target_id = insert_query.node_to_mutate.id;

                                    if !Edge::exists(
                                        node_to_mutate.id,
                                        field.short_name.to_string(),
                                        target_id,
                                        conn,
                                    )? {
                                        let edge = Edge {
                                            src: node_to_mutate.id,
                                            src_entity: entity.short_name.clone(),
                                            label: field.short_name.to_string(),
                                            dest: target_id,
                                            cdate: node_to_mutate.date,
                                            ..Default::default()
                                        };
                                        query.edge_insertions.push(edge);
                                        field_updated = true;
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
                                    Edge::get_edges(&node_to_mutate.id, &field.short_name, conn)?;
                                for e in edges {
                                    query.edge_deletions.push(e);
                                    field_updated = true;
                                }
                            }
                            _ => unreachable!(),
                        },
                        FieldType::Entity(_) => match &field.field_value {
                            MutationFieldValue::Entity(mutation) => {
                                let insert_query =
                                    Self::get_mutate_query(mutation, parameters, conn, date)?;

                                let target_id = insert_query.node_to_mutate.id;
                                if !Edge::exists(
                                    node_to_mutate.id,
                                    field.short_name.to_string(),
                                    target_id,
                                    conn,
                                )? {
                                    let edges = Edge::get_edges(
                                        &node_to_mutate.id,
                                        &field.short_name,
                                        conn,
                                    )?;
                                    for e in edges {
                                        query.edge_deletions.push(e);
                                    }
                                    let edge = Edge {
                                        src: node_to_mutate.id,
                                        src_entity: entity.short_name.clone(),
                                        label: field.short_name.to_string(),
                                        dest: target_id,
                                        cdate: node_to_mutate.date,
                                        ..Default::default()
                                    };
                                    query.edge_insertions.push(edge);
                                    field_updated = true;
                                }

                                query
                                    .sub_nodes
                                    .insert(String::from(&field.name), vec![insert_query]);
                            }
                            MutationFieldValue::Value(_) => {
                                //always a null value
                                let edges =
                                    Edge::get_edges(&node_to_mutate.id, &field.short_name, conn)?;
                                for e in edges {
                                    query.edge_deletions.push(e);
                                    field_updated = true;
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

                            field_updated = true;
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
                            field_updated = true;
                        }
                    }
                }
            }
            if is_update && !field_updated {
                //nothing changed, the node will not be updated
                node_to_mutate.node = None;
            } else if let Some(node) = &mut node_to_mutate.node {
                let json_data = serde_json::to_string(&json)?;
                node._json = Some(json_data);
                node.mdate = date;
                let mut current = String::new();
                extract_json(&json, &mut current)?;
                node_to_mutate.node_fts_str = Some(current);
            }
        }
        query.node_to_mutate = node_to_mutate;
        Ok(query)
    }

    fn create_node_to_mutate(
        entity: &EntityMutation,
        parameters: &Parameters,
        conn: &Connection,
        date: i64,
    ) -> Result<NodeToMutate> {
        let entity_name = &entity.name;
        let entity_short = &entity.short_name;

        let room_id = match entity.fields.get(ROOM_ID_FIELD) {
            Some(room_field) => {
                let id_s = Self::base64_field(room_field, parameters)?
                    .ok_or(Error::InvalidId(entity_name.clone()))?;
                Some(uid_from(id_s)?)
            }
            None => None,
        };

        let node_to_mutate = match entity.fields.get(ID_FIELD) {
            Some(id_field) => {
                let id_s = Self::base64_field(id_field, parameters)?
                    .ok_or(Error::InvalidId(entity_name.clone()))?;
                let id = uid_from(id_s)?;
                let mut node: NodeToMutate = match Node::get_with_entity(&id, entity_short, conn)? {
                    Some(old_node) => {
                        let node_room = if room_id.is_some() {
                            room_id
                        } else {
                            old_node.room_id
                        };
                        let mut new_node = *old_node.clone();
                        new_node.room_id = node_room.clone();
                        new_node.mdate = date;

                        NodeToMutate {
                            id: old_node.id,
                            date,
                            room_id: node_room.clone(),
                            node: Some(new_node),
                            old_node: Some(*old_node),
                            ..Default::default()
                        }
                    }
                    None => {
                        return Err(Error::UnknownEntity(
                            String::from(entity_name),
                            base64_encode(&id),
                        ))
                    }
                };

                node.entity = entity_name.clone();
                node.enable_full_text = entity.enable_full_text;
                node
            }
            None => {
                let node = Node {
                    room_id: room_id,
                    _entity: String::from(entity_short),
                    ..Default::default()
                };
                NodeToMutate {
                    id: node.id,
                    room_id: node.room_id,
                    entity: entity_name.clone(),
                    date,
                    enable_full_text: entity.enable_full_text,
                    node: Some(node),
                    ..Default::default()
                }
            }
        };

        Ok(node_to_mutate)
    }

    pub fn to_json(&self) -> Result<serde_json::Value> {
        let mutas = &self.mutation_parser.mutations;
        let inserts = &self.mutate_entities;

        if mutas.len() != inserts.len() {
            return Err(Error::Query(String::from(
                "mutate query and InsertEntity result lenght are not equal",
            )));
        }

        let mut map: serde_json::Map<String, serde_json::Value> = serde_json::Map::new();
        for i in 0..mutas.len() {
            let ent_mut = &mutas[i];
            let insert_entity = &inserts[i];
            insert_entity.to_json(ent_mut, &mut map)?;
        }

        Ok(serde_json::Value::Object(map))
    }

    pub fn result(&self) -> Result<String> {
        let mutas = &self.mutation_parser.mutations;
        let inserts = &self.mutate_entities;

        if mutas.len() != inserts.len() {
            return Err(Error::Query(String::from(
                "mutate query and InsertEntity result lenght are not equal",
            )));
        }

        let mut map: serde_json::Map<String, serde_json::Value> = serde_json::Map::new();

        for i in 0..mutas.len() {
            let ent_mut = &mutas[i];
            let insert_entity = &inserts[i];

            insert_entity.to_json(ent_mut, &mut map)?;
        }

        let json = serde_json::to_string_pretty(&serde_json::Value::Object(map))?;

        Ok(json)
    }

    pub fn sign_all(&mut self, signing_key: &impl SigningKey) -> Result<()> {
        for insert in &mut self.mutate_entities {
            insert.sign_all(signing_key)?;
        }
        Ok(())
    }
}

#[derive(Debug)]
pub struct InsertEntity {
    pub name: String,
    pub node_to_mutate: NodeToMutate,
    pub edge_deletions: Vec<Edge>,
    pub edge_deletions_log: Vec<EdgeDeletionEntry>,
    pub edge_insertions: Vec<Edge>,
    pub sub_nodes: HashMap<String, Vec<InsertEntity>>,
}
impl InsertEntity {
    fn write(&mut self, conn: &Connection) -> std::result::Result<(), rusqlite::Error> {
        self.node_to_mutate.write(conn)?;

        for edge in &self.edge_deletions {
            edge.delete(conn)?
        }
        for edge_log in &mut self.edge_deletions_log {
            edge_log.write(conn)?
        }
        for edge in &self.edge_insertions {
            edge.write(conn)?;
        }
        for query in &mut self.sub_nodes {
            for insert in query.1 {
                insert.write(conn)?;
            }
        }

        Ok(())
    }

    pub fn update_daily_logs(&self, daily_log: &mut DailyMutations) {
        for query in &self.sub_nodes {
            for insert in query.1 {
                insert.update_daily_logs(daily_log);
            }
        }

        if let Some(room_id) = &self.node_to_mutate.room_id {
            if let Some(node) = &self.node_to_mutate.node {
                daily_log.set_need_update(room_id.clone(), &node._entity, self.node_to_mutate.date);
            }

            if let Some(node) = &self.node_to_mutate.old_node {
                if let Some(room_id) = &node.room_id {
                    daily_log.set_need_update(room_id.clone(), &node._entity, node.mdate);
                }
            }
        }

        for edg in &self.edge_deletions_log {
            daily_log.set_need_update(edg.room_id, &edg.src_entity, edg.deletion_date);
        }
    }

    pub fn sign_all(&mut self, signing_key: &impl SigningKey) -> Result<()> {
        for query in &mut self.sub_nodes {
            for insert in query.1 {
                insert.sign_all(signing_key)?;
            }
        }

        self.node_to_mutate.sign(signing_key)?;

        for edge in &mut self.edge_insertions {
            edge.sign(signing_key)?;
        }

        Ok(())
    }

    pub fn to_json(
        &self,
        mutation: &EntityMutation,
        map: &mut serde_json::Map<String, serde_json::Value>,
    ) -> Result<()> {
        let mut internal: serde_json::Map<String, serde_json::Value> = serde_json::Map::new();
        Self::fill_json(self, mutation, &mut internal)?;

        map.insert(
            String::from(&self.name),
            serde_json::Value::Object(internal),
        );
        Ok(())
    }

    fn fill_json(
        query: &Self,
        mutation: &EntityMutation,
        json_map: &mut serde_json::Map<String, serde_json::Value>,
    ) -> Result<()> {
        let node = &query.node_to_mutate;

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
                        for (i, mutation) in mutations.iter().enumerate() {
                            let mut sub_map: serde_json::Map<String, serde_json::Value> =
                                serde_json::Map::new();
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
            node_to_mutate: NodeToMutate {
                ..Default::default()
            },
            edge_deletions: Vec::new(),
            edge_deletions_log: Vec::new(),
            edge_insertions: Vec::new(),
            sub_nodes: HashMap::new(),
        }
    }
}

#[cfg(test)]
mod tests {

    use rusqlite::Connection;
    use serde::{Deserialize, Serialize};

    use crate::database::{
        query::{PreparedQueries, Query},
        query_language::{
            data_model_parser::DataModel, parameter::ParametersAdd, query_parser::QueryParser,
        },
        sqlite_database::prepare_connection,
    };

    use super::*;

    #[test]
    fn prepare_simple_scalar() {
        let mut data_model = DataModel::new();
        data_model
            .update(
                "
            ns {
                Person {
                    name : String ,
                    age : Integer,
                    weight : Float,
                    is_human : Boolean, 
                    some_nullable : String nullable,
                    some_default : Integer default 2 
                }
            }
        ",
            )
            .unwrap();

        let mutation = MutationParser::parse(
            r#"
            mutate {
                ns.Person {
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
        let mutation_query = MutationQuery::execute(&mut param, mutation.clone(), &conn).unwrap();

        let _js = mutation_query.to_json().unwrap();
        assert_eq!(1, mutation_query.mutate_entities.len());
    }

    #[test]
    fn prepare_double_mutation() {
        let mut data_model = DataModel::new();
        data_model
            .update(
                "
            {
                Person {
                    name : String ,
                }
            }",
            )
            .unwrap();

        let mutation = MutationParser::parse(
            r#"
            mutate {
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
        let mutation_query = MutationQuery::execute(&mut param, mutation.clone(), &conn).unwrap();

        let _js = mutation_query.to_json().unwrap();
        assert_eq!(2, mutation_query.mutate_entities.len());
    }

    #[test]
    fn prepare_double_mutation_namespace() {
        let mut data_model = DataModel::new();
        data_model
            .update(
                "
            ns {
                Person {
                    name : String ,
                }
            }",
            )
            .unwrap();

        let mutation = MutationParser::parse(
            r#"
            mutate {
                ns.Person {
                    name : $name
                }
                second : ns.Person {
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
        let mutation_query = MutationQuery::execute(&mut param, mutation.clone(), &conn).unwrap();

        let _js = mutation_query.to_json().unwrap();

        assert_eq!(2, mutation_query.mutate_entities.len());
    }

    #[test]
    fn prepare_sub_entities() {
        let mut data_model = DataModel::new();
        data_model
            .update(
                "
            {
                Person {
                    name : String ,
                    parents : [Person] ,
                    pet: Pet ,
                    siblings : [Person] 
                }

                Pet {
                    name : String
                }
            }",
            )
            .unwrap();

        let mutation = MutationParser::parse(
            r#"
            mutate {
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
        let mutation_query = MutationQuery::execute(&mut param, mutation.clone(), &conn).unwrap();

        let _js = mutation_query.to_json().unwrap();

        let insert_ent = &mutation_query.mutate_entities[0];
        assert_eq!(5, insert_ent.edge_insertions.len());
        assert_eq!(3, insert_ent.sub_nodes.len());
    }

    #[test]
    fn update_sub_entity() {
        let mut data_model = DataModel::new();
        data_model
            .update(
                "
            {
                Person {
                    name : String ,
                    pet: [Pet] ,
                }

                Pet {
                    name : String,
                    age: Integer
                }
            }",
            )
            .unwrap();

        let mutation = MutationParser::parse(
            r#"
            mutate {
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

        let mut param = Parameters::new();
        let conn = Connection::open_in_memory().unwrap();
        prepare_connection(&conn).unwrap();

        let mutation = Arc::new(mutation);
        let mut mutation_query = MutationQuery::execute(&mut param, mutation, &conn).unwrap();
        mutation_query.write(&conn).unwrap();

        let insert_entity = &mutation_query.mutate_entities[0];

        let person_id = base64_encode(&insert_entity.node_to_mutate.id);

        let pet_id = base64_encode(
            &insert_entity.sub_nodes.get("pet").unwrap()[0]
                .node_to_mutate
                .id,
        );

        let mut param = Parameters::new();
        param.add("person_id", person_id).unwrap();
        param.add("pet_id", pet_id).unwrap();

        let mutation = MutationParser::parse(
            r#"
            mutate {
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
        let mut mutation_query = MutationQuery::execute(&mut param, mutation, &conn).unwrap();

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
        let mut sql = Query {
            parameters: param,
            parser: Arc::new(query_parser),
            sql_queries: Arc::new(query),
        };

        let result = sql.read(&conn).unwrap();
        let expected =
            "{\n\"Person\":[{\"name\":\"Me\",\"pet\":[{\"name\":\"koko\",\"age\":12}]}]\n}";
        assert_eq!(expected, result);
    }

    #[test]
    fn modication_dates_for_edge_update() {
        let mut data_model = DataModel::new();
        data_model
            .update(
                "
            {
                Person {
                    name : String ,
                    pet: [Pet] ,
                }

                Pet {
                    name : String,
                    age: Integer,
                    shelter : Shelter,
                    previous: [Shelter]
                }

                Shelter{
                    name : String,
                }
            }
        ",
            )
            .unwrap();

        let mutation = MutationParser::parse(
            r#"
            mutate {
                Person {
                    name : "Me"
                    pet: [  
                        {
                            name:"kiki" 
                            age:12
                            shelter:{
                                name: "one"
                            }
                            previous:[{
                                name: "two"
                            }]
                        } 
                    ]
                }
            } "#,
            &data_model,
        )
        .unwrap();

        let mut param = Parameters::new();
        let conn = Connection::open_in_memory().unwrap();
        prepare_connection(&conn).unwrap();

        let mutation = Arc::new(mutation);
        let mut mutation_query = MutationQuery::execute(&mut param, mutation, &conn).unwrap();
        mutation_query.write(&conn).unwrap();

        #[derive(Serialize, Deserialize)]
        struct Shelter {
            id: String,
            mdate: i64,
            name: String,
        }

        #[derive(Serialize, Deserialize)]
        struct Pet {
            id: String,
            mdate: i64,
            name: String,
            shelter: Shelter,
            previous: Vec<Shelter>,
        }

        #[derive(Serialize, Deserialize)]
        struct Person {
            id: String,
            mdate: i64,
            name: String,
            pet: Vec<Pet>,
        }
        #[derive(Serialize, Deserialize)]
        struct Result {
            person: Vec<Person>,
        }

        let query_parser = QueryParser::parse(
            r#"
            query sample{
                person : Person  {
                    id
                    mdate
                    name
                    pet {
                        id
                        mdate
                        name
                        shelter {
                            id
                            mdate
                            name
                        }
                        previous {
                            id
                            mdate
                            name
                        }
                    }
                }                
            }
        "#,
            &data_model,
        )
        .unwrap();

        let query = PreparedQueries::build(&query_parser).unwrap();
        let sql_queries = Arc::new(query);
        let parser = Arc::new(query_parser);

        let param = Parameters::new();
        let mut sql = Query {
            parameters: param,
            parser: parser.clone(),
            sql_queries: sql_queries.clone(),
        };

        let result_str = sql.read(&conn).unwrap();
        let result: Result = serde_json::from_str(&result_str).unwrap();

        let person = &result.person[0];
        let pet = &person.pet[0];
        let shelter_one = &pet.shelter;
        let shelter_two = &pet.previous[0];

        let mut param = Parameters::new();
        param.add("person_id", person.id.clone()).unwrap();
        param.add("pet_id", pet.id.clone()).unwrap();
        param.add("shelter_id", shelter_one.id.clone()).unwrap();

        let mutation = MutationParser::parse(
            r#"
            mutate {
                Person {
                    id:$person_id
                    pet: [  
                        {
                            id:$pet_id
                            shelter: {
                                id:$shelter_id
                                name: "a better name"
                            }
                        } 
                    ]
                }
            } "#,
            &data_model,
        )
        .unwrap();

        use std::{thread, time};

        thread::sleep(time::Duration::from_millis(2));

        let mutation = Arc::new(mutation);
        let mut mutation_query = MutationQuery::execute(&mut param, mutation, &conn).unwrap();
        mutation_query.write(&conn).unwrap();

        let param = Parameters::new();
        let mut sql = Query {
            parameters: param,
            parser: parser.clone(),
            sql_queries: sql_queries.clone(),
        };

        let result_str = sql.read(&conn).unwrap();
        let result: Result = serde_json::from_str(&result_str).unwrap();

        let person2 = &result.person[0];
        let pet2 = &person2.pet[0];
        let shelter_one2 = &pet2.shelter;
        let shelter_two2 = &pet2.previous[0];

        assert_eq!(person.id, person2.id);
        assert_eq!(person.mdate, person2.mdate);

        assert_eq!(pet.id, pet2.id);
        assert_eq!(pet.mdate, pet2.mdate);

        assert_eq!(shelter_one.id, shelter_one2.id);

        assert_ne!(shelter_one.mdate, shelter_one2.mdate);

        assert_eq!(shelter_two.id, shelter_two2.id);
        assert_eq!(shelter_two.mdate, shelter_two2.mdate);

        let mut param = Parameters::new();
        param.add("person_id", person.id.clone()).unwrap();
        param.add("pet_id", pet.id.clone()).unwrap();

        let mutation = MutationParser::parse(
            r#"
            mutate {
                Person {
                    id:$person_id
                    pet: [  
                        {
                            id:$pet_id
                            shelter: {
                                name: "a new shelter"
                            }
                        } 
                    ]
                }
            } "#,
            &data_model,
        )
        .unwrap();

        thread::sleep(time::Duration::from_millis(2));

        let mutation = Arc::new(mutation);
        let mut mutation_query = MutationQuery::execute(&mut param, mutation, &conn).unwrap();
        mutation_query.write(&conn).unwrap();

        let param = Parameters::new();
        let mut sql = Query {
            parameters: param,
            parser: parser.clone(),
            sql_queries: sql_queries.clone(),
        };

        let result_str = sql.read(&conn).unwrap();

        let result: Result = serde_json::from_str(&result_str).unwrap();

        let person2 = &result.person[0];
        let pet2 = &person2.pet[0];
        let shelter_one2 = &pet2.shelter;
        let shelter_two2 = &pet2.previous[0];

        assert_eq!(person.id, person2.id);
        assert_eq!(person.mdate, person2.mdate);

        assert_eq!(pet.id, pet2.id);
        assert_ne!(pet.mdate, pet2.mdate);

        assert_ne!(shelter_one.id, shelter_one2.id);
        assert_ne!(shelter_one.mdate, shelter_one2.mdate);

        assert_eq!(shelter_two.id, shelter_two2.id);
        assert_eq!(shelter_two.mdate, shelter_two2.mdate);

        let mut param = Parameters::new();
        param.add("person_id", person.id.clone()).unwrap();
        param.add("pet_id", pet.id.clone()).unwrap();

        let mutation = MutationParser::parse(
            r#"
            mutate {
                Person {
                    id:$person_id
                    pet: [  
                        {
                            id:$pet_id
                            previous: [{
                                name: "a old shelter"
                            }]
                        } 
                    ]
                }
            } "#,
            &data_model,
        )
        .unwrap();

        thread::sleep(time::Duration::from_millis(2));

        let mutation = Arc::new(mutation);
        let mut mutation_query = MutationQuery::execute(&mut param, mutation, &conn).unwrap();
        mutation_query.write(&conn).unwrap();

        let param = Parameters::new();
        let mut sql = Query {
            parameters: param,
            parser: parser.clone(),
            sql_queries: sql_queries.clone(),
        };

        let result_str = sql.read(&conn).unwrap();
        let pet = pet2;
        let shelter_one = shelter_one2;

        let result: Result = serde_json::from_str(&result_str).unwrap();

        let person2 = &result.person[0];
        let pet2 = &person2.pet[0];
        let shelter_one2 = &pet2.shelter;

        assert_eq!(person.id, person2.id);
        assert_eq!(person.mdate, person2.mdate);

        assert_eq!(pet.id, pet2.id);
        assert_ne!(pet.mdate, pet2.mdate);

        assert_eq!(shelter_one.id, shelter_one2.id);
        assert_eq!(shelter_one.mdate, shelter_one2.mdate);

        assert_eq!(2, pet2.previous.len());
    }
}
