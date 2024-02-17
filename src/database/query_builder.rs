use rusqlite::OptionalExtension;
use serde_json::{json, Value};

use crate::{base64_decode, base64_encode};

use super::{
    edge::Edge,
    graph_database::{now, FromRow, InsertQuery, Readable, StatementResult},
    node::Node,
    query_language::{
        data_model::ID_FIELD, mutation::Mutation, parameter::Parameters, FieldType, FieldValue,
    },
    Error, Result,
};
use std::sync::Arc;

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

const LOCAL_NODE_QUERY: &'static str = "SELECT id, cdate, mdate, _entity, _json_data, _binary_data, _pub_key, _signature, rowid FROM _node WHERE id=? AND _entity=?";
impl FromRow for InsertQuery {
    fn from_row() -> super::graph_database::MappingFn<Self> {
        |row| {
            Ok(Box::new(InsertQuery {
                rowid: row.get(8)?,
                index: true,
                previous_fts_str: None,
                current_fts_str: None,
                node: Node {
                    id: row.get(0)?,
                    cdate: row.get(1)?,
                    mdate: row.get(2)?,
                    _entity: row.get(3)?,
                    _json_data: row.get(4)?,
                    _binary_data: row.get(5)?,
                    _pub_key: row.get(6)?,
                    _signature: row.get(7)?,
                },
                edge_deletions: vec![],
                edge_insertion: vec![],
            }))
        }
    }
}

struct PrepareMutation {
    parameters: Parameters,
    mutation: Arc<Mutation>,
}
impl Readable for PrepareMutation {
    fn read(&self, conn: &rusqlite::Connection) -> Result<StatementResult> {
        self.mutation.variables.validate_params(&self.parameters)?;
        let mut insert_queries = vec![];
        for entity in &self.mutation.mutations {
            let entity_name = &entity.name;
            let id_field_opt = entity.fields.get(ID_FIELD);
            let mut query = match id_field_opt {
                Some(id_field) => {
                    let id = self.retrieve_id(id_field)?.unwrap();

                    let mut stmt = conn.prepare(LOCAL_NODE_QUERY)?;
                    let results = stmt
                        .query_row((&id, entity_name), InsertQuery::from_row())
                        .optional()?;
                    let mut node: InsertQuery = match results {
                        Some(node) => *node,
                        None => {
                            return Err(Error::InvalidMutationId(
                                String::from(entity_name),
                                base64_encode(&id),
                            ))
                        }
                    };

                    node.node.mdate = now();
                    node
                }
                None => {
                    let date = now();
                    let node = Node {
                        _entity: String::from(entity_name),
                        cdate: date,
                        mdate: date,
                        ..Default::default()
                    };
                    InsertQuery {
                        rowid: None,
                        index: true,
                        previous_fts_str: None,
                        current_fts_str: None,
                        node,
                        edge_deletions: vec![],
                        edge_insertion: vec![],
                    }
                }
            };

            let node = &mut query.node;
            let mut json: Value = match &node._json_data {
                Some(e) => serde_json::from_str(e)?,
                None => json!("{}"),
            };

            let mut previous = String::new();
            extract_json(&json, &mut previous)?;

            if previous.len() > 0 {
                query.previous_fts_str = Some(previous);
            }

            let obj = match json.as_object_mut() {
                Some(e) => e,
                None => return Err(Error::InvalidJsonObject(json.to_string())),
            };

            for field_entry in &entity.fields {
                let field = field_entry.1;
                if !field.name.eq(ID_FIELD) {
                    match &field.field_type {
                        FieldType::Array(target_entity) => {
                            let target_id = self.retrieve_id(field)?.unwrap();
                            if !Node::exist(&target_id, target_entity, conn)? {
                                return Err(Error::UnknownEntity(
                                    target_entity.to_string(),
                                    base64_encode(&target_id),
                                    entity_name.to_string(),
                                    field.name.to_string(),
                                ));
                            }
                            if !Edge::exists(
                                node.id.clone(),
                                field.name.to_string(),
                                target_id.clone(),
                                conn,
                            )? {
                                let edge = Edge {
                                    src: node.id.clone(),
                                    label: field.name.to_string(),
                                    dest: target_id,
                                    cdate: now(),
                                    ..Default::default()
                                };
                                query.edge_insertion.push(edge);
                            }
                        }
                        FieldType::Entity(target_entity) => {
                            let edges =
                                Edge::get_edges(node.id.clone(), field.name.to_string(), conn)?;
                            for e in edges {
                                query.edge_deletions.push(*e);
                            }

                            let target_id_opt = self.retrieve_id(field)?;
                            match target_id_opt {
                                Some(target_id) => {
                                    if !Node::exist(&target_id, target_entity, conn)? {
                                        return Err(Error::UnknownEntity(
                                            target_entity.to_string(),
                                            base64_encode(&target_id),
                                            entity_name.to_string(),
                                            field.name.to_string(),
                                        ));
                                    }
                                    let edge = Edge {
                                        src: node.id.clone(),
                                        label: field.name.to_string(),
                                        dest: target_id,
                                        cdate: now(),
                                        ..Default::default()
                                    };
                                    query.edge_insertion.push(edge);
                                }
                                None => todo!(),
                            }
                        }
                        FieldType::Boolean
                        | FieldType::Float
                        | FieldType::Base64
                        | FieldType::Integer
                        | FieldType::String => {
                            let value = match &field.field_value {
                                FieldValue::Variable(v) => {
                                    let value = self.parameters.params.get(v).unwrap();
                                    value.as_serde_json_value()?
                                }
                                FieldValue::Value(v) => v.as_serde_json_value()?,
                            };
                            obj.insert(String::from(&field.name), value);
                        }
                    }
                }
            }

            let json_data = serde_json::to_string(&json)?;

            node._json_data = Some(json_data);

            insert_queries.push(query);
        }
        Ok(StatementResult::InsertQuery(insert_queries))
    }
}

impl PrepareMutation {
    fn retrieve_id(
        &self,
        id_field: &super::query_language::mutation::MutationField,
    ) -> Result<Option<Vec<u8>>> {
        Ok(match &id_field.field_value {
            FieldValue::Variable(var) => {
                let value = self.parameters.params.get(var).unwrap();

                match value.as_string() {
                    Some(e) => Some(base64_decode(e.as_bytes())?),
                    None => None,
                }
            }
            FieldValue::Value(value) => match value.as_string() {
                Some(e) => Some(base64_decode(e.as_bytes())?),
                None => None,
            },
        })
    }
}
