use crate::cryptography::base64_decode;
use std::{collections::HashSet, sync::Arc};

use super::{
    configuration::ROOMS_FIELD_SHORT,
    edge::Edge,
    node::Node,
    query_language::{deletion_parser::DeletionParser, parameter::Parameters},
    Result,
};
#[derive(Debug)]
pub struct NodeDelete {
    pub id: Vec<u8>,
    pub name: String,
    pub short_name: String,
    pub rooms: HashSet<Vec<u8>>,
    pub verifying_key: Vec<u8>,
}
#[derive(Debug)]
pub struct EdgeDelete {
    pub src: Vec<u8>,
    pub label: String,
    pub dest: Vec<u8>,
    pub rooms: HashSet<Vec<u8>>,
    pub source_entity: String,
    pub verifying_key: Vec<u8>,
}
#[derive(Debug)]
pub struct DeletionQuery {
    pub nodes: Vec<NodeDelete>,
    pub edges: Vec<EdgeDelete>,
}
impl DeletionQuery {
    pub fn build(
        parameters: &Parameters,
        deletion: Arc<DeletionParser>,
        conn: &rusqlite::Connection,
    ) -> Result<Self> {
        deletion.variables.validate_params(parameters)?;
        let mut deletion_query = Self {
            nodes: Vec::new(),
            edges: Vec::new(),
        };
        for del in &deletion.deletions {
            let src = parameters
                .params
                .get(&del.id_param)
                .unwrap()
                .as_string()
                .unwrap();

            let src = base64_decode(src.as_bytes())?;
            let rooms_query = format!(
                "SELECT dest FROM _edge WHERE src=? AND label='{}'",
                ROOMS_FIELD_SHORT
            );
            let mut rooms_stmt = conn.prepare_cached(&rooms_query)?;
            let mut rows = rooms_stmt.query([&src])?;
            let mut rooms = HashSet::new();
            while let Some(row) = rows.next()? {
                rooms.insert(row.get(0)?);
            }

            let verifying_key_query =
                "SELECT _verifying_key FROM _node WHERE id = ? AND _entity = ?";
            let mut verifying_key_stmt = conn.prepare_cached(verifying_key_query)?;
            let verifying_key: Vec<u8> =
                verifying_key_stmt.query_row((&src, &del.short_name), |row| row.get(0))?;

            if del.references.is_empty() {
                deletion_query.nodes.push(NodeDelete {
                    id: src,
                    name: del.name.clone(),
                    short_name: del.short_name.clone(),
                    rooms: rooms.clone(),
                    verifying_key: verifying_key.clone(),
                })
            } else {
                for edge in &del.references {
                    let dest = parameters
                        .params
                        .get(&edge.dest_param)
                        .unwrap()
                        .as_string()
                        .unwrap();

                    let dest = base64_decode(dest.as_bytes())?;
                    deletion_query.edges.push(EdgeDelete {
                        src: src.clone(),
                        label: edge.label.clone(),
                        dest,
                        rooms: rooms.clone(),
                        source_entity: edge.entity_name.clone(),
                        verifying_key: verifying_key.clone(),
                    });
                }
            }
        }
        Ok(deletion_query)
    }

    pub fn delete(&self, conn: &rusqlite::Connection) -> std::result::Result<(), rusqlite::Error> {
        for edg in &self.edges {
            Edge::delete_edge(&edg.src, &edg.label, &edg.dest, conn)?;
        }
        for nod in &self.nodes {
            Node::delete(&nod.id, &nod.short_name, conn)?;
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {

    use crate::database::{
        mutation_query::MutationQuery,
        query::{PreparedQueries, Query},
        query_language::{
            data_model_parser::DataModel, mutation_parser::MutationParser,
            parameter::ParametersAdd, query_parser::QueryParser,
        },
        sqlite_database::{prepare_connection, Writeable},
    };
    use rusqlite::Connection;

    use super::*;
    #[test]
    fn delete_node() {
        let mut data_model = DataModel::new();
        data_model
            .update(
                "
            Person {
                name : String,
            }
        ",
            )
            .unwrap();

        let mutation = MutationParser::parse(
            r#"
            mutation mutmut {
                P1: Person { name:"John"  }
                P2: Person { name:"Alice"  }
                P3: Person { name:"Bob"  }
            } "#,
            &data_model,
        )
        .unwrap();
        let conn = Connection::open_in_memory().unwrap();
        prepare_connection(&conn).unwrap();

        let param = Parameters::new();
        let mutation = Arc::new(mutation);
        let mutation_query = MutationQuery::build(&param, mutation, &conn).unwrap();
        mutation_query.write(&conn).unwrap();

        let query_parser = QueryParser::parse(
            r#"
            query sample{
                Person {
                    id
                    name
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

        let result = sql.read(&conn).unwrap();
        let value: serde_json::Value = serde_json::from_str(&result).unwrap();
        let value = value.as_object().unwrap();
        let persons = value.get("Person").unwrap().as_array().unwrap();

        let mut param = Parameters::new();
        for i in 0..persons.len() {
            let pers = persons[i].as_object().unwrap();
            let id = pers.get("id").unwrap().as_str().unwrap();
            param.add(&format!("id{}", i), id.to_string()).unwrap();
        }

        let deletion = DeletionParser::parse(
            "
            deletion delete_person {
                Person { $id0 }
                Person { $id1 }
                Person { $id2 }
            }
          ",
            &data_model,
        )
        .unwrap();
        let deletion = Arc::new(deletion);

        let delete = DeletionQuery::build(&param, deletion, &conn).unwrap();
        delete.delete(&conn).unwrap();

        let query_parser = QueryParser::parse(
            r#"
            query sample{
                Person {
                    id
                    name
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

        let result = sql.read(&conn).unwrap();
        let expected = "{\n\"Person\":[]\n}";
        assert_eq!(result, expected);

        println!("{:#?}", result);
    }

    #[test]
    fn delete_edge() {
        let mut data_model = DataModel::new();
        data_model
            .update(
                "
            Person {
                name : String,
                parents : [Person]
            }
        ",
            )
            .unwrap();

        let mutation = MutationParser::parse(
            r#"
            mutation mutmut {
                Person { name:"John" parents:[{name:"Alice"},{name:"Bob"}]  }
            } "#,
            &data_model,
        )
        .unwrap();
        let conn = Connection::open_in_memory().unwrap();
        prepare_connection(&conn).unwrap();

        let param = Parameters::new();
        let mutation = Arc::new(mutation);
        let mutation_query = MutationQuery::build(&param, mutation, &conn).unwrap();
        mutation_query.write(&conn).unwrap();

        let query_parser = QueryParser::parse(
            r#"
            query sample{
                Person(name="John") {
                    id
                    parents{id name}
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

        let result = sql.read(&conn).unwrap();
        let value: serde_json::Value = serde_json::from_str(&result).unwrap();
        let value = value.as_object().unwrap();
        let persons = value.get("Person").unwrap().as_array().unwrap();

        let john = persons[0].as_object().unwrap();
        let src = john.get("id").unwrap().as_str().unwrap();

        let mut param = Parameters::new();
        param.add("src", src.to_string()).unwrap();

        let parents = john.get("parents").unwrap().as_array().unwrap();

        for i in 0..parents.len() {
            let pers = parents[i].as_object().unwrap();
            let id = pers.get("id").unwrap().as_str().unwrap();
            param.add(&format!("p{}", i), id.to_string()).unwrap();
        }

        let deletion = DeletionParser::parse(
            "
            deletion delete_person {
                Person { $src parents[$p0,$p1] }
            }
          ",
            &data_model,
        )
        .unwrap();
        let deletion = Arc::new(deletion);

        let delete = DeletionQuery::build(&param, deletion, &conn).unwrap();
        delete.delete(&conn).unwrap();

        let query_parser = QueryParser::parse(
            r#"
            query sample{
                Person(name="John") {
                    name
                    parents{name}
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

        let result = sql.read(&conn).unwrap();
        let expected = "{\n\"Person\":[]\n}";
        assert_eq!(result, expected);

        //println!("{:#?}", result);
    }
}
