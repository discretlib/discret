use std::sync::Arc;

use crate::cryptography::base64_decode;

use super::{
    edge::Edge,
    node::Node,
    query_language::{deletion_parser::DeletionParser, parameter::Parameters},
    Result,
};

pub struct NodeDelete {
    id: Vec<u8>,
    name: String,
}

pub struct EdgeDelete {
    src: Vec<u8>,
    label: String,
    dest: Vec<u8>,
}

pub struct DeletionQuery {
    pub nodes: Vec<NodeDelete>,
    pub edges: Vec<EdgeDelete>,
}
impl DeletionQuery {
    pub fn build(
        parameters: &Parameters,
        deletion: Arc<DeletionParser>,
        _: &rusqlite::Connection,
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

            if del.references.is_empty() {
                deletion_query.nodes.push(NodeDelete {
                    id: src,
                    name: del.short_name.clone(),
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
            Node::delete(&nod.id, &nod.name, conn)?;
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
        let expected = "{\n\"Person\":[{\"name\":\"John\",\"parents\":[]}]\n}";
        assert_eq!(result, expected);

        //println!("{:#?}", result);
    }
}
