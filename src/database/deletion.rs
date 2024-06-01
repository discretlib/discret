use crate::{
    date_utils::now,
    security::{uid_decode, Uid},
};
use std::sync::Arc;

use super::{
    daily_log::DailyMutations,
    edge::{Edge, EdgeDeletionEntry},
    node::{Node, NodeDeletionEntry},
    query_language::{deletion_parser::DeletionParser, parameter::Parameters},
    sqlite_database::Writeable,
    Result,
};
#[derive(Debug)]
pub struct NodeDelete {
    pub node: Node,
    pub name: String,
    pub short_name: String,
    pub date: i64,
}
#[derive(Debug)]
pub struct EdgeDelete {
    pub edge: Edge,
    pub src_name: String,
    pub room_id: Option<Uid>,
    pub date: i64,
}
#[derive(Debug)]
pub struct DeletionQuery {
    pub nodes: Vec<NodeDelete>,
    pub node_log: Vec<NodeDeletionEntry>,
    pub updated_nodes: Vec<Node>,
    pub edges: Vec<EdgeDelete>,
    pub edge_log: Vec<EdgeDeletionEntry>,
}
impl DeletionQuery {
    pub fn build(
        parameters: &mut Parameters,
        deletion: Arc<DeletionParser>,
        conn: &rusqlite::Connection,
    ) -> Result<Self> {
        let date = now();
        deletion.variables.validate_params(parameters)?;
        let mut deletion_query = Self {
            nodes: Vec::new(),
            node_log: Vec::new(),
            updated_nodes: Vec::new(),
            edges: Vec::new(),
            edge_log: Vec::new(),
        };
        for del in &deletion.deletions {
            let src = parameters
                .params
                .get(&del.id_param)
                .unwrap()
                .as_string()
                .unwrap();

            let src = uid_decode(src)?;
            let node = Node::get(&src, &del.short_name, conn)?;
            if let Some(node) = node {
                if del.references.is_empty() {
                    deletion_query.nodes.push(NodeDelete {
                        node: *node,
                        name: del.name.clone(),
                        short_name: del.short_name.clone(),
                        date,
                    })
                } else {
                    for edge_deletion in &del.references {
                        let dest = parameters
                            .params
                            .get(&edge_deletion.dest_param)
                            .unwrap()
                            .as_string()
                            .unwrap();

                        let dest = uid_decode(dest)?;

                        let edge = Edge::get(&src, &edge_deletion.label, &dest, conn)?;
                        if let Some(edge) = edge {
                            deletion_query.edges.push(EdgeDelete {
                                edge: *edge,
                                src_name: del.name.clone(),
                                room_id: node.room_id,
                                date,
                            });
                        }
                    }
                    let mut node = *node;
                    node.mdate = date;
                    deletion_query.updated_nodes.push(node);
                }
            }
        }
        Ok(deletion_query)
    }

    pub fn delete(
        &mut self,
        conn: &rusqlite::Connection,
    ) -> std::result::Result<(), rusqlite::Error> {
        for edg in &self.edges {
            edg.edge.delete(conn)?;
        }
        for log in &mut self.edge_log {
            log.write(conn)?;
        }
        for nod in &self.nodes {
            Node::delete(&nod.node.id, conn)?;
            Edge::delete_src(&nod.node.id, conn)?;
            Edge::delete_dest(&nod.node.id, conn)?;
        }
        for update in &mut self.updated_nodes {
            update.write(conn, false, &None, &None)?;
        }
        for log in &mut self.node_log {
            log.write(conn)?;
        }
        Ok(())
    }

    pub fn update_daily_logs(&self, daily_log: &mut DailyMutations) {
        for edg in &self.edge_log {
            daily_log.set_need_update(edg.room_id, edg.deletion_date);
        }
        for log in &self.node_log {
            daily_log.set_need_update(log.room_id, log.mdate);
            daily_log.set_need_update(log.room_id, log.deletion_date);
        }
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
            {
                Person {
                    name : String,
                }
            }",
            )
            .unwrap();

        let mutation = MutationParser::parse(
            r#"
            mutate {
                P1: Person { name:"John"  }
                P2: Person { name:"Alice"  }
                P3: Person { name:"Bob"  }
            } "#,
            &data_model,
        )
        .unwrap();
        let conn = Connection::open_in_memory().unwrap();
        prepare_connection(&conn).unwrap();

        let mut param = Parameters::new();
        let mutation = Arc::new(mutation);
        let mut mutation_query = MutationQuery::execute(&mut param, mutation, &conn).unwrap();
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
        let mut sql = Query {
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
            delete delete_person {
                Person { $id0 }
                Person { $id1 }
                Person { $id2 }
            }
          ",
            &data_model,
        )
        .unwrap();
        let deletion = Arc::new(deletion);

        let mut delete = DeletionQuery::build(&mut param, deletion, &conn).unwrap();
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
        let mut sql = Query {
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
            {
                Person {
                    name : String,
                    parents : [Person]
                }
            }",
            )
            .unwrap();

        let mutation = MutationParser::parse(
            r#"
            mutate {
                Person { name:"John" parents:[{name:"Alice"},{name:"Bob"}]  }
            } "#,
            &data_model,
        )
        .unwrap();
        let conn = Connection::open_in_memory().unwrap();
        prepare_connection(&conn).unwrap();

        let mut param = Parameters::new();
        let mutation = Arc::new(mutation);
        let mut mutation_query = MutationQuery::execute(&mut param, mutation, &conn).unwrap();
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
        let mut sql = Query {
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
            delete delete_person {
                Person { $src parents[$p0,$p1] }
            }
          ",
            &data_model,
        )
        .unwrap();
        let deletion = Arc::new(deletion);

        let mut delete = DeletionQuery::build(&mut param, deletion, &conn).unwrap();
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
        let mut sql = Query {
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
