use std::sync::Arc;

use rusqlite::{OptionalExtension, ToSql};

use super::graph_database::{QueryResult, Readable};
use super::query_language::query_parser::{
    EntityQuery, FilterParam, FilterType, Function, QueryField, QueryFieldType,
};
use super::query_language::{parameter::Parameters, query_parser::QueryParser};
use super::query_language::{FieldValue, Value};
use super::Error;
use super::Result;
pub struct QueryVariable {}
#[derive(Debug)]
struct Param {
    internal: bool,
    value: String,
}

#[derive(Debug)]
pub struct PreparedQuery {
    name: String,
    var_order: Vec<Param>,
    sql_query: String,
}
impl Default for PreparedQuery {
    fn default() -> Self {
        Self {
            name: Default::default(),
            var_order: Default::default(),
            sql_query: Default::default(),
        }
    }
}
impl PreparedQuery {
    fn add_param(&mut self, value: String, internal: bool) -> String {
        if internal {
            self.var_order.push(Param { internal, value });
            format!("?{}", self.var_order.len())
        } else {
            for i in 0..self.var_order.len() {
                let p = &self.var_order[i].value;
                if value.eq(p) {
                    return format!("?{}", i + 1);
                }
            }
            self.var_order.push(Param { internal, value });
            format!("?{}", self.var_order.len())
        }
    }

    pub fn build(entity: &EntityQuery) -> Result<Self> {
        let mut prepared_query = PreparedQuery {
            name: String::from(&entity.aliased_name()),
            ..Default::default()
        };
        let mut query = String::new();
        query.push_str("SELECT \n");
        query.push_str("    json_group_array(");
        if entity.is_aggregate {
            query.push_str(&build_aggregate_fields(
                &entity.fields,
                &aggregate_tbl(&entity.aliased_name()),
            ));
        } else {
            query.push_str(&build_default_fields(&entity.fields));
        }
        query.push_str(")");
        query.push_str(" FROM _node\n");

        for field in &entity.fields {
            match &field.field_type {
                QueryFieldType::EntityQuery(e, nullable) => {
                    if *nullable {
                        query.push_str(" LEFT");
                    }
                    query.push_str(" JOIN ");
                    query.push_str(&build_entity_table(
                        &*e,
                        &field.name(),
                        &field.field.short_name,
                    ));
                    query.push_str(&format!(" ON  _node.id = {}.src \n", &field.name()));
                }
                QueryFieldType::EntityArrayQuery(e, nullable) => {
                    if *nullable {
                        query.push_str(" LEFT ");
                    }
                    query.push_str(" JOIN ");
                    query.push_str(&build_entity_table(
                        &*e,
                        &field.name(),
                        &field.field.short_name,
                    ));
                    query.push_str(&format!(" ON  _node.id = {}.src \n", &field.name()));
                }
                _ => {}
            }
        }

        query.push_str(" WHERE \n");
        query.push_str(&format!(" _node._entity='{}' ", &entity.short_name));
        if let Some(params) = &entity.params {
            query.push_str(" AND \n");
            if params.filters.len() > 0 {
                query.push_str(&prepared_query.build_filters(&params.filters));
            }
        }

        prepared_query.sql_query = query;
        Ok(prepared_query)
    }

    fn build_filters(&mut self, filters: &Vec<FilterParam>) -> String {
        let mut sql = String::new();
        let it = &mut filters.iter().peekable();
        while let Some(filter) = it.next() {
            let value = match &filter.value {
                FieldValue::Variable(var) => self.add_param(String::from(var), false),
                FieldValue::Value(val) => match val {
                    Value::Boolean(bool) => bool.to_string(),
                    Value::Integer(i) => i.to_string(),
                    Value::Float(f) => f.to_string(),
                    Value::String(s) => self.add_param(String::from(s), true),
                    Value::Null => String::from("null"),
                },
            };
            match filter.filter_type {
                FilterType::Field => {
                    sql.push_str(&format!(
                        " {} {} {} ",
                        &format!("_json_data->>'$.{}'", &filter.short_name),
                        &filter.operation,
                        &value
                    ));
                }
                FilterType::SystemField => {
                    sql.push_str(&format!(
                        " {} {} {} ",
                        &filter.name, &filter.operation, &value
                    ));
                }
                FilterType::EntityField => {
                    sql.push_str(&format!(
                        " {}._value->>'$' {} {} ",
                        &filter.name, &filter.operation, &value
                    ));
                }
            }

            if !it.peek().is_none() {
                sql.push_str(" AND \n");
            }
        }
        sql
    }

    pub fn build_query_params(
        &self,
        params: &Parameters,
    ) -> Result<Vec<Box<dyn ToSql + Sync + Send>>> {
        let mut v: Vec<Box<dyn ToSql + Sync + Send>> = Vec::new();

        for var in &self.var_order {
            if var.internal {
                v.push(Box::new(var.value.clone()));
            } else {
                let para = params.params.get(&var.value);
                if let Some(val) = para {
                    match val {
                        Value::Boolean(e) => {
                            v.push(Box::new(*e));
                        }
                        Value::Float(e) => {
                            v.push(Box::new(*e));
                        }
                        Value::Integer(e) => {
                            v.push(Box::new(*e));
                        }
                        Value::Null => {
                            let null: Option<String> = None;
                            v.push(Box::new(null));
                        }
                        Value::String(e) => {
                            v.push(Box::new(e.clone()));
                        }
                    }
                } else {
                    return Err(Error::MissingParameter(String::from(&var.value)));
                }
            }
        }
        Ok(v)
    }
}

#[derive(Debug)]
pub struct Queries {
    name: String,
    sql_queries: Vec<PreparedQuery>,
}
impl Queries {
    pub fn build(parser: &QueryParser) -> Result<Self> {
        let mut sql_queries = Vec::new();
        for query in &parser.queries {
            sql_queries.push(PreparedQuery::build(&query)?);
        }
        Ok(Self {
            name: String::from(&parser.name),
            sql_queries,
        })
    }
}

pub struct Query {
    parameters: Parameters,
    parser: Arc<QueryParser>,
    sql_queries: Queries,
}
impl Readable for Query {
    fn read(&self, conn: &rusqlite::Connection) -> Result<super::graph_database::QueryResult> {
        let mut result_string = String::new();
        result_string.push('{');
        result_string.push('\n');

        self.parser.variables.validate_params(&self.parameters)?;

        let quer = &self.sql_queries.sql_queries;
        for i in 0..quer.len() {
            let query = &quer[i];
            let params_vec = query.build_query_params(&self.parameters)?;
            let sql = &query.sql_query;
            let mut stmt = conn.prepare_cached(sql)?;
            let params = rusqlite::params_from_iter(&params_vec);
            let query_res: Option<String> =
                stmt.query_row(params, |row| Ok(row.get(0)?)).optional()?;
            let result = match query_res {
                Some(e) => e,
                None => String::from("[]"),
            };
            result_string.push('"');
            result_string.push_str(&query.name);
            result_string.push('"');
            result_string.push(':');
            result_string.push_str(&result);
            if i < quer.len() - 1 {
                result_string.push(',');
            }
            result_string.push('\n');
        }

        result_string.push('}');
        Ok(QueryResult::String(result_string))
    }
}

fn build_default_fields(fields: &Vec<QueryField>) -> String {
    let mut query = String::new();
    query.push_str("json_object(");
    let it = &mut fields.iter().peekable();
    while let Some(field) = it.next() {
        let field_tuple = if field.field.is_system {
            match field.field_type {
                QueryFieldType::BinaryField => {
                    format!(
                        "'{}', base64_encode({})",
                        &field.name(),
                        &field.field.short_name,
                    )
                }
                _ => format!("'{}', {}", &field.name(), &field.field.short_name,),
            }
        } else {
            match field.field_type {
                QueryFieldType::NamedField => {
                    format!("'{}',{}", &field.name(), js_field(&field.field.short_name,))
                }
                QueryFieldType::BinaryField => format!(
                    "'{}',base64_encode({}) ",
                    &field.name(),
                    js_field(&field.field.short_name,)
                ),
                QueryFieldType::EntityQuery(_, _) | QueryFieldType::EntityArrayQuery(_, _) => {
                    format!("'{}',{}._value->'$' ", &field.name(), &field.name())
                }
                QueryFieldType::Function(_) | QueryFieldType::Aggregate(_) => todo!(),
            }
        };

        query.push_str(&field_tuple);
        if !it.peek().is_none() {
            query.push(',');
        }
    }
    query.push(')');
    query
}

fn js_field(field: &str) -> String {
    format!("_json_data->'$.{}'", field)
}

fn aggregate_tbl(entity: &str) -> String {
    format!("_agg_{}", entity)
}

fn build_aggregate_fields(fields: &Vec<QueryField>, inner_table: &str) -> String {
    let mut query = String::new();
    query.push_str("json_object(");
    let it = &mut fields.iter().peekable();
    while let Some(field) = it.next() {
        let field_tuple = match field.field_type {
            QueryFieldType::NamedField => {
                format!("'{}',{}.{}", &field.name(), inner_table, &field.name())
            }
            QueryFieldType::BinaryField => format!(
                "'{}',base64_encode({}.{}) ",
                &field.name(),
                inner_table,
                &field.name()
            ),
            QueryFieldType::Function(_) => unreachable!(),
            _ => unreachable!(),
        };

        query.push_str(&field_tuple);
        if !it.peek().is_none() {
            query.push(',');
        }
    }
    query.push(')');
    query
}

fn build_inner_aggregate_fields(fields: &Vec<QueryField>) -> String {
    let mut query = String::new();
    query.push_str("json_object(");
    let it = &mut fields.iter().peekable();
    while let Some(field) = it.next() {
        let field_tuple = match &field.field_type {
            QueryFieldType::NamedField => {
                format!("{} as {}", &field.name(), &field.name())
            }
            QueryFieldType::BinaryField => {
                format!("base64_encode({}) as {}", &field.name(), &field.name(),)
            }

            QueryFieldType::Function(funx) => match &funx {
                Function::Avg(f) => {
                    format!("avg({}) as {}", js_field(f), &field.name())
                }
                Function::Count => format!("count(1) as {}", &field.name()),
                Function::Max(f) => {
                    format!("max({}) as {}", js_field(f), &field.name())
                }
                Function::Min(f) => {
                    format!("min({}) as {}", js_field(f), &field.name())
                }
                Function::Sum(f) => {
                    format!("sum({}) as {}", js_field(f), &field.name())
                }
                Function::RefBy(_, _) => unreachable!(),
            },
            _ => unreachable!(),
        };

        query.push_str(&field_tuple);
        if !it.peek().is_none() {
            query.push(',');
        }
    }
    query.push(')');
    query
}

fn build_entity_table(entity: &EntityQuery, field_name: &str, field_short: &str) -> String {
    let mut query = String::new();
    query.push_str("( SELECT _edge.src,  \n");
    query.push_str("    json_group_array(");
    if entity.is_aggregate {
        query.push_str(&build_aggregate_fields(
            &entity.fields,
            &aggregate_tbl(&entity.aliased_name()),
        ));
    } else {
        query.push_str(&build_default_fields(&entity.fields));
    }
    query.push_str(") as _value");
    query.push_str(&format!(
        "\n   FROM _edge JOIN _node on _edge.dest=_node.id AND _edge.label = '{}' AND _node._entity ='{}'\n",
        field_short,
        &entity.short_name
    ));
    for field in &entity.fields {
        match &field.field_type {
            QueryFieldType::EntityQuery(e, nullable) => {
                if *nullable {
                    query.push_str(" LEFT ");
                }
                query.push_str(" JOIN ");
                query.push_str(&build_entity_table(
                    &*e,
                    &field.name(),
                    &field.field.short_name,
                ));
                query.push_str(&format!(" ON  _node.id = {}.src \n", &field.name()));
            }
            QueryFieldType::EntityArrayQuery(e, nullable) => {
                if *nullable {
                    query.push_str(" LEFT ");
                }
                query.push_str(" JOIN ");
                query.push_str(&build_entity_table(
                    &*e,
                    &field.name(),
                    &field.field.short_name,
                ));
                query.push_str(&format!(" ON  _node.id = {}.src \n", &field.name()));
            }
            _ => {}
        }
    }

    query.push_str(" GROUP BY _edge.src ");
    query.push_str(&format!(" ) as {} ", field_name));
    query
}

#[cfg(test)]
mod tests {

    use std::{
        fs,
        path::{Path, PathBuf},
    };

    use rusqlite::Connection;

    use crate::{
        database::{
            graph_database::{prepare_connection, Writeable},
            mutation_query::PrepareMutation,
            query_language::{data_model::DataModel, mutation_parser::MutationParser, Value},
        },
        Ed25519SigningKey, SigningKey,
    };

    use super::*;

    const DATA_PATH: &str = "test/data/database/query_builder";
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
    fn simple_scalar() {
        let data_model = DataModel::parse(
            "
            Person {
                name : String ,
                age : Integer,
                weight : Float,
                is_human : Boolean, 
                some_nullable : String nullable,
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
            mutation_query.write(&conn).unwrap();
        }

        let query_parser = QueryParser::parse(
            "
            query sample{
                Person {
                    name
                    age
                    weight
                    is_human
                    some_nullable
                }
                same_person: Person {
                    name
                    age
                    weight
                    is_human
                    some_nullable
                }
            }
        ",
            &data_model,
        )
        .unwrap();

        let query = Queries::build(&query_parser).unwrap();
        let param = Parameters::new();
        let sql = Query {
            parameters: param,
            parser: Arc::new(query_parser),
            sql_queries: query,
        };
        let result = sql.read(&conn).unwrap();

        let expected = "{\n\"Person\":[{\"name\":\"John\",\"age\":100,\"weight\":42.2,\"is_human\":true,\"some_nullable\":null}],\n\"same_person\":[{\"name\":\"John\",\"age\":100,\"weight\":42.2,\"is_human\":true,\"some_nullable\":null}]\n}";
        //println!("{:#?}", result.as_string().unwrap());
        assert_eq!(expected, result.as_string().unwrap());
    }

    #[test]
    fn system() {
        let data_model = DataModel::parse(
            "
            Person {
                name : String
            }
        ",
        )
        .unwrap();

        let mutation = MutationParser::parse(
            r#"
            mutation mutmut {
                Person {
                    name : "hello"
                }
            } "#,
            &data_model,
        )
        .unwrap();

        let param = Parameters::new();
        let conn = Connection::open_in_memory().unwrap();
        prepare_connection(&conn).unwrap();

        let prep_mut = PrepareMutation {
            parameters: param,
            mutation: Arc::new(mutation),
        };
        let signing_key = Ed25519SigningKey::new();
        let mut to_insert = prep_mut.read(&conn).unwrap();

        let mutation_query = to_insert.as_mutation_query().unwrap();
        mutation_query.sign_all(&signing_key).unwrap();
        mutation_query.write(&conn).unwrap();

        let query_parser = QueryParser::parse(
            "
            query sample{
                Person {
                    id
                    cdate
                    mdate
                    _entity
                    _json_data
                    _binary_data
                    _pub_key
                    _signature
                }
                
            }
        ",
            &data_model,
        )
        .unwrap();

        let query = Queries::build(&query_parser).unwrap();
        let param = Parameters::new();
        let sql = Query {
            parameters: param,
            parser: Arc::new(query_parser),
            sql_queries: query,
        };
        let result = sql.read(&conn).unwrap();
        //println!("{:#?}", result.as_string().unwrap());
        println!("{}", result.as_string().unwrap());
    }

    #[test]
    fn entity() {
        let data_model = DataModel::parse(
            "
            Person {
                name : String ,
                parents : [Person] nullable,
                pet: Pet nullable,
                siblings : [Person] nullable,
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

        let mut to_insert = prep_mut.read(&conn).unwrap();

        let mutation_query = to_insert.as_mutation_query().unwrap();
        mutation_query.write(&conn).unwrap();

        let query_parser = QueryParser::parse(
            r#"
            query sample{
                Person (remps_pets is not NULL, 
                    id != "zSRIyMbf70V999wyC0KlhQ", 
                    name = "John"
                    ) {
                    name
                    parents {
                        name
                    }
                    pet {name}
                    remps_pets : parents {
                        name
                        pet {name}
                    }
                }
                
            }
        "#,
            &data_model,
        )
        .unwrap();

        let query = Queries::build(&query_parser).unwrap();
        for vals in &query.sql_queries {
            println!("{}", vals.sql_query);
        }

        let param = Parameters::new();
        let sql = Query {
            parameters: param,
            parser: Arc::new(query_parser),
            sql_queries: query,
        };
        let result = sql.read(&conn).unwrap();
        //println!("{:#?}", result.as_string().unwrap());
        //println!("{}", result.as_string().unwrap());
        //let expected = "{\n\"Person\":[{\"name\":\"John\",\"parents\":[{\"name\":\"World\"},{\"name\":\"Hello\"}],\"pet\":[{\"name\":\"Truffle\"}],\"remps_pets\":[{\"name\":\"World\",\"pet\":[{\"name\":\"kiki\"}]},{\"name\":\"Hello\",\"pet\":null}]}]\n}";
        //assert_eq!(expected, result.as_string().unwrap());
    }
}
