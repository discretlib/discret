use std::sync::Arc;

use rusqlite::{OptionalExtension, ToSql};

use super::graph_database::{QueryResult, Readable};
use super::query_language::query_parser::{
    Direction, EntityParams, EntityQuery, Function, QueryField, QueryFieldType,
};
use super::query_language::{parameter::Parameters, query_parser::QueryParser};
use super::query_language::{FieldType, FieldValue, Value};
use super::Error;
use super::Result;
pub struct QueryVariable {}
#[derive(Debug)]
pub struct Param {
    internal: bool,
    value: String,
}

#[derive(Debug)]
pub struct PreparedQuery {
    pub name: String,
    pub var_order: Vec<Param>,
    pub sql_query: String,
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
        query.push_str("json_group_array(value->'$') \n");
        query.push_str("FROM (\n");
        let sub = get_entity_query(entity, &mut prepared_query, 1);
        query.push_str(&sub);
        query.push_str("\n )");

        prepared_query.sql_query = query;
        Ok(prepared_query)
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

pub fn get_entity_query(
    entity: &EntityQuery,
    prepared_query: &mut PreparedQuery,
    t: usize,
) -> String {
    let mut q = String::new();
    tab(&mut q, t);
    q.push_str("SELECT \n");
    let selection = get_fields(&entity, prepared_query, &entity.aliased_name(), t);
    tab(&mut q, t);
    q.push_str(&selection);
    q.push_str(" as value\n");
    tab(&mut q, t);
    q.push_str(&format!("FROM _node {}", entity.aliased_name()));

    q.push('\n');
    tab(&mut q, t);
    q.push_str("WHERE \n");
    tab(&mut q, t);
    q.push_str(&format!(
        "{}._entity='{}' ",
        entity.aliased_name(),
        &entity.short_name
    ));
    let paging = get_paging(&entity.params, prepared_query, t);
    q.push_str(&paging);

    let filters = get_where_filters(&entity.params, prepared_query, t);
    q.push_str(&filters);
    if entity.is_aggregate {
        let group_by = get_group_by(&entity.fields, t);
        q.push_str(&group_by);
    }

    if entity.params.order_by.len() > 0 {
        q.push('\n');
        tab(&mut q, t);
        let order_by = get_order(&entity.params);
        q.push_str(&order_by);
    }

    q.push('\n');
    tab(&mut q, t);
    let limit = get_limit(&entity.params, prepared_query);
    q.push_str(&limit);

    q
}

pub fn get_sub_group_array(
    entity: &EntityQuery,
    prepared_query: &mut PreparedQuery,
    parent_table: &str,
    field_name: &str,
    field_short: &str,
    t: usize,
) -> String {
    let mut q = String::new();

    tab(&mut q, t);
    q.push_str("SELECT \n");
    tab(&mut q, t);
    q.push_str("json_group_array(value->'$') as value \n");
    tab(&mut q, t);
    q.push_str("FROM (\n");
    let sub = get_sub_entity_query(
        entity,
        prepared_query,
        parent_table,
        field_name,
        field_short,
        t + 1,
        false,
    );
    q.push_str(&sub);
    q.push('\n');
    tab(&mut q, t);
    q.push_str(")");
    q.push('\n');
    tab(&mut q, t);
    q
}

pub fn get_sub_entity_query(
    entity: &EntityQuery,
    prepared_query: &mut PreparedQuery,
    parent_table: &str,
    field_name: &str,
    field_short: &str,
    t: usize,
    is_unique_value: bool,
) -> String {
    let mut q = String::new();
    tab(&mut q, t);
    q.push_str("SELECT \n");
    let selection = get_fields(&entity, prepared_query, field_name, t);
    tab(&mut q, t);
    q.push_str(&selection);
    q.push_str(" as value \n");
    tab(&mut q, t);

    q.push_str(&format!(
        "FROM _edge JOIN _node {0} on _edge.dest={0}.id AND _edge.label='{1}'",
        field_name, field_short
    ));

    q.push('\n');
    tab(&mut q, t);
    q.push_str("WHERE \n");
    tab(&mut q, t);
    q.push_str(&format!(
        "{}._entity='{}' AND \n",
        field_name, &entity.short_name
    ));
    tab(&mut q, t);
    q.push_str(&format!("_edge.src={}.id ", &parent_table));

    let paging = get_paging(&entity.params, prepared_query, t);
    q.push_str(&paging);

    let filters = get_where_filters(&entity.params, prepared_query, t);
    q.push_str(&filters);

    if entity.is_aggregate {
        let group_by = get_group_by(&entity.fields, t);
        q.push_str(&group_by);
    }

    if entity.params.order_by.len() > 0 {
        q.push('\n');
        tab(&mut q, t);
        let order_by = get_order(&entity.params);
        q.push_str(&order_by);
    }

    q.push('\n');
    tab(&mut q, t);
    if !is_unique_value {
        let limit = get_limit(&entity.params, prepared_query);
        q.push_str(&limit);
    } else {
        q.push_str("LIMIT 1 ");
    }
    q
}

pub fn tab(q: &mut String, t: usize) {
    for _ in 0..t {
        q.push_str("    ");
    }
}

fn js_field(field: &str) -> String {
    format!("_json->'$.{}'", field)
}

fn get_fields(
    entity: &EntityQuery,
    prepared_query: &mut PreparedQuery,
    parent_table: &str,
    t: usize,
) -> String {
    let mut q = String::new();
    q.push_str("json_object(");
    let it = &mut entity.fields.iter().peekable();
    while let Some(field) = it.next() {
        q.push('\n');
        tab(&mut q, t);

        match &field.field_type {
            QueryFieldType::BinaryField => {
                q.push_str(&format!(
                    "'{}', base64_encode({})",
                    &field.name(),
                    &field.field.short_name,
                ));
            }

            QueryFieldType::NamedField => {
                if field.field.is_system {
                    q.push_str(&format!("'{}', {}", &field.name(), &field.field.short_name,));
                } else {
                    q.push_str(&format!(
                        "'{}',{}",
                        &field.name(),
                        js_field(&field.field.short_name,)
                    ))
                }
            }

            QueryFieldType::EntityQuery(field_entity, _) => {
                q.push_str(&format!("'{}', (\n", &field.name()));
                let query = get_sub_entity_query(
                    &field_entity,
                    prepared_query,
                    parent_table,
                    &field.name(),
                    &field.field.short_name,
                    t + 1,
                    true,
                );
                q.push_str(&query);
                q.push('\n');
                tab(&mut q, t);
                q.push_str(")->'$'");
            }

            QueryFieldType::EntityArrayQuery(field_entity, _) => {
                q.push_str(&format!("'{}', (\n", &field.name()));
                let query = get_sub_group_array(
                    &field_entity,
                    prepared_query,
                    parent_table,
                    &field.name(),
                    &field.field.short_name,
                    t + 1,
                );
                q.push_str(&query);
                q.push('\n');
                tab(&mut q, t);
                q.push(')');
            }

            QueryFieldType::Aggregate(funx) => {
                let func = match &funx {
                    Function::Avg(f) => {
                        let agg_field = if field.field.is_system {
                            field.field.name.clone()
                        } else {
                            js_field(f)
                        };
                        format!("'{}', avg({}) ", &field.name(), agg_field)
                    }
                    Function::Count => format!("'{}',count(1) ", &field.name()),
                    Function::Max(f) => {
                        let agg_field = if field.field.is_system {
                            field.field.name.clone()
                        } else {
                            js_field(f)
                        };
                        format!("'{}', max({}) ", &field.name(), agg_field)
                    }
                    Function::Min(f) => {
                        let agg_field = if field.field.is_system {
                            field.field.name.clone()
                        } else {
                            js_field(f)
                        };
                        format!("'{}', min({}) ", &field.name(), agg_field)
                    }
                    Function::Sum(f) => {
                        let agg_field = if field.field.is_system {
                            field.field.name.clone()
                        } else {
                            js_field(f)
                        };
                        format!("'{}', total({}) ", &field.name(), agg_field)
                    }
                    Function::RefBy(_, _) => unreachable!(),
                };
                q.push_str(&func);
            }

            QueryFieldType::Function(_) => todo!(),
        }

        if !it.peek().is_none() {
            q.push(',');
        }
    }
    q.push(')');
    q
}

fn get_where_filters(
    params: &EntityParams,
    prepared_query: &mut PreparedQuery,
    t: usize,
) -> String {
    let mut q = String::new();

    if params.filters.len() > 0 {
        q.push_str("AND ");
        q.push('\n');
        tab(&mut q, t);
        let it = &mut params.filters.iter().peekable();
        while let Some(filter) = it.next() {
            let mut operation = filter.operation.clone();

            let value = match &filter.value {
                FieldValue::Variable(var) => prepared_query.add_param(String::from(var), false),
                FieldValue::Value(val) => match val {
                    Value::Boolean(bool) => bool.to_string(),
                    Value::Integer(i) => i.to_string(),
                    Value::Float(f) => f.to_string(),
                    Value::String(s) => prepared_query.add_param(String::from(s), true),
                    Value::Null => {
                        match filter.operation.as_str() {
                            "=" => operation = String::from("is"),
                            "!=" => operation = String::from("is not"),
                            _ => {}
                        }
                        String::from("null")
                    }
                },
            };

            if filter.field.is_system {
                q.push_str(&format!("{} {} {}", &filter.name, operation, &value));
            } else {
                match filter.field.field_type {
                    FieldType::Array(_) => {
                        q.push_str(&format!(
                            "value->>'$.{}[0]' {} {}",
                            &filter.name, operation, &value
                        ));
                    }

                    FieldType::Entity(_) => {
                        q.push_str(&format!(
                            "value->>'$.{}' {} {}",
                            &filter.name, operation, &value
                        ));
                    }
                    _ => {
                        if filter.is_selected {
                            q.push_str(&format!(
                                "value->>'$.{}' {} {}",
                                &filter.name, operation, &value
                            ));
                        } else {
                            q.push_str(&format!(
                                "_json->>'$.{}' {} {}",
                                &filter.field.short_name, operation, &value
                            ));
                        }
                    }
                }
            }

            if !it.peek().is_none() {
                q.push_str(" AND\n");
                tab(&mut q, t);
            }
        }
    }
    q
}
pub fn get_order(params: &EntityParams) -> String {
    let mut query = String::new();

    if !params.order_by.is_empty() {
        query.push_str("ORDER BY ");

        let it = &mut params.order_by.iter().peekable();
        while let Some(ord) = it.next() {
            let direction = match ord.direction {
                Direction::Asc => String::from("asc"),
                Direction::Desc => String::from("desc"),
            };
            if ord.is_selected {
                query.push_str(&format!("value->>'$.{}' {} ", &ord.name, direction));
            } else if ord.field.is_system {
                query.push_str(&format!("{} {} ", &ord.name, direction));
            } else {
                query.push_str(&format!(
                    "_json->>'$.{}' {} ",
                    &ord.field.short_name, direction
                ));
            }

            if !it.peek().is_none() {
                query.push_str(", ");
            }
        }
    }

    query
}

pub fn get_paging(params: &EntityParams, prepared_query: &mut PreparedQuery, t: usize) -> String {
    let mut q = String::new();

    let mut before = true;
    let paging = if !params.before.is_empty() {
        &params.before
    } else {
        before = false;
        &params.after
    };

    if paging.len() > 0 {
        q.push_str(" AND \n");
        tab(&mut q, t);
        q.push('(');
    }
    for i in 0..paging.len() {
        if paging.len() > 1 {
            q.push('(');
        }

        for j in 0..i {
            let ord = &params.order_by[j];
            let value = &paging[j];
            let value = match value {
                FieldValue::Variable(var) => prepared_query.add_param(String::from(var), false),
                FieldValue::Value(val) => match val {
                    Value::Boolean(bool) => bool.to_string(),
                    Value::Integer(i) => i.to_string(),
                    Value::Float(f) => f.to_string(),
                    Value::String(s) => prepared_query.add_param(String::from(s), true),
                    Value::Null => String::from("null"),
                },
            };

            if ord.is_selected {
                q.push_str(&format!("value->>'$.{}' = {}", &ord.name, value));
            } else if ord.field.is_system {
                q.push_str(&format!("{} = {}", &ord.name, value));
            } else {
                q.push_str(&format!(
                    "_json->>'$.{}' = {}",
                    &ord.field.short_name, value
                ));
            }

            q.push_str(" AND ");
        }

        let ord = &params.order_by[i];
        let value = &paging[i];
        let value = match value {
            FieldValue::Variable(var) => prepared_query.add_param(String::from(var), false),
            FieldValue::Value(val) => match val {
                Value::Boolean(bool) => bool.to_string(),
                Value::Integer(i) => i.to_string(),
                Value::Float(f) => f.to_string(),
                Value::String(s) => prepared_query.add_param(String::from(s), true),
                Value::Null => String::from("null"),
            },
        };

        // asc 12345  before <
        // asc 12345  after >
        // desc 54321  before >
        // asc 12345  after <
        let ope = match ord.direction {
            Direction::Asc => {
                if before {
                    '<'
                } else {
                    '>'
                }
            }
            Direction::Desc => {
                if before {
                    '>'
                } else {
                    '<'
                }
            }
        };

        if ord.is_selected {
            q.push_str(&format!("value->>'$.{}' {} {}", &ord.name, ope, value));
        } else if ord.field.is_system {
            q.push_str(&format!("{} {} {}", &ord.name, ope, value));
        } else {
            q.push_str(&format!(
                "_json->>'$.{}' {} {}",
                &ord.field.short_name, ope, value
            ));
        }

        if paging.len() > 1 {
            q.push(')');
        }

        if i < paging.len() - 1 {
            q.push_str(" OR ")
        }
    }
    if paging.len() > 0 {
        q.push_str(") ");
    }

    q
}

pub fn get_limit(params: &EntityParams, prepared_query: &mut PreparedQuery) -> String {
    let mut query = String::new();

    match &params.first {
        FieldValue::Variable(var) => {
            let vars = prepared_query.add_param(String::from(var), false);
            query.push_str(&format!("LIMIT {}", vars));
        }
        FieldValue::Value(val) => {
            let val = val.as_i64().unwrap();
            if val != 0 {
                query.push_str(&format!("LIMIT {}", val));
            }
        }
    }

    if let Some(skip) = &params.skip {
        match skip {
            FieldValue::Variable(var) => {
                let vars = prepared_query.add_param(String::from(var), false);
                query.push_str(&format!(" OFFSET {}", vars));
            }
            FieldValue::Value(val) => {
                let val = val.as_i64().unwrap();
                if val != 0 {
                    query.push_str(&format!(" OFFSET {}", val));
                }
            }
        }
    }
    query
}

fn get_group_by(fields: &Vec<QueryField>, t: usize) -> String {
    let mut q = String::new();

    let mut v = Vec::new();

    for field in fields {
        match &field.field_type {
            QueryFieldType::NamedField => v.push(field.field.short_name.clone()),
            _ => {}
        }
    }
    if v.len() > 0 {
        q.push('\n');
        tab(&mut q, t);
        q.push_str("GROUP BY ")
    }

    let it = &mut v.iter().peekable();
    while let Some(field) = it.next() {
        q.push_str(&format!("_json->>'$.{}'", field));
        if !it.peek().is_none() {
            q.push(',');
        }
    }

    q
}

#[derive(Debug)]
pub struct Queries {
    pub name: String,
    pub sql_queries: Vec<PreparedQuery>,
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
    pub parameters: Parameters,
    pub parser: Arc<QueryParser>,
    pub sql_queries: Queries,
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
