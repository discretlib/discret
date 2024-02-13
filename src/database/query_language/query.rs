use std::collections::HashMap;

use crate::database::query_language::VariableType;

use super::{
    data_model::{DataModel, Entity},
    parameter::Variables,
    Error, FieldType, FieldValue, Value,
};

use pest::{iterators::{Pair, Pairs}, Parser};
use pest_derive::Parser;

#[derive(Parser)]
#[grammar = "database/query_language/query.pest"]
struct PestParser;


#[derive(Debug)]
pub enum QueryFieldType {
    Function(Function),
    NamedField,
    EntityQuery(EntityQuery)
}


#[derive(Debug)]
pub struct QueryField{
    name: String,
    alias: Option<String>,
    field_type:QueryFieldType
}

#[derive(Debug)]
pub enum Function {
    Avg(String),
    Count,
    Max(String),
    Min(String) ,
    Sum(String),
    RefBy(String,EntityQuery)
}

#[derive(Debug)]
pub enum QueryType {
    Query,
    Subscription,
}

const DEFAULT_LIMIT: i64 = 100;
#[derive(Debug)]
pub struct EntityParams {
    after: Option<FieldValue>,
    before: Option<FieldValue>,
    filters: Vec<FilterParam>,
    fulltext_search: Option<FieldValue>,
    limit: FieldValue,
    order_by: Vec<(String, String)>,
    skip: Option<FieldValue>,
}
impl EntityParams {
    pub fn new() -> Self {
        Self {
            after: None,
            before: None,
            filters: Vec::new(),
            fulltext_search: None,
            limit: FieldValue::Value(Value::Integer(DEFAULT_LIMIT)),
            order_by: Vec::new(),
            skip: None,
        }
    }

    pub fn add_filter(&mut self, name: String, operation: String, value: FieldValue) {
        self.filters.push(FilterParam {
            name,
            operation,
            value,
        })
    }
}

#[derive(Debug)]
pub struct FilterParam {
    name: String,
    operation: String,
    value: FieldValue,
}

#[derive(Debug)]
pub struct EntityQuery {
    name: String,
    alias: Option<String>,
    params: Option<EntityParams>,
    fields: HashMap<String, QueryField>,
}
impl EntityQuery {
    pub fn new() -> Self {
        Self {
            name: "".to_string(),
            alias: None,
            params: None,
            fields: HashMap::new(),
        }
    }
    pub fn add_field(&mut self, field:QueryField) -> Result<(),Error> {
        let key;
        if field.alias.is_some(){
            key = field.alias.clone().unwrap();
        }else{
            key = field.name.clone();
        }
        if self.fields.contains_key(&key){
            return Err(Error::DuplicatedField(key))
        } else{
            self.fields.insert(key, field);
        }
        
        Ok(())
    }
}

#[derive(Debug)]
pub struct Query {
    name: String,
    query_type: QueryType,
    variables: Variables,
    queries: Vec<EntityQuery>,
}
impl Query {
    pub fn new() -> Self {
        Self {
            name: "".to_string(),
            query_type: QueryType::Query,
            variables: Variables::new(),
            queries: Vec::new(),
        }
    }

    pub fn parse(p: &str, data_model: &DataModel) -> Result<Self, Error> {
        let mut query = Query::new();

        let parse = match PestParser::parse(Rule::query, p) {
            Err(e) => {
                let message = format!("{}", e);
                return Err(Error::ParserError(message));
            }
            Ok(f) => f,
        }
        .next()
        .unwrap();

        match parse.as_rule() {
            Rule::query => {
                let mut query_pairs = parse.into_inner();

                let query_type = query_pairs.next().unwrap();
                match query_type.as_str() {
                    "query" => query.query_type = QueryType::Query,
                    "subscription" => query.query_type = QueryType::Subscription,
                    _ => unreachable!(),
                }

                query.name = query_pairs.next().unwrap().as_str().to_string();

                for entity_pair in query_pairs.into_iter() {
                    match entity_pair.as_rule() {
                        Rule::entity => {
                            let ent =
                                Self::parse_entity(data_model, entity_pair, &mut query.variables)?;
                            query.queries.push(ent);
                        }
                        Rule::EOI => {}
                        _ => unreachable!(),
                    }
                }
            }
            _ => {}
        }

        Ok(query)
    }


    fn parse_entity_internals(
        entity: &mut EntityQuery,
        data_model: &DataModel,
        pairs: Pairs<'_, Rule>,
        variables: &mut Variables,
    ) -> Result<(), Error> {

        for entity_pair in pairs {
            match entity_pair.as_rule() {
                Rule::entity_param => {
                    let model_entity = data_model.get_entity(&entity.name)?;
                    let params = Self::parse_params(model_entity, entity_pair, variables)?;
                    entity.params = Some(params);
                }

                Rule::field => {
                    let field_pair = entity_pair.into_inner().next().unwrap();
                    match field_pair.as_rule() {
                        Rule::named_field => {
                            let mut name_pair = field_pair.into_inner();
                            let name;
                            let alias;
                            if name_pair.len() == 2 {
                                let alias_name = name_pair.next().unwrap().as_str().to_string();
                                alias = Some(alias_name);
                                name = name_pair.next().unwrap().as_str().to_string();
                            } else {
                                name = name_pair.next().unwrap().as_str().to_string();
                                alias = None;
                            }

                            let model_entity = data_model.get_entity(&entity.name)?;
                            let model_field = model_entity.get_field(&name)?;

                            match model_field.field_type {
                                FieldType::Array(_) | FieldType::Entity(_) => {
                                    return Err(Error::InvalidQuery(format!(
                                        "Invalid syntax for non scalar field. please use {}{{ .. }}",
                                        &name
                                    )))
                                }
                                _=>{}   
                            }
                            let named = QueryField{
                                name,
                                alias,
                                field_type: QueryFieldType::NamedField
                            };
                            entity.add_field(named)?;

                        }
                       
                        Rule::entity => { 
                            let model_entity = data_model.get_entity(&entity.name)?;

                            let mut entity_pairs =  field_pair.into_inner();
                            let mut  name_pair = entity_pairs.next().unwrap().into_inner();
                            let name;
                            let alias;
                            if name_pair.len() == 2 {
                                alias = Some(name_pair.next().unwrap().as_str().to_string());
                                name = name_pair.next().unwrap().as_str().to_string();
                            } else {
                                alias = None;
                                name = name_pair.next().unwrap().as_str().to_string();
                            }
                            let entity_field = model_entity.get_field(&name)?;
                            let taget_entity_name = match &entity_field.field_type {

                                FieldType::Array(e) => e,
                                FieldType::Entity(e) => e,  
                                _=>  return Err(Error::InvalidQuery(format!(
                                    "Invalid syntax for scalar field. please use {} without {{ .. }}",
                                    &name
                                ))) 
                            };
                            let mut target_entity =  EntityQuery::new();
                            target_entity.name = taget_entity_name.clone();

                            Self::parse_entity_internals(&mut target_entity, data_model, entity_pairs, variables)?;

                            let named = QueryField{
                                name,
                                alias,
                                field_type: QueryFieldType::EntityQuery(target_entity)
                            };
                            entity.add_field(named)?;
                        }
                        Rule::function => {
                           
                            let mut function_pairs = field_pair.into_inner();
                            let name = function_pairs.next().unwrap().as_str().to_string();
                            
                            let function_pair =  function_pairs.next().unwrap().into_inner().next().unwrap();

                            let model_entity = data_model.get_entity(&entity.name)?;
                           
                        
                            match function_pair.as_rule() {
                                Rule::count_fn => {
                                    let named = QueryField{
                                        name,
                                        alias:None,
                                        field_type: QueryFieldType::Function(Function::Count)
                                    };
                                    entity.add_field(named)?;
                                }
                                Rule::avg_fn => {
                                    let param = function_pair.into_inner().next().unwrap().as_str();
                                    let model_field = model_entity.get_field(param)?;
                                    match model_field.field_type{
                                        FieldType::Integer | FieldType::Float => {}
                                        _=> {return Err(Error::InvalidQuery(format!(
                                            "avg({}) requires integer or float field and '{}' is a '{}'",
                                            &param, &param, model_field.field_type
                                        ))) 
                                        }
                                    }
                                    let named = QueryField{
                                        name,
                                        alias:None,
                                        field_type: QueryFieldType::Function(Function::Avg(param.to_string()))
                                    };
                                    entity.add_field(named)?;

                                }
                                Rule::max_fn => {
                                    let param = function_pair.into_inner().next().unwrap().as_str();
                                    let model_field = model_entity.get_field(param)?;
                                    match model_field.field_type{
                                        FieldType::Array(_) | FieldType::Entity(_) => {}
                                        _=> {return Err(Error::InvalidQuery(format!(
                                            "max({}) requires a scalar field and '{}' is a '{}'",
                                            &param, &param, model_field.field_type
                                        ))) 
                                        }
                                    }
                                    let named = QueryField{
                                        name,
                                        alias:None,
                                        field_type: QueryFieldType::Function(Function::Max(param.to_string()))
                                    };
                                    entity.add_field(named)?;
                                }
                                Rule::min_fn => {
                                    let param = function_pair.into_inner().next().unwrap().as_str();
                                    let model_field = model_entity.get_field(param)?;
                                    match model_field.field_type{
                                        FieldType::Array(_) | FieldType::Entity(_) => {}
                                        _=> {return Err(Error::InvalidQuery(format!(
                                            "min({}) requires a scalar field and '{}' is a '{}'",
                                            &param, &param, model_field.field_type
                                        ))) 
                                        }
                                    }
                                    let named = QueryField{
                                        name,
                                        alias:None,
                                        field_type: QueryFieldType::Function(Function::Min(param.to_string()))
                                    };
                                    entity.add_field(named)?;

                                }
                                Rule::sum_fn => {
                                    let param = function_pair.into_inner().next().unwrap().as_str();
                                    let model_field = model_entity.get_field(param)?;
                                    match model_field.field_type{
                                        FieldType::Integer | FieldType::Float => {}
                                        _=> {
                                            return Err(Error::InvalidQuery(format!(
                                            "sum({}) requires integer or float field and '{}' is a '{}'",
                                            &param, &param, model_field.field_type
                                        ))) 
                                        }
                                    }
                                    let named = QueryField{
                                        name,
                                        alias:None,
                                        field_type: QueryFieldType::Function(Function::Sum(param.to_string()))
                                    };
                                    entity.add_field(named)?;

                                }

                                Rule::ref_by_fn => { 
                                    let mut ref_by_pairs = function_pair.into_inner();
                                    let ref_field = ref_by_pairs.next().unwrap().as_str();
                                    let ref_entity_name = ref_by_pairs.next().unwrap().as_str();

                                    let model_entity = data_model.get_entity(ref_entity_name)?;
                                    let model_field = model_entity.get_field(ref_field)?;
                                    match &model_field.field_type {
                                        FieldType::Array(e)| FieldType::Entity(e) => {
                                            if !e.eq(&entity.name){
                                                return Err(Error::InvalidQuery(format!(
                                                    "field: '{}' in entity '{}' is not referencing entity '{}'. It is referencing the entity: '{}'",
                                                    &ref_field, &ref_entity_name, &entity.name, e
                                                ))) 
                                            }
                                        }
                                        _=>{
                                            return Err(Error::InvalidQuery(format!(
                                                "field: '{}' in entity: '{}' is not referencing external entities. Its field type is '{}' ",
                                                &ref_field, &ref_entity_name, model_field.field_type 
                                            ))) 
                                        }
                                    }
                                    let mut target_entity =  EntityQuery::new();
                                    target_entity.name = ref_entity_name.to_string();
        
                                    Self::parse_entity_internals(&mut target_entity, data_model, ref_by_pairs, variables)?;

                                    let refby = QueryField{
                                        name,
                                        alias:None,
                                        field_type: QueryFieldType::Function(Function::RefBy(ref_field.to_string(), target_entity))
                                    };
                                    entity.add_field(refby)?;
                                }
                               
                                _=> unreachable!()
                            }
                        }
                        _ => unreachable!()
                    }
                }
                _ => unreachable!()
            }
        }

        Ok(())

    }


    fn parse_entity(
        data_model: &DataModel,
        pair: Pair<'_, Rule>,
        variables: &mut Variables,
    ) -> Result<EntityQuery, Error> {
        let mut entity = EntityQuery::new();

        let mut entity_pairs =  pair.into_inner();
        let mut  name_pair = entity_pairs.next().unwrap().into_inner();
        let name;
        if name_pair.len() == 2 {
            let alias = name_pair.next().unwrap().as_str().to_string();
            entity.alias = Some(alias);
            name = name_pair.next().unwrap().as_str().to_string();
        } else {
            name = name_pair.next().unwrap().as_str().to_string();
        }
        data_model.get_entity(&name)?;
        entity.name = name;

        Self::parse_entity_internals(&mut entity,data_model, entity_pairs,variables)?;

        Ok(entity)
    }

    fn parse_params(
        entity: &Entity,
        pair: Pair<'_, Rule>,
        variables: &mut Variables,
    ) -> Result<EntityParams, Error> {
        let mut parameters = EntityParams::new();
        let param_pairs = pair.into_inner();
        for param_pair in param_pairs {
            let pair = param_pair.into_inner().next().unwrap();
            match pair.as_rule() {
                Rule::filter => {
                    let filter = Self::parse_filter(pair, entity, variables)?;
                    parameters.filters.push(filter)
                }
                Rule::order_by => {
                    let order_pairs = pair.into_inner();
                    for order_pair in order_pairs {
                        let mut order_p = order_pair.into_inner();
                        let name = order_p.next().unwrap().as_str();
                        let field = entity.get_field(name)?;
                        match field.field_type{
                            FieldType::Array(_) | FieldType::Entity(_) => {
                                return Err(Error::InvalidQuery(format!(
                                    "Only scalar fields are allowed in order by clause. '{}' is a '{}'",
                                    &name, &field.field_type
                                )))
                            }
                            _ => {} 
                        }

                        let direction = order_p.next().unwrap().as_str();
                        parameters.order_by.push((name.to_string(), direction.to_string()));
                    }
                }
                Rule::limit => {
                    let val = pair.into_inner().next().unwrap().into_inner().next().unwrap();
                    match val.as_rule(){
                        Rule::variable => {
                            let var = &val.as_str()[1..];
                            variables.add(var.to_string(), VariableType::Integer(false))?;
                            parameters.limit = FieldValue::Variable(var.to_string());

                        }
                        Rule::unsigned_int => {
                            let value = val.as_str();
                            parameters.limit = FieldValue::Value(Value::Integer(value.parse()?));
                        }
                        _=> unreachable!()
                    }
                }

                Rule::skip => {
                    let val = pair.into_inner().next().unwrap().into_inner().next().unwrap();
                    match val.as_rule(){
                        Rule::variable => {
                            let var = &val.as_str()[1..];
                            variables.add(var.to_string(), VariableType::Integer(false))?;
                            parameters.skip = Some(FieldValue::Variable(var.to_string()));

                        }
                        Rule::unsigned_int => {
                            let value = val.as_str();
                            parameters.skip = Some(FieldValue::Value(Value::Integer(value.parse()?)));
                        }
                        _=> unreachable!()
                    }
                }


                Rule::search => {
                    let val = pair.into_inner().next().unwrap().into_inner().next().unwrap();
                    match val.as_rule(){
                        Rule::variable => {
                            let var = &val.as_str()[1..];
                            variables.add(var.to_string(), VariableType::String(false))?;
                            parameters.fulltext_search = Some(FieldValue::Variable(var.to_string()));

                        }
                        Rule::string => {
                            let value = val.into_inner().next().unwrap().as_str();
                            parameters.fulltext_search = Some(FieldValue::Value(Value::String(value.to_string())));
                        }
                        _=> unreachable!()
                    }
                }

                Rule::before => {
                    let val = pair.into_inner().next().unwrap().into_inner().next().unwrap();
                    match val.as_rule(){
                        Rule::variable => {
                            let var = &val.as_str()[1..];
                            variables.add(var.to_string(), VariableType::Hex(false))?;
                            parameters.before = Some(FieldValue::Variable(var.to_string()));

                        }
                        Rule::string => {
                            let value = val.into_inner().next().unwrap().as_str();
                            Self::validate_hex(value, "Before")?;
                            parameters.before = Some(FieldValue::Value(Value::String(value.to_string())));
                        }
                        _=> unreachable!()
                    }
                }

                Rule::after => {
                    let val = pair.into_inner().next().unwrap().into_inner().next().unwrap();
                    match val.as_rule(){
                        Rule::variable => {
                            let var = &val.as_str()[1..];
                            variables.add(var.to_string(), VariableType::Hex(false))?;
                            parameters.after = Some(FieldValue::Variable(var.to_string()));

                        }
                        Rule::string => {
                            let value = val.into_inner().next().unwrap().as_str();
                            Self::validate_hex(value, "After")?;
                            parameters.after = Some(FieldValue::Value(Value::String(value.to_string())));
                        }
                        _=> unreachable!()
                    }
                }


                _ => unreachable!(),
                
            }
        }

        Ok(parameters)
    }

    fn parse_filter(
        pair: Pair<'_, Rule>,
        entity: &Entity,
        variables: &mut Variables,
    ) -> Result<FilterParam, Error> {
        let mut filter_pairs = pair.into_inner();

        let name = filter_pairs.next().unwrap().as_str().to_string();

        let field = entity.get_field(&name)?;

        match field.field_type {
            FieldType::Array(_) | FieldType::Entity(_) => {
                return Err(Error::InvalidQuery(format!(
                    "Only scalar fields are allowed in filters. '{}' is a '{}'",
                    &name, &field.field_type
                )))
            }
            _ => {}
        }
        let operation = filter_pairs.next().unwrap().as_str().to_string();

        let value_pair = filter_pairs.next().unwrap().into_inner().next().unwrap();
        let value = match value_pair.as_rule() {
            Rule::boolean => match field.field_type {
                FieldType::Boolean => {
                    let value_str = value_pair.as_str();
                    FieldValue::Value(Value::Boolean(value_str.parse()?))
                }
                _ => {
                    return Err(Error::InvalidFieldType(
                        name.to_string(),
                        field.field_type.to_string(),
                        "Boolean".to_string(),
                    ))
                }
            },
            Rule::float => match field.field_type {
                FieldType::Float => {
                    let value_str = value_pair.as_str();
                    FieldValue::Value(Value::Float(value_str.parse()?))
                }
                _ => {
                    return Err(Error::InvalidFieldType(
                        name.to_string(),
                        field.field_type.to_string(),
                        "Float".to_string(),
                    ))
                }
            },
            Rule::integer => match field.field_type {
                FieldType::Float => {
                    let value_str = value_pair.as_str();
                    FieldValue::Value(Value::Float(value_str.parse()?))
                }
                FieldType::Integer => {
                    let value_str = value_pair.as_str();
                    FieldValue::Value(Value::Integer(value_str.parse()?))
                }
                _ => {
                    return Err(Error::InvalidFieldType(
                        name.to_string(),
                        field.field_type.to_string(),
                        "Integer".to_string(),
                    ))
                }
            },
            Rule::null => {
                if field.nullable {
                    FieldValue::Value(Value::Null)
                } else {
                    return Err(Error::NotNullable(name.clone()));
                }
            }
            Rule::string => {
                let value_str = value_pair.into_inner().next().unwrap().as_str();
                match field.field_type {
                    FieldType::String => FieldValue::Value(Value::String(value_str.to_string())),
                    FieldType::Hex => {
                        Self::validate_hex(value_str, &name)?;
                        FieldValue::Value(Value::String(value_str.to_string()))
                    }
                    _ => {
                        return Err(Error::InvalidFieldType(
                            name.to_string(),
                            field.field_type.to_string(),
                            "String".to_string(),
                        ))
                    }
                }
            }
            Rule::variable => {
                let var = &value_pair.as_str()[1..];
                let var_type = field.get_variable_type();
                variables.add(var.to_string(), var_type)?;
                FieldValue::Variable(var.to_string())
            }

            _ => unreachable!(), 
        };

        Ok(FilterParam {
            name,
            operation,
            value,
        })
    }

    fn validate_hex(var: &str, name: &str) -> Result<(), Error> {
        if hex::decode(var).is_err() {
            return Err(Error::InvalidQuery(format!(
                "'{}' value '{}' is not a valid hexadecimal ",
                &name, var
            )));
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use crate::database::query_language::data_model::DataModel;

    use super::*;
    #[test]
    fn parse_valid_mutation() {
        let data_model = DataModel::parse(
            "
            Person {
                name : String,
                surname : String,
                parents : [Person],
                pet : Pet,
                age : Integer,
                weight : Float,
                is_human : Boolean
            }

            Pet {
                name : String ,
                age : Integer
            }
        
        ",
        )
        .unwrap();

        let _query = Query::parse(
            r#"
            query aquery {
                Person (
                    search("a search string"),
                    is_human = true, 
                    age >= $age,
                    order_by(surname asc, name desc ),
                    limit $limit,
                    skip 2,
                    before "121212",
                    after $id_person,
                ){
                    a_name:name 
                    surname 
                    parents {
                       age
                       pet {
                            name
                       }
                    }
                    age
                    weight
                    pet {
                        name
                    }
                }

                PetAndOwner : Pet (id = $id) {
                    name 

                    asum: sum(age)
                    coun: count()

                    owner: ref_by(
                        pet, 
                        Person{
                            name
                            surname
                        })
                }
            }
        "#,
            &data_model,
        )
        .unwrap();

        println!("{:#?}", _query);
    }
}
