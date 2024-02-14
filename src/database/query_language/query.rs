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
    EntityQuery(Box<EntityQuery>)
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
    RefBy(String,Box<EntityQuery>)
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
impl Default for EntityParams{
    fn default() -> Self {
        EntityParams::new()
    }
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
    depth: usize,
    complexity: usize,
    params: Option<EntityParams>,
    fields: HashMap<String, QueryField>,
}
impl Default for EntityQuery{
    fn default() -> Self {
        EntityQuery::new()
    }
}
impl EntityQuery {
    pub fn new() -> Self {
        Self {
            name: "".to_string(),
            alias: None,
            depth: 0,
            complexity: 0,
            params: None,
            fields: HashMap::new(),
        }
    }

    #[allow(clippy::map_entry)]
    pub fn add_field(&mut self, field:QueryField) -> Result<(),Error> {
        let key =
        if field.alias.is_some(){
            field.alias.clone().unwrap()
        } else{
            field.name.clone()
        };

        
        if self.fields.contains_key(&key){
            return Err(Error::DuplicatedField(key))
        } else {
            self.fields.insert(key, field);
        }
        
        Ok(())
    }

    pub fn aliased_name(&self) -> String{
        if self.alias.is_some(){
            self.alias.clone().unwrap()
        } else{
            self.name.clone()
        }
    }

    pub fn check_consistency(&self) -> Result<(), Error>{
        if let Some(par) = &self.params{
            if par.after.is_some() && par.before.is_some(){
                return Err(Error::InvalidQuery(format!(
                    "'after' and 'before' filters cannot be used at the same time in query '{}'",
                    self.aliased_name()
                )))
            }
        }
        let mut has_entity_field = false;
        let mut has_aggregate_function = false;

        for field in  &self.fields  {
            let ftype = &field.1.field_type;
            match ftype {
                QueryFieldType::EntityQuery(_)=>{has_entity_field = true}
                QueryFieldType::Function(f)=>{
                    match f {
                      Function::RefBy(_,_ ) => has_entity_field = true,
                      _=>  has_aggregate_function = true
                    }

                }
                QueryFieldType::NamedField=>{}
                
            }
        }
        
        if has_entity_field && has_aggregate_function{
            return Err(Error::InvalidQuery(format!(
                "when using aggregate functions, you cannot select entity fields of ref_by() function in the same sub-entity selection current entity '{}'",
                self.aliased_name()
            )))
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
impl Default for Query{
    fn default() -> Self {
        Query::new()
    }
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

        if parse.as_rule() == Rule::query  {
            let mut query_pairs = parse.into_inner();

            let query_type = query_pairs.next().unwrap();
            match query_type.as_str() {
                "query" => query.query_type = QueryType::Query,
                "subscription" => query.query_type = QueryType::Subscription,
                _ => unreachable!(),
            }

            query.name = query_pairs.next().unwrap().as_str().to_string();

            for entity_pair in query_pairs {
                match entity_pair.as_rule() {
                    Rule::entity => {
                        let ent =
                            Self::parse_entity(data_model, entity_pair, &mut query.variables)?;

                        if let Some(al) = &ent.alias{
                            if data_model.get_entity(al).is_ok(){
                                return Err(Error::InvalidQuery(format!(
                                    "Query alias '{}' is conflicting with a data model entity with the same name",
                                    al
                                )))
                            }
                        }

                        let alias = ent.aliased_name();
                        let exists = query.queries.iter().any(|x| x.aliased_name().eq(&alias)); 
                        if exists {
                            return Err(Error::InvalidQuery(format!(
                                "Query name or alias '{}' is allready defined",
                                alias
                            )))
                        }
                        query.queries.push(ent);
                    }
                    Rule::EOI => {}
                    _ => unreachable!(),
                }
            }
        }
            
        Ok(query)
    }


    fn parse_entity_internals(
        entity: &mut EntityQuery,
        data_model: &DataModel,
        pairs: Pairs<'_, Rule>,
        variables: &mut Variables,
    ) -> Result<(), Error> {
        let depth = entity.depth;
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
                            let model_entity = data_model.get_entity(&entity.name)?;
                            let mut name_pair = field_pair.into_inner();
                            let name;
                            let alias;
                            if name_pair.len() == 2 {
                                let alias_name = name_pair.next().unwrap().as_str();
                                if model_entity.get_field(alias_name).is_ok(){
                                    return Err(Error::InvalidQuery(format!(
                                        "alias: '{}' is conflicting with a field name in entity:'{}'",
                                        &alias_name, &entity.name
                                    )))
                                }
                                alias = Some(alias_name.to_string());
                                name = name_pair.next().unwrap().as_str().to_string();
                            } else {
                                name = name_pair.next().unwrap().as_str().to_string();
                                alias = None;
                            }

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
                                let alias_name = name_pair.next().unwrap().as_str();
                                if model_entity.get_field(alias_name).is_ok(){
                                    return Err(Error::InvalidQuery(format!(
                                        "alias: '{}' is conflicting with a field name in entity:'{}'",
                                        &alias_name, &entity.name
                                    )))
                                }
                                alias = Some(alias_name.to_string());
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
                            target_entity.depth = depth + 1;

                            Self::parse_entity_internals(&mut target_entity, data_model, entity_pairs, variables)?;
                            
                            entity.complexity += target_entity.complexity + 1;

                            if entity.depth < target_entity.depth {
                                entity.depth = target_entity.depth
                            }
                            
                            let named = QueryField{
                                name,
                                alias,
                                field_type: QueryFieldType::EntityQuery(Box::new(target_entity))
                            };
                            entity.add_field(named)?;
                        }
                        Rule::function => {
                            let query_field =  Self::parse_functions(depth, entity, data_model,field_pair, variables)?;
                            entity.add_field(query_field)?;
                        }
                        _ => unreachable!()
                    }
                }
                _ => unreachable!()
            }
        }
        entity.check_consistency()?;
        Ok(())

    }


    fn parse_functions(  
        depth: usize,
        entity: &mut EntityQuery,
        data_model: &DataModel,
        field_pair: Pair<'_, Rule>,
        variables: &mut Variables,) -> Result<QueryField, Error>{

        let mut function_pairs = field_pair.into_inner();
        let name = function_pairs.next().unwrap().as_str().to_string();
        
        let function_pair =  function_pairs.next().unwrap().into_inner().next().unwrap();

        let model_entity = data_model.get_entity(&entity.name)?;
       
        let query_field =  match function_pair.as_rule() {
            Rule::count_fn => {
                QueryField{
                    name,
                    alias:None,
                    field_type: QueryFieldType::Function(Function::Count)
                }
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
               QueryField{
                    name,
                    alias:None,
                    field_type: QueryFieldType::Function(Function::Avg(param.to_string()))
                }
            }
            Rule::max_fn => {
                let param = function_pair.into_inner().next().unwrap().as_str();
                let model_field = model_entity.get_field(param)?;
                match model_field.field_type{
                    FieldType::Array(_) | FieldType::Entity(_) => {
                        return Err(Error::InvalidQuery(format!(
                            "max({}) requires a scalar field and '{}' is a '{}'",
                            &param, &param, model_field.field_type
                        ))) 
                    }
                    _=> {}
                }
               QueryField{
                    name,
                    alias:None,
                    field_type: QueryFieldType::Function(Function::Max(param.to_string()))
                }
            }
            Rule::min_fn => {
                let param = function_pair.into_inner().next().unwrap().as_str();
                let model_field = model_entity.get_field(param)?;
                match model_field.field_type{
                    FieldType::Array(_) | FieldType::Entity(_) => {   
                        return Err(Error::InvalidQuery(format!(
                        "min({}) requires a scalar field and '{}' is a '{}'",
                        &param, &param, model_field.field_type
                    ))) }
                    _=> {}
                }

                QueryField{
                    name,
                    alias:None,
                    field_type: QueryFieldType::Function(Function::Min(param.to_string()))
                }
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
                    ))) }
                }
                QueryField{
                    name,
                    alias:None,
                    field_type: QueryFieldType::Function(Function::Sum(param.to_string()))
                }

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
                target_entity.depth = depth + 1;

                Self::parse_entity_internals(&mut target_entity, data_model, ref_by_pairs, variables)?;

                entity.complexity += target_entity.complexity + 1;

                if entity.depth < target_entity.depth {
                    entity.depth = target_entity.depth
                }

                QueryField{
                    name,
                    alias:None,
                    field_type: QueryFieldType::Function(Function::RefBy(ref_field.to_string(), Box::new(target_entity)))
                }
            }
           
            _=> unreachable!()
        };
        Ok(query_field)
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
            name = name_pair.next().unwrap().as_str().to_string();
        

            entity.alias = Some(alias);
        
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
                Person(
                    search("a search string"),
                    name = "someone",
                    is_human = true, 
                    age >= 1,
                    weight <= 200,
                    order_by(surname asc, name desc ),
                    limit 30,
                    skip 2,
                    before "A21212",
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


                Parametrized : Person (
                    search($search),
                    name = $name,
                    is_human = $human, 
                    age >= $age,
                    weight <= $weight,
                    order_by(surname asc, name desc ),
                    limit $limit,
                    skip $skip,
                    after $after_id,
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

                Pet () {
                    name 
                    asum: sum( age )
                    avg: avg(age)
                    min: min(age)
                    max : max(age)
                    count: count()
                }

                PetAndOwner : Pet (id=$id) {
                    name 
                    owner: ref_by(
                        pet, 
                        Person{
                            name
                            surname
                        }
                    )
                }

            }
        "#,
            &data_model,
        )
        .unwrap();

       // println!("{:#?}", _query);
    }

    #[test]
    fn query_depth() {
        let data_model = DataModel::parse(
            "
            Person {
                name : String,
                parents : [Person],
            }        
        ",
        )
        .unwrap();

        let query = Query::parse(
            r#"
            query aquery {
                Person {
                    name 
                   
                }
            } "#,
            &data_model,
        )
        .unwrap();
        assert_eq!(0, query.queries[0].depth);

        let query = Query::parse(
            r#"
            query aquery {
                Person {
                    name 
                    parents{
                        name
                    }
                }
            } "#,
            &data_model,
        )
        .unwrap();
        assert_eq!(1, query.queries[0].depth);
        

        let query = Query::parse(
            r#"
            query aquery {
                Person {
                    name 
                    aliased : parents {
                        name
                        parents {
                            name
                        }
                    }
                    parents {
                        name
                    }
                }
            } "#,
            &data_model,
        )
        .unwrap();
        assert_eq!(2, query.queries[0].depth);


        let query = Query::parse(
            r#"
            query aquery {
                Person {
                    name 
                    parents {
                        name
                    }
                    children : ref_by(parents, Person {
                        name
                        parents {
                            name
                        }
                    })
                }
            } "#,
            &data_model,
        )
        .unwrap();
        assert_eq!(2, query.queries[0].depth);
        
    }

    #[test]
    fn query_complexity() {
        let data_model = DataModel::parse(
            "
            Person {
                name : String,
                parents : [Person],
            }        
        ",
        )
        .unwrap();

        let query = Query::parse(
            r#"
            query aquery {
                Person {
                    name 
                }
            } "#,
            &data_model,
        )
        .unwrap();
        assert_eq!(0, query.queries[0].complexity);

        let query = Query::parse(
            r#"
            query aquery {
                Person {
                    name 
                    parents{
                        name
                    }
                }
            } "#,
            &data_model,
        )
        .unwrap();
        assert_eq!(1, query.queries[0].complexity);
        

        let query = Query::parse(
            r#"
            query aquery {
                Person {
                    name 
                    aliased : parents {
                        name
                        parents {
                            name
                        }
                    }
                    parents {
                        name
                    }
                }
            } "#,
            &data_model,
        )
        .unwrap();
        assert_eq!(3, query.queries[0].complexity);

        let query = Query::parse(
            r#"
            query aquery {
                Person {
                    name 
                    aliased : parents {
                        name
                        parents {
                            name
                        }
                    }
                    parents {
                        name
                    }
                    children : ref_by(parents, Person {
                        name
                        parents {
                            name
                        }
                    })
                }
            } "#,
            &data_model,
        )
        .unwrap();
        assert_eq!(5, query.queries[0].complexity);
        
    }


    #[test]
    fn duplicated_field_and_aliases() {
        let data_model = DataModel::parse(
            "
            Person {
                name : String,
                age : Integer,
                parents : [Person],
            }        
        ",
        )
        .unwrap();

        let _query = Query::parse(
            r#"
            query aquery {
                Person {
                    name 
                    name
                }
            } "#,
            &data_model,
        )
        .expect_err("name is defined twice ");

        let _query = Query::parse(
            r#"
            query aquery {
                Person {
                    aname : name 
                    aname : name
                }
            } "#,
            &data_model,
        )
        .expect_err("aname is defined twice ");


        let _query = Query::parse(
            r#"
            query aquery {
                Person {
                    name 
                    aname : name
                }
            } "#,
            &data_model,
        )
        .expect("name is correctly aliased ");


        let _query = Query::parse(
            r#"
            query aquery {
                Person {
                    name 
                }
                Person {
                    name 
                }
            } "#,
            &data_model,
        )
        .expect_err("Person is defined twice ");

        let _query = Query::parse(
            r#"
            query aquery {
                Person {
                    name 
                }
                Aperson: Person {
                    name 
                }
            } "#,
            &data_model,
        )
        .expect("Person is correctly aliased ");
        
    }

    
    #[test]
    fn function() {
        let data_model = DataModel::parse(
            "
            Person {
                name : String,
                age : Integer,
                parents : [Person],
            }        
        ",
        )
        .unwrap();

        let _query = Query::parse(
            r#"
            query aquery {
                Person {
                    name 
                    fn : avg(name)
                }
            } "#,
            &data_model,
        )
        .expect_err("avg can only be done on Integer or float ");


        let _query = Query::parse(
            r#"
            query aquery {
                Person {
                    name 
                    fn : avg(age)
                }
            } "#,
            &data_model,
        )
        .expect("avg is valid");



        let _query = Query::parse(
            r#"
            query aquery {
                Person {
                    name 
                    fn : sum(name)
                }
            } "#,
            &data_model,
        )
        .expect_err("sum can only be done on Integer or float ");


        let _query = Query::parse(
            r#"
            query aquery {
                Person {
                    name 
                    fn : sum(age)
                }
            } "#,
            &data_model,
        )
        .expect("sum is valid");


        let _query = Query::parse(
            r#"
            query aquery {
                Person {

                    name 
                    fn : min(parents)
                }
            } "#,
            &data_model,
        )
        .expect_err("min can only be done on scalar field");


        let _query = Query::parse(
            r#"
            query aquery {
                Person {
                    age 
                    fn : min(name)
                }
            } "#,
            &data_model,
        )
        .expect("strange but valid");
       

        
        let _query = Query::parse(
            r#"
            query aquery {
                Person {
                    name 
                    fn : max(parents)
                }
            } "#,
            &data_model,
        )
        .expect_err("min can only be done on scalar field");


        let _query = Query::parse(
            r#"
            query aquery {
                Person {
                    age 
                    fn : max(name)
                }
            } "#,
            &data_model,
        )
        .expect("strange but valid");


        let _query = Query::parse(
            r#"
            query aquery {
                Person {
                    age 
                    fn : max(not_exist)
                }
            } "#,
            &data_model,
        )
        .expect_err("field does not exists");


        let _query = Query::parse(
            r#"
            query aquery {
                Person {
                    parents{
                        name
                    } 
                    fn : count()
                }
            } "#,
            &data_model,
        )
        .expect_err("when a function is used, 'entity' sub query is not allowed");

        let _query = Query::parse(
            r#"
            query aquery {
                Person {
                    age 
                    fn : count()
                }
            } "#,
            &data_model,
        )
        .expect("count wil be grouped by age");
       

        let _query = Query::parse(
            r#"
            query aquery {
                Person {
                    fn : count()
                    children : ref_by(parents, Person{
                        name
                    })
                }
            } "#,
            &data_model,
        )
        .expect_err("when an aggregate function is used, 'entity' sub query is not allowed and ref_by(..) is a sub_query ");

        let _query = Query::parse(
            r#"
            query aquery {
                Person {
                    parents{
                        name
                    } 
                    children : ref_by(parents, Person{
                        name
                    })
                }
            } "#,
            &data_model,
        )
        .expect("ref_by(..) is not an aggregate function and accepts others sub queries");
        
    }

    #[test]
    fn ref_by() {
        let data_model = DataModel::parse(
            "
            Person {
                name : String,
                age : Integer,
                parents : [Person],
                pets : [Pet],
                someone : Person
            } 

            Pet {
                name: String
            }
        ",
        )
        .unwrap();

        let _query = Query::parse(
            r#"
            query aquery {
                Person {
                    children : ref_by(age, Person{
                        name
                    })
                }
            } "#,
            &data_model,
        )
        .expect_err("ref_by(..) is not referencing an entity");

        let _query = Query::parse(
            r#"
            query aquery {
                Person {
                    children : ref_by(pets, Person{
                        name
                    })
                }
            } "#,
            &data_model,
        )
        .expect_err("ref_by(..) field pets is not referencing a Person");

        let _query = Query::parse(
            r#"
            query aquery {
                Person {
                    some : ref_by(someone, Person{
                        name
                    })
                    children : ref_by(parents, Person{
                        name
                    })
                }
            } "#,
            &data_model,
        )
        .expect("ref_by(..) is correct ");


    }

    #[test]
    fn aliases() {
        let data_model = DataModel::parse(
            "
            Person {
                name : String,
                age : Integer,
                parents : [Person],
                pets : [Pet],
                someone : Person
            } 

            Pet {
                name: String
            }
        ",
        )
        .unwrap();

        let _query = Query::parse(
            r#"
            query aquery {
                Person {
                    name
                }

                Pet: Person {
                    name
                }

            } "#,
            &data_model,
        )
        .expect_err("alias is conflicting with the Pet entity");

        let _query = Query::parse(
            r#"
            query aquery {
                Person {
                    name
                    someone : name
                }

            } "#,
            &data_model,
        )
        .expect_err("alias is conflicting with the someone field");

        
        let _query = Query::parse(
            r#"
            query aquery {
                Person {
                    name : someone{name}
                }

            } "#,
            &data_model,
        )
        .expect_err("alias is conflicting with the name field");

        let _query = Query::parse(
            r#"
            query aquery {
                Person {
                    aname : someone{name}
                }

            } "#,
            &data_model,
        )
        .expect("alias is not conflicting");

    }

    #[test]
    fn entity_field() {
        let data_model = DataModel::parse(
            "
            Person {
                parents : [Person],
                someone : Person
            } 

        ",
        )
        .unwrap();

        let _query = Query::parse(
            r#"
            query aquery {
                Person {
                    parents
                }
            } "#,
            &data_model,
        )
        .expect_err("parents must be used with syntax parents{..}");

        let _query = Query::parse(
            r#"
            query aquery {
                Person {
                    someone
                }
            } "#,
            &data_model,
        )
        .expect_err("someone must be used with syntax someone{..}");

        let _query = Query::parse(
            r#"
            query aquery {
                Person {
                    parents{id}
                    someone{id}
                }
            } "#,
            &data_model,
        )
        .expect("good syntax");


    }


    #[test]
    fn filters() {
        let data_model = DataModel::parse(
            "
            Person {
                name : String,
                age : Integer,
                weight : Float,
                parents : [Person],
                someone : Person
            } 

        ",
        )
        .unwrap();

        let _query = Query::parse(
            r#"
            query aquery {
                Person (parents > 0) {
                    name
                }
            } "#,
            &data_model,
        )
        .expect_err("non scalar field cannot be used in filters");

        let _query = Query::parse(
            r#"
            query aquery {
                Person (someone > 0) {
                    name
                }
            } "#,
            &data_model,
        )
        .expect_err("non scalar field cannot be used in filters");

        let _query = Query::parse(
            r#"
            query aquery {
                Person (aage > 10) {
                    name
                }
            } "#,
            &data_model,
        )
        .expect_err("aage does not exists");

        let _query = Query::parse(
            r#"
            query aquery {
                Person (age > 10.5) {
                    name
                }
            } "#,
            &data_model,
        )
        .expect_err("age is not a float");

        let _query = Query::parse(
            r#"
            query aquery {
                Person (weight > 10) {
                    name
                }
            } "#,
            &data_model,
        )
        .expect("weight is a float and integer value will be cast as float");

        let _query = Query::parse(
            r#"
            query aquery {
                Person (age > 10) {
                    name
                }
            } "#,
            &data_model,
        )
        .expect("age is an integer");



    }

}
