use crate::{base64_decode, database::query_language::VariableType};

use super::{
    data_model::{DataModel, Entity, Field},
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
    Aggregate(Function),
    NamedField,
    BinaryField,
    EntityQuery(Box<EntityQuery>,bool),
    EntityArrayQuery(Box<EntityQuery>, bool), 
}



#[derive(Debug)]
pub struct QueryField{
    pub field: Field,
    pub alias: Option<String>,
    pub field_type:QueryFieldType
} impl QueryField{
    pub fn name(&self) -> String{
        if self.alias.is_some(){
            self.alias.clone().unwrap()
        } else{
            self.field.name.clone()
        }
    }
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
   pub after: Option<FieldValue>,
   pub before: Option<FieldValue>,
   pub filters: Vec<FilterParam>,
   pub fulltext_search: Option<FieldValue>,
   pub limit: FieldValue,
   pub order_by: Vec<(String, String)>,
   pub skip: Option<FieldValue>,
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
}

#[derive(Debug)]
pub struct FilterParam {
    pub name: String, 
    pub short_name: String, 
    pub operation: String,
    pub value: FieldValue,
    pub filter_type: FilterType
}

#[derive(Debug)]
struct ParsedFilter{
    pub name: String, 
    pub operation: String,
    pub value: String,
    pub parsed_type: ParsedType
}
#[derive(Debug)]
enum ParsedType{
    Boolean,
    Float,
    Integer,
    Null,
    String,
    Variable
}

#[derive(Debug)]
pub enum FilterType{
    Field,
    SystemField,
    EntityField
}

#[derive(Debug)]
pub struct EntityQuery {
    pub name: String,
    pub alias: Option<String>,
    pub short_name: String,
    pub depth: usize,
    pub complexity: usize,
    pub is_aggregate: bool,
    pub params: Option<EntityParams>,
    pub fields: Vec<QueryField>,
}
impl Default for EntityQuery{
    fn default() -> Self {
        EntityQuery::new()
    }
}
impl EntityQuery {
    pub fn new() -> Self {
        Self {
            name: String::from(""),
            alias: None,
            short_name: String::from(""),
            depth: 0,
            complexity: 0,
            is_aggregate:false,
            params: None,
            fields: Vec::new(),
        }
    }

    #[allow(clippy::map_entry)]
    pub fn add_field(&mut self, field:QueryField) -> Result<(),Error> {
        let key =field.name();
        let exist: bool = self.fields.iter().any(|row| row.name().eq(&key));
        if exist{
            return Err(Error::DuplicatedField(key))
        } else {
            self.fields.push(field);
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
            let ftype = &field.field_type;
            match ftype {
                QueryFieldType::EntityQuery(_,_)| QueryFieldType::EntityArrayQuery(_,_)=>{
                    has_entity_field = true
                }
                QueryFieldType::Aggregate(_)=>{
                    has_aggregate_function = true;
                }
                QueryFieldType::Function(f)=>{
                    match f {
                      Function::RefBy(_,_ ) => has_entity_field = true,
                      _=> {} 
                    }
                }
                QueryFieldType::NamedField| QueryFieldType::BinaryField=>{}
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
pub struct QueryParser {
    pub name: String,
    pub query_type: QueryType,
    pub variables: Variables,
    pub queries: Vec<EntityQuery>,
}
impl Default for QueryParser{
    fn default() -> Self {
        QueryParser::new()
    }
}
impl QueryParser {
    pub fn new() -> Self {
        Self {
            name: "".to_string(),
            query_type: QueryType::Query,
            variables: Variables::new(),
            queries: Vec::new(),
        }
    }

    pub fn parse(p: &str, data_model: &DataModel) -> Result<Self, Error> {
        let mut query = QueryParser::new();

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
        let model_entity = data_model.get_entity(&entity.name)?;
        let mut parsed_filters = None;

        let mut parameters = None;
        for entity_pair in pairs {
            match entity_pair.as_rule() {
                Rule::entity_param => {
                    let params = Self::parse_params(model_entity, entity_pair, variables)?;
                    parameters = Some(params.0);
                    parsed_filters = Some(params.1);
                }

                Rule::field => {
                    let field_pair = entity_pair.into_inner().next().unwrap();
                    match field_pair.as_rule() {
                        Rule::named_field => {
                            let mut name_pair = field_pair.into_inner();
                            let name;
                            let alias;
                            if name_pair.len() == 2 {
                                let alias_name = name_pair.next().unwrap().as_str();
                                if alias_name.starts_with('_') {
                                    return Err(Error::InvalidName(alias_name.to_string()));
                                }
                                
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

                            let field_type = match model_field.field_type {
                                FieldType::Array(_) | FieldType::Entity(_) => {
                                   

                                    return Err(Error::InvalidQuery(format!(
                                        "Invalid syntax for non scalar field. please use {}{{ .. }}",
                                        &name
                                    )))
                                }
                                FieldType::Base64 => QueryFieldType::BinaryField,
                                
                                _=>QueryFieldType::NamedField  
                            };
                            

                            let named = QueryField{
                                field:model_field.clone(),
                                alias,
                                field_type
                            };
                            entity.add_field(named)?;

                        }
                       
                        Rule::entity => { 
                            let mut entity_pairs =  field_pair.into_inner();
                            let mut  name_pair = entity_pairs.next().unwrap().into_inner();
                            let name;
                            let alias;
                            if name_pair.len() == 2 {
                                let alias_name = name_pair.next().unwrap().as_str();
                                if alias_name.starts_with('_') {
                                    return Err(Error::InvalidName(alias_name.to_string()));
                                }
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
                            let model_field = model_entity.get_field(&name)?;


                            let taget_entity_name = match &model_field.field_type {
                                FieldType::Array(e) => e,
                                FieldType::Entity(e) => e,  
                                _=>  return Err(Error::InvalidQuery(format!(
                                    "Invalid syntax for scalar field. please use {} without {{ .. }}",
                                    &name
                                ))) 
                            };
                            let mut target_entity =  EntityQuery::new();
                            target_entity.name = taget_entity_name.clone();

                            let target_model_field = data_model.get_entity(&taget_entity_name)?;
                            target_entity.short_name = target_model_field.short_name.clone();
                            target_entity.depth = depth + 1;

                            Self::parse_entity_internals(&mut target_entity, data_model, entity_pairs, variables)?;
                            
                            entity.complexity += target_entity.complexity + 1;

                            if entity.depth < target_entity.depth {
                                entity.depth = target_entity.depth
                            }
                            
                            let field_type =
                                match &model_field.field_type {
                                    FieldType::Array(_) => QueryFieldType::EntityArrayQuery(Box::new(target_entity), model_field.nullable),
                                    FieldType::Entity(_) => QueryFieldType::EntityQuery(Box::new(target_entity), model_field.nullable),  
                                    _=> unreachable!()
                            };

                            let named = QueryField{
                                field:model_field.clone(),
                                alias,
                                field_type: field_type
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

        if let Some(filters) = parsed_filters{
            if let Some(par) = &mut parameters{
                for parse in filters{
                    let param = Self::build_filter(
                        entity,
                        model_entity,
                        variables,
                        parse
                    )?;
                    par.filters.push(param);
                }
            }
        }
        entity.params = parameters;
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
                entity.is_aggregate = true;
                let field = Field {
                    name,
                    is_system: false,
                    field_type: FieldType::String,
                    ..Default::default()
                };
                QueryField{
                    field,
                    alias:None,
                    field_type: QueryFieldType::Aggregate(Function::Count)
                }
            }
            Rule::avg_fn => {
                entity.is_aggregate = true;
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
                let field = Field {
                    name,
                    is_system: false,
                    field_type: FieldType::String,
                    ..Default::default()
                };
                QueryField{
                    field,
                    alias:None,
                    field_type: QueryFieldType::Aggregate(Function::Avg(String::from(&model_field.short_name)))
                }
            }
            Rule::max_fn => {
                entity.is_aggregate = true;
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
                let field = Field {
                    name,
                    is_system: false,
                    field_type: FieldType::String,
                    ..Default::default()
                };
                QueryField{
                    field,
                    alias:None,
                    field_type: QueryFieldType::Aggregate(Function::Max(String::from(&model_field.short_name)))
                }
            }
            Rule::min_fn => {
                entity.is_aggregate = true;
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

                let field = Field {
                    name,
                    is_system: false,
                    field_type: FieldType::String,
                    ..Default::default()
                };
                QueryField{
                    field,
                    alias:None,
                    field_type: QueryFieldType::Aggregate(Function::Min(String::from(&model_field.short_name)))
                }
            }
            Rule::sum_fn => {
                entity.is_aggregate = true;
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
                let field = Field {
                    name,
                    is_system: false,
                    field_type: FieldType::String,
                    ..Default::default()
                };
                QueryField{
                    field,
                    alias:None,
                    field_type: QueryFieldType::Aggregate(Function::Sum(String::from(&model_field.short_name)))
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

                let field = Field {
                    name,
                    is_system: false,
                    field_type: FieldType::String,
                    ..Default::default()
                };
                QueryField{
                    field,
                    alias:None,
                    field_type: QueryFieldType::Function(Function::RefBy(model_field.short_name.to_string(), Box::new(target_entity)))
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
            if alias.starts_with('_') {
                return Err(Error::InvalidName(alias));
            }
            name = name_pair.next().unwrap().as_str().to_string();
        

            entity.alias = Some(alias);
        
        } else {
            name = name_pair.next().unwrap().as_str().to_string();
        }
        let model_entity = data_model.get_entity(&name)?;
        entity.name = name;
        entity.short_name = String::from(&model_entity.short_name);

        Self::parse_entity_internals(&mut entity,data_model, entity_pairs,variables)?;

        Ok(entity)
    }

    fn parse_params(
        entity: &Entity,
        pair: Pair<'_, Rule>,
        variables: &mut Variables,
    ) -> Result<(EntityParams, Vec<ParsedFilter>), Error> {
        let mut parameters = EntityParams::new();
        let param_pairs = pair.into_inner();
        let mut parsed_filter = Vec::new();
        for param_pair in param_pairs {
            let pair = param_pair.into_inner().next().unwrap();
            match pair.as_rule() {
                Rule::filter => {
                    let filter = Self::parse_filter(pair);
                    parsed_filter.push(filter);
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
                            variables.add(var.to_string(), VariableType::Base64(true))?;
                            parameters.before = Some(FieldValue::Variable(var.to_string()));

                        }
                        Rule::string => {
                            let value = val.into_inner().next().unwrap().as_str();
                            Self::validate_base64(value, "Before")?;
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
                            variables.add(var.to_string(), VariableType::Base64(true))?;
                            parameters.after = Some(FieldValue::Variable(var.to_string()));

                        }
                        Rule::string => {
                            let value = val.into_inner().next().unwrap().as_str();
                            Self::validate_base64(value, "After")?;
                            parameters.after = Some(FieldValue::Value(Value::String(value.to_string())));
                        }
                        _=> unreachable!()
                    }
                }


                _ => unreachable!(),
                
            }
        }

        Ok((parameters, parsed_filter))
    }

    fn parse_filter(
        pair: Pair<'_, Rule>,
    ) -> ParsedFilter {
        let mut filter_pairs = pair.into_inner();

        let name = filter_pairs.next().unwrap().as_str().to_string();

        let operation_pair =  filter_pairs.next().unwrap();
        let mut operation = operation_pair.as_str().to_string();
        
        match operation_pair.as_rule(){
            Rule::is => operation = String::from("is"),
            Rule::is_not => operation = String::from("is not"),
           _=> {}
        };
        let value_pair = filter_pairs.next().unwrap().into_inner().next().unwrap();

         match value_pair.as_rule(){
            Rule::boolean => {
                let value = value_pair.as_str().to_string();
                ParsedFilter{ name, operation, value ,parsed_type: ParsedType::Boolean}
            }
            Rule::float => {
                let value = value_pair.as_str().to_string();
                ParsedFilter{ name, operation, value ,parsed_type: ParsedType::Float}
            }
            Rule::integer => {
                let value = value_pair.as_str().to_string();
                ParsedFilter{ name, operation, value ,parsed_type: ParsedType::Integer}
            }
            Rule::null => {
                let value = value_pair.as_str().to_string();
                ParsedFilter{ name, operation, value ,parsed_type: ParsedType::Null}
            }
            Rule::string => {
                let value = value_pair.into_inner().next().unwrap().as_str().to_string();
                ParsedFilter{ name, operation, value ,parsed_type: ParsedType::String}
            }
            Rule::variable => {
                let value = value_pair.as_str().to_string();
                ParsedFilter{ name, operation, value ,parsed_type: ParsedType::Variable}
            }
            _=>unreachable!()
        }
    }


    fn build_filter(
        entity: &EntityQuery,
        entity_model: &Entity,
        variables: &mut Variables,
        parsed_filters: ParsedFilter
    ) -> Result<FilterParam, Error> {
        
        let is_entity_and_field = match entity_model.get_field(&parsed_filters.name) {
            Ok(field) => {
                match field.field_type {
                    FieldType::Array(_)|FieldType::Entity(_)  => (true, field, String::from(&field.name)),
                    _ => (false, field, String::from(&field.name)),
                }

            },
            Err(_) => {
                let e = entity.fields.iter().find(|entry| entry.name().eq(&parsed_filters.name));
                match e {
                    Some(query_field) => {
                        match query_field.field.field_type {
                            FieldType::Array(_)|FieldType::Entity(_)  => (true, &query_field.field, query_field.name()),
                            _ => (false, &query_field.field, query_field.name()),
                        }
                    },
                    None => return Err(Error::InvalidQuery(format!("filter field '{}' does not exists", &parsed_filters.name))),
                }
            },
        };
        let is_entity_field = is_entity_and_field.0;
        if is_entity_field{
            match parsed_filters.operation.as_str(){
                "is" | "is not" => {}
                _ => 
                return Err(Error::InvalidEntityFilter(
                    String::from(&parsed_filters.name)
                ))
            }
        }
       
        let parsed_value = &parsed_filters.value;
        let field =  is_entity_and_field.1;
        let name = is_entity_and_field.2;

        let value = match parsed_filters.parsed_type {
            ParsedType::Boolean => {
                if is_entity_field{
                    return Err(Error::InvalidEntityFilter(
                        name
                    ))
                }
                
                match field.field_type {
                    FieldType::Boolean => {
                
                        FieldValue::Value(Value::Boolean(parsed_value.parse()?))
                    }
                    _ => {
                        return Err(Error::InvalidFieldType(
                            name,
                            field.field_type.to_string(),
                            "Boolean".to_string(),
                        ))
                    }
                }
            },
            ParsedType::Float =>{
                    if is_entity_field{
                        return Err(Error::InvalidEntityFilter(
                            name,
                        ))
                    } 
                    
                    match field.field_type {
                    FieldType::Float => {
                        FieldValue::Value(Value::Float(parsed_value.parse()?))
                    }
                    _ => {
                        return Err(Error::InvalidFieldType(
                            name,
                            field.field_type.to_string(),
                            "Float".to_string(),
                        ))
                    }
                }
            },
            ParsedType::Integer => {
                    if is_entity_field{
                        return Err(Error::InvalidEntityFilter(
                            name,
                        ))
                    }
                    
                    match field.field_type {
                        FieldType::Float => {
                            FieldValue::Value(Value::Float(parsed_value.parse()?))
                        }
                        FieldType::Integer => {
                            FieldValue::Value(Value::Integer(parsed_value.parse()?))
                        }
                        _ => {
                            return Err(Error::InvalidFieldType(
                                name,
                                field.field_type.to_string(),
                                "Integer".to_string(),
                            ))
                    }
                }
            },
            ParsedType::Null => {
                if field.nullable {
                    FieldValue::Value(Value::Null)
                } else {
                    return Err(Error::NotNullable(name));
                }
            }
            ParsedType::String => {
                if is_entity_field{
                    return Err(Error::InvalidEntityFilter(
                        name
                    ))
                }
               
                match field.field_type {
                    FieldType::String => FieldValue::Value(Value::String(parsed_value.to_string())),
                    FieldType::Base64 => {
                        Self::validate_base64(parsed_value, &name)?;
                        FieldValue::Value(Value::String(parsed_value.to_string()))
                    }
                    _ => {
                        return Err(Error::InvalidFieldType(
                            name,
                            field.field_type.to_string(),
                            "String".to_string(),
                        ))
                    }
                }
            }
            ParsedType::Variable => {
                if is_entity_field{
                    return Err(Error::InvalidEntityFilter(
                        String::from(name)
                    ))
                }
                let var = &parsed_value.as_str()[1..];
                let var_type = field.get_variable_type();
                variables.add(var.to_string(), var_type)?;
                FieldValue::Variable(var.to_string())
            }
        };
        let filter_type = {
            if is_entity_field{
                FilterType::EntityField
            } else if field.is_system {
                FilterType::SystemField
            }else {
                FilterType::Field
            }
        };
        Ok(FilterParam {
            name: name,
            short_name:String::from(&field.short_name),
            operation: String::from(&parsed_filters.operation),
            value,
            filter_type
        })
    }

    fn validate_base64(var: &str, name: &str) -> Result<(), Error> {
        if base64_decode(var.as_bytes()).is_err() {
            return Err(Error::InvalidQuery(format!(
                "'{}' value '{}' is not a valid base64 string ",
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
    fn parse_valid_query() {
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

        let _query = QueryParser::parse(
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
                    before "emV0emV0",
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

        let query = QueryParser::parse(
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

        let query = QueryParser::parse(
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
        

        let query = QueryParser::parse(
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


        let query = QueryParser::parse(
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

        let query = QueryParser::parse(
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

        let query = QueryParser::parse(
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
        

        let query = QueryParser::parse(
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

        let query = QueryParser::parse(
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
    fn duplicated_field() {
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

        let _query = QueryParser::parse(
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

        let _query = QueryParser::parse(
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


        let _query = QueryParser::parse(
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


        let _query = QueryParser::parse(
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

        let _query = QueryParser::parse(
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

        let _query = QueryParser::parse(
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


        let _query = QueryParser::parse(
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



        let _query = QueryParser::parse(
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


        let _query = QueryParser::parse(
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


        let _query = QueryParser::parse(
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


        let _query = QueryParser::parse(
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
       

        
        let _query = QueryParser::parse(
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


        let _query = QueryParser::parse(
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


        let _query = QueryParser::parse(
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


        let _query = QueryParser::parse(
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

        let _query = QueryParser::parse(
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
       

        let _query = QueryParser::parse(
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

        let _query = QueryParser::parse(
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

        let _query = QueryParser::parse(
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

        let _query = QueryParser::parse(
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

        let _query = QueryParser::parse(
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
    fn start_with_underscore() {
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

        let _query = QueryParser::parse(
            r#"
            query aquery {
                Person {
                    name
                }

                _pet: Person {
                    name
                }

            } "#,
            &data_model,
        )
        .expect_err("alias cannot starts with an _");
    
        let _query = QueryParser::parse(
            r#"
            query aquery {
                Person {
                    name
                }

                pet: Person {
                   _name : name
                }

            } "#,
            &data_model,
        )
        .expect_err("alias cannot starts with an _");

        let _query = QueryParser::parse(
            r#"
            query aquery {
                Person {
                    name
                }

                pet: Person {
                    _pub_key
                }

            } "#,
            &data_model,
        )
        .expect("_pub_key is a valid system field");

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

        let _query = QueryParser::parse(
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

        let _query = QueryParser::parse(
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

        
        let _query = QueryParser::parse(
            r#"
            query aquery {
                Person {
                    name : someone{name}
                }

            } "#,
            &data_model,
        )
        .expect_err("alias is conflicting with the name field");

        let _query = QueryParser::parse(
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

        let _query = QueryParser::parse(
            r#"
            query aquery {
                Person {
                    parents
                }
            } "#,
            &data_model,
        )
        .expect_err("parents must be used with syntax parents{..}");

        let _query = QueryParser::parse(
            r#"
            query aquery {
                Person {
                    someone
                }
            } "#,
            &data_model,
        )
        .expect_err("someone must be used with syntax someone{..}");

        let _query = QueryParser::parse(
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
                parents : [Person] nullable,
                someone : Person
            } 

        ",
        )
        .unwrap();

        let _query = QueryParser::parse(
            r#"
            query aquery {
                Person (parents > 0) {
                    name
                }
            } "#,
            &data_model,
        )
        .expect_err("non scalar field cannot be used in filters");


        let _query = QueryParser::parse(
            r#"
            query aquery {
                Person (parents is null) {
                    name
                }
            } "#,
            &data_model,
        )
        .expect("nullable non scalar fields can check for the null value");

        let _query = QueryParser::parse(
            r#"
            query aquery {
                Person (parents is not null) {
                    name
                }
            } "#,
            &data_model,
        )
        .expect("nullable non scalar fields can check for the null value");


        let _query = QueryParser::parse(
            r#"
            query aquery {
                Person (someone = null) {
                    name
                }
            } "#,
            &data_model,
        )
        .expect_err("non nullable non scalar fields cannot check for the null value");

        let _query = QueryParser::parse(
            r#"
            query aquery {
                Person (someone != null) {
                    name
                }
            } "#,
            &data_model,
        )
        .expect_err("non nullable non scalar fields cannot check for the null value");

        let _query = QueryParser::parse(
            r#"
            query aquery {
                Person (someone > 0) {
                    name
                }
            } "#,
            &data_model,
        )
        .expect_err("non scalar field cannot be used in filters");

        let _query = QueryParser::parse(
            r#"
            query aquery {
                Person (aage > 10) {
                    name
                }
            } "#,
            &data_model,
        )
        .expect_err("aage does not exists");

        let _query = QueryParser::parse(
            r#"
            query aquery {
                Person (age > 10.5) {
                    name
                }
            } "#,
            &data_model,
        )
        .expect_err("age is not a float");

        let _query = QueryParser::parse(
            r#"
            query aquery {
                Person (weight > 10) {
                    name
                }
            } "#,
            &data_model,
        )
        .expect("weight is a float and integer value will be cast as float");

        let _query = QueryParser::parse(
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
    #[test]
    fn before_after() {
        let data_model = DataModel::parse(
            "
            Person {
                name : String,
            } 

        ",
        )
        .unwrap();

        let _query = QueryParser::parse(
            r#"
            query aquery {
                Person (before $id, after $id) {
                    name
                }
            } "#,
            &data_model,
        )
        .expect_err("'after' and 'before' filters cannot be used at the same time");

        let _query = QueryParser::parse(
            r#"
            query aquery {
                Person (before $id) {
                    name
                }
            } "#,
            &data_model,
        )
        .expect("valid query");

        
        let _query = QueryParser::parse(
            r#"
            query aquery {
                Person (after $id) {
                    name
                }
            } "#,
            &data_model,
        )
        .expect("valid query");        
    }
}
