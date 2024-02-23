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
   pub filters: Vec<FilterParam>,
   pub aggregate_filters: Vec<FilterParam>,
   pub fulltext_search: Option<FieldValue>,
   pub after: Vec<FieldValue>,
   pub before: Vec<FieldValue>,
   pub order_by: Vec<OrderBy>,
   pub first: FieldValue,
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
            after: Vec::new(),
            before: Vec::new(),
            filters: Vec::new(),
            aggregate_filters: Vec::new(),
            fulltext_search: None,
            first: FieldValue::Value(Value::Integer(DEFAULT_LIMIT)),
            order_by: Vec::new(),
            skip: None,
        }
    }
}


#[derive(Debug)]
struct ParsedFilter{
    pub name: String, 
    pub operation: String,
    pub value: FieldValue,

}
#[derive(Debug)]
pub struct FilterParam {
    pub name: String, 
    pub operation: String,
    pub value: FieldValue,
    pub is_aggregate: bool,
    pub is_selected: bool,
    pub field: Field
}

#[derive(Debug)]
pub struct ParsedOrderBy{
    pub name: String, 
    pub direction: Direction
}

#[derive(Debug)]
pub struct OrderBy {
    pub name: String,
    pub direction: Direction, 
    pub is_aggregate: bool,
    pub is_selected: bool,
    pub field: Field
}

#[derive(Debug)]
pub enum Direction{
    Asc,
    Desc
}

#[derive(Debug)]
pub struct EntityQuery {
    pub name: String,
    pub alias: Option<String>,
    pub short_name: String,
    pub depth: usize,
    pub complexity: usize,
    pub is_aggregate: bool,
    pub params: EntityParams,
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
            params: EntityParams::new(),
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

    pub fn finalize(&self, variables: &mut Variables) -> Result<(), Error>{
        let par =&self.params;
        if !par.after.is_empty() && !par.before.is_empty(){
            return Err(Error::InvalidQuery(format!(
                "'after' and 'before' filters cannot be used at the same time in query '{}'",
                self.aliased_name()
            )))
        }
        let paging = if !par.after.is_empty(){
            &par.after
        }else{
            &par.before
        };

        if !paging.is_empty(){
            if paging.len() > par.order_by.len() {
                return Err(Error::InvalidQuery(format!(
                    "'after' and 'before' must have a number of parameters lower or equal to the Order By clause. Order by size: '{}'",
                    par.order_by.len()
                )))
            }

            for i in 0..paging.len(){
                let val = &paging[i];
                let order_field = &par.order_by[i];

                if self.is_aggregate{
                    return Err(Error::InvalidPagingQuery())
                }
  
                let field_type = &order_field.field.field_type;
                match val{
                    FieldValue::Variable(var) => {
                        //we couln't know the variable type until now 
                        let variable_type = order_field.field.get_variable_type_non_nullable();
                        variables.add(var.clone(), variable_type)?;

                    },
                    FieldValue::Value(val) => match val{
                        Value::Boolean(_) => {
                            match field_type{
                                FieldType::Boolean => {},
                                _ => { return Err(Error::InvalidPagingValue(i, String::from("Boolean")))},
                            }
                        }
                        
                        Value::Integer(_) => {
                            match field_type{
                                FieldType::Integer => {},
                                FieldType::Float => {},
                                _ => { return Err(Error::InvalidPagingValue(i, String::from("Integer")))},
                            }
                        }
                        Value::Float(_) => {
                            match field_type{
                                FieldType::Float => {},
                                _ => { return Err(Error::InvalidPagingValue(i, String::from("Float")))},
                            }
                        }
                        Value::String(s) => {
                            match field_type{
                                FieldType::String => {},
                                FieldType::Base64 => {
                                    validate_base64(s, &format!( "'after' or 'before' field position {} ",i))?;
                                },
                                _ => { return Err(Error::InvalidPagingValue(i, String::from("String")))},
                            }
                        }
                        _=> unreachable!(),
                    },
                }
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
        let entity_model = data_model.get_entity(&entity.name)?;
        let mut parsed_filters = None;
        let mut parsed_order_by = None;
        let mut parameters = EntityParams::new();
        for entity_pair in pairs {
            match entity_pair.as_rule() {
                Rule::entity_param => {
                    let params = Self::parse_params( entity_pair, variables)?;
                    parameters = params.0;
                    parsed_filters = Some(params.1);
                    parsed_order_by = Some(params.2)
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
                                
                                if entity_model.get_field(alias_name).is_ok(){
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

                            let model_field = entity_model.get_field(&name)?;

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
                                if entity_model.get_field(alias_name).is_ok(){
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
                            let model_field = entity_model.get_field(&name)?;


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
            for parse in filters{
                let param = Self::build_filter(
                    entity,
                    entity_model,
                    variables,
                    parse
                )?;
                if param.is_aggregate {
                    parameters.aggregate_filters.push(param);
                } else {
                    parameters.filters.push(param);
                }
                
            }
        }
    

        if let Some(order_by) = parsed_order_by{
            for parsed_order in order_by{
                let ord = Self::build_order_by(entity, entity_model,parsed_order)?;
                parameters.order_by.push(ord);
            }
        }
      
        entity.params = parameters;
        
        entity.finalize(variables)?;
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
                    name : name.clone(),
                    is_system: false,
                    field_type: FieldType::Float,
                    ..Default::default()
                };
                QueryField{
                    field,
                    alias:Some(name),
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
                    name : model_field.name.clone(),
                    is_system: model_field.is_system,
                    field_type: FieldType::Float,
                    ..Default::default()
                };
                QueryField{
                    field,
                    alias:Some(name),
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
                    name : model_field.name.clone(),
                    is_system: model_field.is_system,
                    field_type: FieldType::Float,
                    ..Default::default()
                };
                QueryField{
                    field,
                    alias:Some(name),
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
                    name : model_field.name.clone(),
                    is_system: model_field.is_system,
                    field_type: FieldType::Float,
                    ..Default::default()
                };
                QueryField{
                    field,
                    alias:Some(name),
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
                    name : model_field.name.clone(),
                    is_system: model_field.is_system,
                    field_type: FieldType::Float,
                    ..Default::default()
                };
                QueryField{
                    field,
                    alias:Some(name),
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
                    field_type: FieldType::Float,
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
        pair: Pair<'_, Rule>,
        variables: &mut Variables,
    ) -> Result<(EntityParams, Vec<ParsedFilter>, Vec<ParsedOrderBy>), Error> {
        let mut parameters = EntityParams::new();
        let mut parsed_filter = Vec::new(); 
        let mut parsed_order_by = Vec::new();

        let param_pairs = pair.into_inner();
        for param_pair in param_pairs {
            let pair = param_pair.into_inner().next().unwrap();
            match pair.as_rule() {
                Rule::filter => {
                    let filter = Self::parse_filter(pair)?;
                    parsed_filter.push(filter);
                }
                Rule::order_by => {
                    let order_pairs = pair.into_inner();
                    
                    for order_pair in order_pairs {
                        let mut order_p = order_pair.into_inner();
                        let name = order_p.next().unwrap().as_str().to_string();

                        let direction_str = order_p.next().unwrap().as_str().to_lowercase();
                        let direction = match direction_str.as_str() {
                            "asc" => Direction::Asc,
                            "desc" => Direction::Desc,
                            _=> unreachable!()
                        };
                        parsed_order_by.push(ParsedOrderBy{ name, direction })
                    }
                }
                Rule::first => {
                    let val = pair.into_inner().next().unwrap().into_inner().next().unwrap();
                    match val.as_rule(){
                        Rule::variable => {
                            let var = &val.as_str()[1..];
                            variables.add(var.to_string(), VariableType::Integer(false))?;
                            parameters.first = FieldValue::Variable(var.to_string());

                        }
                        Rule::unsigned_int => {
                            let value = val.as_str();
                            parameters.first = FieldValue::Value(Value::Integer(value.parse()?));
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
                  let values = pair.into_inner();
                  let before = Self::parse_paging_params(values)?;
                  parameters.before = before;
                }

                Rule::after => {
                    let values = pair.into_inner();
                    let after = Self::parse_paging_params(values)?;
                    parameters.after = after;
                }
                _ => unreachable!(),
                
            }
        }

        Ok((parameters, parsed_filter, parsed_order_by))
    }


    fn parse_filter(
        pair: Pair<'_, Rule>,
    ) -> Result<ParsedFilter, Error> {
        let mut filter_pairs = pair.into_inner();

        let name = filter_pairs.next().unwrap().as_str().to_string();

        let operation_pair =  filter_pairs.next().unwrap();
        let operation = operation_pair.as_str().to_string();
    
        let value_pair = filter_pairs.next().unwrap().into_inner().next().unwrap();
        let value = Self::parse_field_value(value_pair)?;
        Ok(ParsedFilter{ name, operation, value })

    }

    fn build_filter(
        entity: &EntityQuery,
        entity_model: &Entity,
        variables: &mut Variables,
        parsed_filters: ParsedFilter
    ) -> Result<FilterParam, Error> {

        let mut is_aggregate = false;
        let mut is_entity_field = false;
        let mut is_selected = false;

        let field_res = entity_model.get_field(&parsed_filters.name);       
        let field =  match field_res {
            Ok(field) => {
                match field.field_type {
                    FieldType::Array(_) | FieldType::Entity(_) =>  is_entity_field = true,
                    _ => {},
                }
                field
            },
            Err(_) => {
                let query_field = entity.fields.iter().find(|entry| entry.name().eq(&parsed_filters.name));
                let field = match &query_field {
                        Some(e) => {
                            is_selected = true;
                            match e.field_type {
                                QueryFieldType::Function(_) | QueryFieldType::EntityQuery(_, _) | QueryFieldType::EntityArrayQuery(_, _)=> is_entity_field = true,
                                QueryFieldType::Aggregate(_) => is_aggregate = true,
                                QueryFieldType::NamedField | QueryFieldType::BinaryField => {},
                            }
                            &e.field
                        },
                        None => return Err(Error::InvalidQuery(format!("filter field '{}' does not exists", &parsed_filters.name))),
                };
                field
            },
        };

        if is_entity_field{
            match parsed_filters.operation.as_str(){
                "=" | "!=" => {}
                _ => 
                return Err(Error::InvalidEntityFilter(
                    String::from(&parsed_filters.name)
                ))
            }
        }
       
       
        let name = parsed_filters.name;
        let value = match &parsed_filters.value {
            FieldValue::Variable(var) => {
                if is_entity_field{
                    return Err(Error::InvalidEntityFilter(
                        String::from(name)
                    ))
                }
                let var_type = field.get_variable_type();
                variables.add(var.to_string(), var_type)?;
                parsed_filters.value
            },
            FieldValue::Value(val) => {
                match val{
                    Value::Null => {
                        if field.nullable {
                            parsed_filters.value
                        } else {
                            return Err(Error::NotNullable(name));
                        }
                    },

                    Value::Boolean(_) => {
                        if is_entity_field{
                            return Err(Error::InvalidEntityFilter(
                                name
                            ))
                        }
                        match field.field_type {
                            FieldType::Boolean => {
                                parsed_filters.value
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
                    Value::Integer(i) => {
                        if is_entity_field{
                            return Err(Error::InvalidEntityFilter(
                                name,
                            ))
                        } 
                        match field.field_type {
                            FieldType::Float =>  FieldValue::Value(Value::Float(*i as f64)),  
                            FieldType::Integer =>  parsed_filters.value,  
                            _ => {
                                return Err(Error::InvalidFieldType(
                                    name,
                                    field.field_type.to_string(),
                                    "Float".to_string(),
                                ))
                            }
                        }
                    },
                    Value::Float(_) => {
                        if is_entity_field{
                            return Err(Error::InvalidEntityFilter(
                                name,
                            ))
                        } 
                        match field.field_type {
                             FieldType::Float =>  parsed_filters.value,  
                            _ => {
                                return Err(Error::InvalidFieldType(
                                    name,
                                    field.field_type.to_string(),
                                    "Float".to_string(),
                                ))
                            }
                        }
                    },
                    Value::String(s) => {
                        if is_entity_field{
                            return Err(Error::InvalidEntityFilter(
                                name
                            ))
                        }
                       
                        match field.field_type {
                            FieldType::String => parsed_filters.value,
                            FieldType::Base64 => {
                                validate_base64(s, &name)?;
                                parsed_filters.value
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
                    
                }
            },
        };

       
        Ok(FilterParam {
            name: name,
            operation: String::from(&parsed_filters.operation),
            value,
            is_aggregate,
            is_selected,
            field:field.clone()
        })
    }

    fn build_order_by(
        entity: &EntityQuery,
        entity_model: &Entity,
        parsed_order: ParsedOrderBy
    ) -> Result<OrderBy, Error> {
        
        let mut is_aggregate = false;
        let mut is_entity_field = false;
        let mut is_selected = false;

        let field_res = entity_model.get_field(&parsed_order.name);       
        let field =  match field_res {
            Ok(field) => {
                match field.field_type {
                    FieldType::Array(_) | FieldType::Entity(_) =>  is_entity_field = true,
                    _ => {},
                }
                field
            },
            Err(_) => {
                let query_field = entity.fields.iter().find(|entry| entry.name().eq(&parsed_order.name));
                let field = match &query_field {
                        Some(e) => {
                            is_selected = true;
                            match e.field_type {
                                QueryFieldType::Function(_) | QueryFieldType::EntityQuery(_, _) | QueryFieldType::EntityArrayQuery(_, _)=> is_entity_field = true,
                                QueryFieldType::Aggregate(_) => is_aggregate = true,
                                QueryFieldType::NamedField | QueryFieldType::BinaryField => {},
                            }
                            &e.field
                        },
                        None => return Err(Error::InvalidQuery(format!("Order by field '{}' does not exists", &parsed_order.name))),
                };
                field
            },
        };



        Ok(OrderBy { 
            name: parsed_order.name,
            direction:parsed_order.direction,
            is_aggregate,
            is_selected,
            field: field.clone()
        })       
    }

    fn parse_field_value(value_pair: Pair<'_, Rule>) -> Result<FieldValue, Error> {
        let field = match value_pair.as_rule(){
            Rule::boolean => {
                let value = value_pair.as_str();
                FieldValue::Value(Value::Boolean(value.parse()?))
            }
            Rule::float => {
                let value = value_pair.as_str();
                FieldValue::Value(Value::Float(value.parse()?))
            }
            Rule::integer => {
                let value = value_pair.as_str();
                FieldValue::Value(Value::Integer(value.parse()?))
            }
            Rule::null => {
                FieldValue::Value(Value::Null)
            }
            Rule::string => {
                let value = value_pair.into_inner().next().unwrap().as_str().to_string();
                FieldValue::Value(Value::String(value))
            }
            Rule::variable => {
                let value = &value_pair.as_str()[1..];
                FieldValue::Variable(String::from(value))
            }
            _=>unreachable!()
        };
        Ok(field)
    }
    

    fn parse_paging_params(values: Pairs<'_, Rule>) -> Result<Vec<FieldValue>, Error> {
        let mut before = Vec::new();
        for value in values {
            let value_pair = value.into_inner().next().unwrap();
            let field = Self::parse_field_value(value_pair)?;
            before.push(field);
        }
        Ok(before)
    }

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




