use std::collections::HashMap;

use crate::base64_decode;

use super::{
    data_model::{DataModel, Entity, Field, ID_FIELD},
    parameter::Variables,
    Error, FieldType, Value,
};

use pest::{
    iterators::{Pair, Pairs},
    Parser,
};
use pest_derive::Parser;

#[derive(Parser)]
#[grammar = "database/query_language/mutation.pest"]
struct PestParser;

#[derive(Debug)]
pub struct EntityMutation {
    pub name: String,
    pub alias: Option<String>,
    pub short_name: String,
    pub depth: usize,
    pub fields: HashMap<String, MutationField>,
}
impl Default for EntityMutation {
    fn default() -> Self {
        EntityMutation::new()
    }
}
impl EntityMutation {
    pub fn new() -> Self {
        Self {
            name: String::from(""),
            short_name: String::from(""),
            alias: None,
            depth: 0,
            fields: HashMap::new(),
        }
    }
    pub fn add_field(&mut self, field: MutationField) -> Result<(), Error> {
        if self.fields.get(&field.name).is_some() {
            Err(Error::DuplicatedField(field.name.clone()))
        } else {
            self.fields.insert(field.name.clone(), field);
            Ok(())
        }
    }

    pub fn aliased_name(&self) -> String {
        if self.alias.is_some() {
            self.alias.clone().unwrap()
        } else {
            self.name.clone()
        }
    }
}
#[derive(Debug)]
pub enum MutationFieldValue {
    Variable(String),
    Value(Value),
    Array(Vec<EntityMutation>),
    Entity(EntityMutation),
}

#[derive(Debug)]
pub struct MutationField {
    pub name: String,
    pub short_name: String,
    pub field_type: FieldType,
    pub field_value: MutationFieldValue,
    pub is_default_filled: bool,
}
impl Default for MutationField {
    fn default() -> Self {
        MutationField::new()
    }
}
impl MutationField {
    pub fn new() -> Self {
        Self {
            name: String::from(""),
            short_name: String::from(""),
            field_type: FieldType::Boolean,
            field_value: MutationFieldValue::Value(Value::Boolean(true)),
            is_default_filled: false,
        }
    }
}

#[derive(Debug)]
pub struct Mutation {
    pub name: String,
    pub variables: Variables,
    pub mutations: Vec<EntityMutation>,
}
impl Default for Mutation {
    fn default() -> Self {
        Mutation::new()
    }
}
impl Mutation {
    pub fn new() -> Self {
        Self {
            name: "".to_string(),
            variables: Variables::new(),
            mutations: Vec::new(),
        }
    }

    pub fn parse(p: &str, data_model: &DataModel) -> Result<Self, Error> {
        let mut mutation = Mutation::new();

        let parse = match PestParser::parse(Rule::mutation, p) {
            Err(e) => {
                let message = format!("{}", e);
                return Err(Error::ParserError(message));
            }
            Ok(f) => f,
        }
        .next()
        .unwrap();

        if parse.as_rule() == Rule::mutation {
            let mut mutation_pairs = parse.into_inner();
            mutation.name = mutation_pairs.next().unwrap().as_str().to_string();

            for entity_pair in mutation_pairs {
                match entity_pair.as_rule() {
                    Rule::entity => {
                        let ent =
                            Self::parse_entity(data_model, entity_pair, &mut mutation.variables)?;
                        let alias = ent.aliased_name();
                        let exists = mutation
                            .mutations
                            .iter()
                            .any(|x| x.aliased_name().eq(&alias));
                        if exists {
                            return Err(Error::InvalidQuery(format!(
                                "Query name or alias '{}' is allready defined",
                                alias
                            )));
                        }

                        mutation.mutations.push(ent);
                    }
                    Rule::EOI => {}
                    _ => unreachable!(),
                }
            }
        }

        Ok(mutation)
    }

    fn parse_entity(
        data_model: &DataModel,
        pair: Pair<'_, Rule>,
        variables: &mut Variables,
    ) -> Result<EntityMutation, Error> {
        let mut entity = EntityMutation::new();

        let mut entity_pairs = pair.into_inner();
        let mut name_pair = entity_pairs.next().unwrap().into_inner();
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

        entity.name = name;
        entity.depth =
            Self::parse_entity_internals(&mut entity, data_model, entity_pairs, variables)?;

        let entity_model = data_model.get_entity(&entity.name)?;
        entity.short_name = entity_model.short_name.clone();
        Self::fill_not_nullable(&mut entity, entity_model)?;
        Ok(entity)
    }

    //
    // fill mutation with default values for nullable fields
    // only happens if the id is not provided, which means that the mutation will create the entity
    // it ensures backward compatibility in case of model change
    //
    fn fill_not_nullable(
        entity_mutation: &mut EntityMutation,
        entity_model: &Entity,
    ) -> Result<(), Error> {
        if entity_mutation.fields.contains_key(ID_FIELD) {
            //the mutation is an update not a creation,
            return Ok(());
        }
        for m_field_tuple in &entity_model.fields {
            let model_field = m_field_tuple.1;
            if !model_field.nullable {
                let field = entity_mutation.fields.get(&model_field.name);
                if field.is_none() {
                    if let Some(default) = &model_field.default_value {
                        let mutation_field = MutationField {
                            name: model_field.name.clone(),
                            short_name: model_field.short_name.clone(),
                            field_type: model_field.field_type.clone(),
                            field_value: MutationFieldValue::Value(default.clone()),
                            is_default_filled: true,
                        };
                        entity_mutation
                            .fields
                            .insert(mutation_field.name.clone(), mutation_field);
                    } else {
                        return Err(Error::MissingUpdateField(
                            String::from(&entity_model.name),
                            String::from(&model_field.name),
                        ));
                    }
                }
            }
        }
        Ok(())
    }

    fn parse_entity_internals(
        entity: &mut EntityMutation,
        data_model: &DataModel,
        pairs: Pairs<'_, Rule>,
        variables: &mut Variables,
    ) -> Result<usize, Error> {
        let mut depth: usize = 0;
        for entity_pair in pairs {
            match entity_pair.as_rule() {
                Rule::field => {
                    let mut field_pairs = entity_pair.into_inner();
                    let name = field_pairs.next().unwrap().as_str().to_string();

                    let field_model = data_model
                        .get_entity(&entity.name)
                        .unwrap()
                        .get_field(&name)?;
                    if !field_model.mutable {
                        return Err(Error::InvalidQuery(format!(
                            "System Field '{}' is not mutable",
                            &name
                        )));
                    }
                    let mut mutation_field = MutationField::new();
                    mutation_field.name = name;
                    mutation_field.short_name = field_model.short_name.clone();

                    let content_pair = field_pairs.next().unwrap().into_inner().next().unwrap();
                    match content_pair.as_rule() {
                        Rule::entity_ref => {
                            let adepth = Mutation::parse_entity_type(
                                field_model,
                                &mut mutation_field,
                                content_pair,
                                data_model,
                                variables,
                            )?;
                            if adepth > depth {
                                depth = adepth
                            }
                        }
                        Rule::entity_array => {
                            let adepth = Mutation::parse_array_type(
                                field_model,
                                &mut mutation_field,
                                content_pair,
                                data_model,
                                variables,
                            )?;
                            if adepth > depth {
                                depth = adepth
                            }
                        }
                        Rule::boolean => {
                            Mutation::parse_boolean_type(
                                field_model,
                                &mut mutation_field,
                                content_pair,
                            )?;
                        }

                        Rule::float => {
                            Mutation::parse_float_type(
                                field_model,
                                &mut mutation_field,
                                content_pair,
                            )?;
                        }
                        Rule::integer => {
                            // println!("{:#?}", content_pair);
                            Mutation::parse_int_type(
                                field_model,
                                &mut mutation_field,
                                content_pair,
                            )?;
                        }

                        Rule::string => {
                            // println!("{:#?}", content_pair);
                            Mutation::parse_string_type(
                                field_model,
                                &mut mutation_field,
                                content_pair,
                            )?;
                        }

                        Rule::null => {
                            // println!("{:#?}", content_pair);
                            Mutation::parse_null_type(field_model, &mut mutation_field)?;
                        }

                        Rule::variable => {
                            Mutation::parse_variable_type(
                                field_model,
                                &mut mutation_field,
                                content_pair,
                                variables,
                            )?;
                        }

                        _ => {
                            //println!("{:#?}", content_pair);
                            unreachable!()
                        }
                    }

                    entity.add_field(mutation_field)?;
                }
                _ => {
                    // println!("{:#?}", entity_pair);
                    unreachable!()
                }
            }
        }
        Ok(depth)
    }

    fn validate_base64(var: &str, name: &String) -> Result<(), Error> {
        if base64_decode(var.as_bytes()).is_err() {
            return Err(Error::InvalidQuery(format!(
                "Entity Field '{}' value '{}' is not a valid base64 ",
                &name, var
            )));
        }
        Ok(())
    }

    fn parse_array_type(
        field: &Field,
        mutation_field: &mut MutationField,
        content_pair: Pair<'_, Rule>,
        data_model: &DataModel,
        variables: &mut Variables,
    ) -> Result<usize, Error> {
        let name = match &field.field_type {
            FieldType::Array(e) => e,
            _ => {
                return Err(Error::InvalidFieldType(
                    mutation_field.name.to_string(),
                    field.field_type.to_string(),
                    "Array".to_string(),
                ))
            }
        };
        mutation_field.field_type = field.field_type.clone();

        let mut entities = vec![];
        let entity_pairs = content_pair.into_inner();
        let mut depth = 0;
        for entity_pair in entity_pairs {
            let mut entity = EntityMutation::new();
            entity.name = name.clone();
            let var_pair = entity_pair.into_inner();
            let adepth =
                Self::parse_entity_internals(&mut entity, data_model, var_pair, variables)?;
            if adepth > depth {
                depth = adepth;
            }
            let entity_model = data_model.get_entity(&entity.name)?;
            entity.short_name = entity_model.short_name.clone();
            Self::fill_not_nullable(&mut entity, entity_model)?;
            entities.push(entity)
        }
        mutation_field.field_value = MutationFieldValue::Array(entities);
        Ok(depth + 1)
    }

    fn parse_entity_type(
        field: &Field,
        mutation_field: &mut MutationField,
        content_pair: Pair<'_, Rule>,
        data_model: &DataModel,
        variables: &mut Variables,
    ) -> Result<usize, Error> {
        let mut entity = EntityMutation::new();

        match &field.field_type {
            FieldType::Entity(e) => entity.name = e.clone(),
            _ => {
                return Err(Error::InvalidFieldType(
                    mutation_field.name.to_string(),
                    field.field_type.to_string(),
                    "Entity".to_string(),
                ))
            }
        }

        mutation_field.field_type = field.field_type.clone();

        let var_pair = content_pair.into_inner();

        let adepth = Self::parse_entity_internals(&mut entity, data_model, var_pair, variables)?;
        let entity_model = data_model.get_entity(&entity.name)?;
        entity.short_name = entity_model.short_name.clone();

        Self::fill_not_nullable(&mut entity, entity_model)?;

        mutation_field.field_value = MutationFieldValue::Entity(entity);
        Ok(adepth + 1)
    }

    fn parse_boolean_type(
        field: &Field,
        mutation_field: &mut MutationField,
        content_pair: Pair<'_, Rule>,
    ) -> Result<(), Error> {
        match field.field_type {
            FieldType::Boolean => {}
            _ => {
                return Err(Error::InvalidFieldType(
                    mutation_field.name.to_string(),
                    field.field_type.to_string(),
                    "Boolean".to_string(),
                ))
            }
        }
        mutation_field.field_type = field.field_type.clone();

        let value = content_pair.as_str();

        mutation_field.field_value = MutationFieldValue::Value(Value::Boolean(value.parse()?));
        Ok(())
    }

    fn parse_float_type(
        field: &Field,
        mutation_field: &mut MutationField,
        content_pair: Pair<'_, Rule>,
    ) -> Result<(), Error> {
        match field.field_type {
            FieldType::Float => {}
            _ => {
                return Err(Error::InvalidFieldType(
                    mutation_field.name.to_string(),
                    field.field_type.to_string(),
                    "Float".to_string(),
                ))
            }
        }
        mutation_field.field_type = field.field_type.clone();

        let value = content_pair.as_str();
        mutation_field.field_value = MutationFieldValue::Value(Value::Float(value.parse()?));
        Ok(())
    }

    fn parse_int_type(
        field: &Field,
        mutation_field: &mut MutationField,
        content_pair: Pair<'_, Rule>,
    ) -> Result<(), Error> {
        match field.field_type {
            FieldType::Float => {
                let value = content_pair.as_str();
                mutation_field.field_value =
                    MutationFieldValue::Value(Value::Float(value.parse()?));
            }
            FieldType::Integer => {
                let value = content_pair.as_str();
                mutation_field.field_value =
                    MutationFieldValue::Value(Value::Integer(value.parse()?));
            }
            _ => {
                return Err(Error::InvalidFieldType(
                    mutation_field.name.to_string(),
                    field.field_type.to_string(),
                    "Float".to_string(),
                ))
            }
        }
        mutation_field.field_type = field.field_type.clone();

        Ok(())
    }

    fn parse_string_type(
        field: &Field,
        mutation_field: &mut MutationField,
        content_pair: Pair<'_, Rule>,
    ) -> Result<(), Error> {
        let value = content_pair.into_inner().next().unwrap().as_str();
        match field.field_type {
            FieldType::String => {
                mutation_field.field_value =
                    MutationFieldValue::Value(Value::String(value.to_string()));
            }
            FieldType::Base64 => {
                Mutation::validate_base64(value, &field.name)?;
                mutation_field.field_value =
                    MutationFieldValue::Value(Value::String(value.to_string()));
            }
            _ => {
                return Err(Error::InvalidFieldType(
                    mutation_field.name.to_string(),
                    field.field_type.to_string(),
                    "String".to_string(),
                ))
            }
        }
        mutation_field.field_type = field.field_type.clone();

        Ok(())
    }

    fn parse_null_type(field: &Field, mutation_field: &mut MutationField) -> Result<(), Error> {
        if field.nullable {
            mutation_field.field_value = MutationFieldValue::Value(Value::Null);
        } else {
            return Err(Error::NotNullable(field.name.clone()));
        }
        mutation_field.field_type = field.field_type.clone();

        Ok(())
    }

    fn parse_variable_type(
        field: &Field,
        mutation_field: &mut MutationField,
        content_pair: Pair<'_, Rule>,
        variables: &mut Variables,
    ) -> Result<(), Error> {
        match field.field_type {
            FieldType::Entity(_) => {
                return Err(Error::InvalidQuery(format!(
                    "Invalid syntax for the '{}' Entity field, please use field:{{$variable}} ",
                    field.name
                )))
            }

            FieldType::Array(_) => {
                return Err(Error::InvalidQuery(format!(
                    "Invalid syntax for the '{}' Entity field, please use field:[$variable] ",
                    field.name
                )))
            }
            _ => {}
        }
        mutation_field.field_type = field.field_type.clone();
        let var = &content_pair.as_str()[1..];
        let var_type = field.get_variable_type();

        variables.add(var.to_string(), var_type)?;
        mutation_field.field_value = MutationFieldValue::Variable(var.to_string());

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
                name : String ,
                surname : String ,
                parents : [Person],
                pet : Pet,
                age : Integer,
                weight : Float,
                is_human : Boolean 
            }

            Pet {
                name : String ,
            }
        
        ",
        )
        .unwrap();

        let _mutation = Mutation::parse(
            r#"
            mutation mutmut {
                Person {
                    id : $id
                    name : $name
                    surname : $surname
                    parents : [{id: $father_id}, {id: $mother_id}]
                    age: $age
                    weight: $weight
                    pet : { id : $pet_id}
                    is_human : $human
                }
                person_value : Person {
                    name : "me"
                    surname : "also me"
                    parents : [{id: "emV0emV0"}, {id: "emV0emV1"}]
                    age: 4200
                    weight: 71.1
                    pet : { name : "kiki"}
                    is_human : false
                }
            }
        "#,
            &data_model,
        )
        .unwrap();

        //println!("{:#?}", _mutation);
    }

    #[test]
    fn scalar_field() {
        let data_model = DataModel::parse(
            "
            Person {
                name : String nullable,
                surname : String nullable,
                age : Integer nullable,
                weight : Float nullable,
                is_human : Boolean nullable
            }
        
        ",
        )
        .unwrap();

        let _mutation = Mutation::parse(
            r#"
            mutation mutmut {
                Person {
                    id : $id
                    name : [{id : $pet_id}]
                }
            }
        "#,
            &data_model,
        )
        .expect_err("scalar field cannot use the syntax name : [{$name}]");

        let _mutation = Mutation::parse(
            r#"
            mutation mutmut {
                Person {
                    id : $id
                    name : {id : $pet_id}
                }
            }
        "#,
            &data_model,
        )
        .expect_err("scalar field cannot use the syntax name : {$name}");

        let _mutation = Mutation::parse(
            r#"
            mutation mutmut {
                Person {
                    id : $id
                    name: $name
                    weight : "name"
                }
            }
        "#,
            &data_model,
        )
        .expect_err("weight is not a string");

        let _mutation = Mutation::parse(
            r#"
            mutation mutmut {
                Person {
                    id : $id
                    weight : true
                }
            }
        "#,
            &data_model,
        )
        .expect_err("weight is not a boolean");

        let _mutation = Mutation::parse(
            r#"
            mutation mutmut {
                Person {
                    id : $id
                    weight : 1
                }
            }
        "#,
            &data_model,
        )
        .expect("weight is a float compatible with integer");

        let _mutation = Mutation::parse(
            r#"
            mutation mutmut {
                Person {
                    id : $id
                    weight : 1.12
                }
            }
        "#,
            &data_model,
        )
        .expect("weight is a float ");

        let _mutation = Mutation::parse(
            r#"
            mutation mutmut {
                Person {
                    id : "qsdgqzaddfq"
                    
                }
            }
        "#,
            &data_model,
        )
        .expect_err("id requires a valid base64 string");

        let _mutation = Mutation::parse(
            r#"
            mutation mutmut {
                Person {
                    id : "emV0emV0"
                    
                }
            }
        "#,
            &data_model,
        )
        .expect("id is a valid base64 string");
    }

    #[test]
    fn duplicated_field() {
        let data_model = DataModel::parse(
            "
            Person {
                name : String ,
            }
        
        ",
        )
        .unwrap();

        let _mutation = Mutation::parse(
            r#"
            mutation mutmut {
                Person {
                    name : $name
                    name : $name2
                }
            }
        "#,
            &data_model,
        )
        .expect_err("duplicated name");
    }

    #[test]
    fn alias() {
        let data_model = DataModel::parse(
            "
            Person {
                name : String ,
            }
        
        ",
        )
        .unwrap();

        let _mutation = Mutation::parse(
            r#"
            mutation mutmut {
                Person {
                    name : $name
                }
                Person {
                    name : $name
                }
            }
        "#,
            &data_model,
        )
        .expect_err("duplicated entity");

        let _mutation = Mutation::parse(
            r#"
            mutation mutmut {
                Person {
                    name : $name
                }
                Person : Person {
                    name : $name
                }
            }
        "#,
            &data_model,
        )
        .expect_err("duplicated alias");

        let _mutation = Mutation::parse(
            r#"
            mutation mutmut {
                Person {
                    name : $name
                }
                aPerson : Person {
                    name : $name
                }
                aPerson : Person {
                    name : $name
                }
            }
        "#,
            &data_model,
        )
        .expect_err("duplicated alias");

        let _mutation = Mutation::parse(
            r#"
            mutation mutmut {
                Person {
                    name : $name
                }
                person : Person {
                    name : $name
                }
                bPerson : Person {
                    name : $name
                }
            }
        "#,
            &data_model,
        )
        .expect("all is good, names are case sensitive");
    }

    #[test]
    fn nullables() {
        let data_model = DataModel::parse(
            "
            Person {
                name : String ,
                surname : String nullable,
                is_human : Boolean default true
            }
        
        ",
        )
        .unwrap();

        let _mutation = Mutation::parse(
            r#"
            mutation mutmut {
                Person {
                    surname : $name
                }
            }
        "#,
            &data_model,
        )
        .expect_err("missing name");

        let _mutation = Mutation::parse(
            r#"
            mutation mutmut {
                Person {
                    name : $name
                }
            }
        "#,
            &data_model,
        )
        .expect("is_human is missing but will be defaulted to true");
    }

    #[test]
    fn non_scalar_field() {
        let data_model = DataModel::parse(
            "
            Person {
                name: String,
                parents : [Person],
                someone : Person nullable,
            }
        
        ",
        )
        .unwrap();

        let mutation = Mutation::parse(
            r#"
            mutation mutmut {
                Person {
                    name : $name
                    someone : {name:"hello"}
                }
            }
        "#,
            &data_model,
        )
        .expect("missing name");
        let entity = &mutation.mutations[0];
        assert_eq!("Person", entity.name);
        let some = entity.fields.get("someone").unwrap();
        if let FieldType::Entity(e) = &some.field_type {
            assert_eq!("Person", e);
        } else {
            unreachable!()
        }
        if let MutationFieldValue::Entity(e) = &some.field_value {
            let field = e.fields.get("name").unwrap();
            if let MutationFieldValue::Value(val) = &field.field_value {
                assert_eq!("hello", val.as_string().unwrap());
            } else {
                unreachable!()
            }
        } else {
            unreachable!()
        }
    }

    #[test]
    fn depth() {
        let data_model = DataModel::parse(
            "
            Person {
                name: String,
                parents : [Person],
                someone : Person nullable,
            }
        
        ",
        )
        .unwrap();

        let mutation = Mutation::parse(
            r#"
            mutation mutmut {
                Person {
                    name : $name
                    someone : {
                        name : $name
                        someone : {
                            name : $name
                            someone : {
                                name : $name
                                someone : {
                                    name : $name
                                }
                            }
                        }
                    }

                    parents : [{
                        name : $name
                        someone : {
                            name : $name
                            someone : {
                                name : $name
                                someone : {
                                    name : $name
                                    someone : {
                                        name : $name
                                        someone : {
                                            name : $name
                                            someone : {
                                                name : $name
                                                someone : {
                                                    name : $name
                                                }
                                            }
                                        }
                                    }
                                }
                            }
                        }
                    }]
                }
            }
        "#,
            &data_model,
        )
        .unwrap();
        let depth = mutation.mutations[0].depth;
        assert_eq!(8, depth);
    }
}
