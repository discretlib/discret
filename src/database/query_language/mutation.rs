use std::collections::HashMap;

use crate::database::query_language::VariableType;

use super::{
    data_model::{DataModel, Field},
    parameter::Variables,
    Error, FieldType, FieldValue, Value,
};

use pest::{iterators::Pair, Parser};
use pest_derive::Parser;

#[derive(Parser)]
#[grammar = "database/query_language/mutation.pest"]
struct PestParser;

//
// String parameters in the query are transformed into parameters that will be passed to a prepared statement to avoid SQL injection issues
//
#[derive(Debug)]
pub struct EntityMutation {
    name: String,
    fields: HashMap<String, MutationField>,
}
impl EntityMutation {
    pub fn new() -> Self {
        Self {
            name: "".to_string(),
            fields: HashMap::new(),
        }
    }
    pub fn add_field(&mut self, field: MutationField) -> Result<(), Error> {
        if let Some(_) = self.fields.get(&field.name) {
            Err(Error::DuplicatedField(field.name.clone()))
        } else {
            self.fields.insert(field.name.clone(), field);
            Ok(())
        }
    }
}

#[derive(Debug)]
pub struct MutationField {
    name: String,
    field_type: FieldType,
    field_value: FieldValue,
}
impl MutationField {
    pub fn new() -> Self {
        Self {
            name: "".to_string(),
            field_type: FieldType::Boolean,
            field_value: FieldValue::Value(Value::Boolean(true)),
        }
    }
}

#[derive(Debug)]
pub struct Mutation {
    name: String,
    variables: Variables,
    mutations: Vec<EntityMutation>,
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

        match parse.as_rule() {
            Rule::mutation => {
                let mut mutation_pairs = parse.into_inner();
                mutation.name = mutation_pairs.next().unwrap().as_str().to_string();

                for entity_pair in mutation_pairs.into_iter() {
                    match entity_pair.as_rule() {
                        Rule::entity => {
                            let ent = Self::parse_entity(
                                data_model,
                                entity_pair,
                                &mut mutation.variables,
                            )?;
                            mutation.mutations.push(ent);
                        }
                        Rule::EOI => {}
                        _ => unreachable!(),
                    }
                }
            }
            _ => {}
        }

        Ok(mutation)
    }

    fn parse_entity(
        data_model: &DataModel,
        pair: Pair<'_, Rule>,
        variables: &mut Variables,
    ) -> Result<EntityMutation, Error> {
        let mut entity = EntityMutation::new();
        for entity_pair in pair.into_inner().into_iter() {
            match entity_pair.as_rule() {
                Rule::identifier => {
                    let name = entity_pair.as_str().to_string();
                    data_model.get_entity(&name)?;
                    entity.name = name;
                }
                Rule::field => {
                    let mut field_pairs = entity_pair.into_inner();
                    let name = field_pairs.next().unwrap().as_str().to_string();

                    let field = data_model
                        .get_entity(&entity.name)
                        .unwrap()
                        .get_field(&name)?;
                    if !field.mutable {
                        return Err(Error::InvalidQuery(format!(
                            "System Field '{}' is not mutable",
                            &name
                        )));
                    }
                    let mut mutation_field = MutationField::new();
                    mutation_field.name = name;

                    let content_pair = field_pairs.next().unwrap().into_inner().next().unwrap();
                    match content_pair.as_rule() {
                        Rule::entity_ref => {
                            Mutation::parse_entity_type(
                                field,
                                &mut mutation_field,
                                content_pair,
                                variables,
                            )?;
                            //  println!("{}", var);
                        }
                        Rule::entity_array => {
                            Mutation::parse_entity_array_type(
                                field,
                                &mut mutation_field,
                                content_pair,
                                variables,
                            )?;
                        }
                        Rule::boolean => {
                            Mutation::parse_boolean_type(field, &mut mutation_field, content_pair)?;
                        }

                        Rule::float => {
                            Mutation::parse_float_type(field, &mut mutation_field, content_pair)?;
                        }
                        Rule::integer => {
                            // println!("{:#?}", content_pair);
                            Mutation::parse_int_type(field, &mut mutation_field, content_pair)?;
                        }

                        Rule::string => {
                            // println!("{:#?}", content_pair);
                            Mutation::parse_string_type(field, &mut mutation_field, content_pair)?;
                        }

                        Rule::null => {
                            // println!("{:#?}", content_pair);
                            Mutation::parse_null_type(field, &mut mutation_field)?;
                        }

                        Rule::variable => {
                            Mutation::parse_variable_type(
                                field,
                                &mut mutation_field,
                                content_pair,
                                variables,
                            )?;
                        }

                        _ => { //println!("{:#?}", content_pair);
                        }
                    }

                    entity.add_field(mutation_field)?;
                }
                _ => unreachable!(),
            }
        }

        Ok(entity)
    }

    fn validate_hex(var: &str, name: &String) -> Result<(), Error> {
        if hex::decode(var).is_err() {
            return Err(Error::InvalidQuery(format!(
                "Entity Field '{}' value '{}' is not a valid hexadecimal ",
                &name, var
            )));
        }
        Ok(())
    }

    fn parse_entity_type(
        field: &Field,
        mutation_field: &mut MutationField,
        content_pair: Pair<'_, Rule>,
        variables: &mut Variables,
    ) -> Result<(), Error> {
        match field.field_type {
            FieldType::Entity(_) => {}
            _ => {
                return Err(Error::InvalidFieldType(
                    mutation_field.name.to_string(),
                    field.field_type.to_string(),
                    "Entity".to_string(),
                ))
            }
        }
        mutation_field.field_type = field.field_type.clone();
        let var_pair = content_pair
            .into_inner()
            .next()
            .unwrap()
            .into_inner()
            .next()
            .unwrap();

        match var_pair.as_rule() {
            Rule::variable => {
                let var = &var_pair.as_str()[1..];
                variables.add(var.to_string(), VariableType::Hex(field.nullable))?;
                mutation_field.field_value = FieldValue::Variable(var.to_string());
            }
            Rule::string => {
                let var = var_pair.into_inner().next().unwrap().as_str();
                let name = &mutation_field.name;
                Mutation::validate_hex(var, name)?;
                mutation_field.field_value = FieldValue::Value(Value::String(var.to_string()));
            }

            _ => {
                return Err(Error::InvalidQuery(format!(
                    "Entity Field '{}' must contain a variable or an hex string.  value '{}' ",
                    mutation_field.name.to_string(),
                    var_pair.as_str()
                )))
            }
        }
        Ok(())
    }

    fn parse_entity_array_type(
        field: &Field,
        mutation_field: &mut MutationField,
        content_pair: Pair<'_, Rule>,
        variables: &mut Variables,
    ) -> Result<(), Error> {
        match field.field_type {
            FieldType::Array(_) => {}
            _ => {
                return Err(Error::InvalidFieldType(
                    mutation_field.name.to_string(),
                    field.field_type.to_string(),
                    "Array".to_string(),
                ))
            }
        }
        mutation_field.field_type = field.field_type.clone();

        let var_pair = content_pair
            .into_inner()
            .next()
            .unwrap()
            .into_inner()
            .next()
            .unwrap();

        match var_pair.as_rule() {
            Rule::variable => {
                let var = &var_pair.as_str()[1..];
                variables.add(var.to_string(), VariableType::Hex(field.nullable))?;
                mutation_field.field_value = FieldValue::Variable(var.to_string());
            }
            Rule::string => {
                let var = var_pair.into_inner().next().unwrap().as_str();
                let name = &mutation_field.name;
                Mutation::validate_hex(var, name)?;
                mutation_field.field_value = FieldValue::Value(Value::String(var.to_string()));
            }

            _ => {
                return Err(Error::InvalidQuery(format!(
                    "Entity Field '{}' must contain a variable or an hex string.  value '{}' ",
                    mutation_field.name.to_string(),
                    var_pair.as_str()
                )))
            }
        }
        Ok(())
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

        mutation_field.field_value = FieldValue::Value(Value::Boolean(value.parse()?));
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
        mutation_field.field_value = FieldValue::Value(Value::Float(value.parse()?));
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
                mutation_field.field_value = FieldValue::Value(Value::Float(value.parse()?));
            }
            FieldType::Integer => {
                let value = content_pair.as_str();
                mutation_field.field_value = FieldValue::Value(Value::Integer(value.parse()?));
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
                mutation_field.field_value = FieldValue::Value(Value::String(value.to_string()));
            }
            FieldType::Hex => {
                Mutation::validate_hex(value, &field.name)?;
                mutation_field.field_value = FieldValue::Value(Value::String(value.to_string()));
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

    fn parse_null_type(field: &Field, mutation_field: &mut MutationField) -> Result<(), Error> {
        if field.nullable {
            mutation_field.field_value = FieldValue::Value(Value::Null);
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
        mutation_field.field_value = FieldValue::Variable(var.to_string());

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
                name : String NOT NULL UNIQUE,
                surname : String INDEXED,
                parents : [Person],
                pet : Pet,
                age : Integer,
                weight : Float,
                is_human : Boolean NOT NULL
            }

            Pet {
                name : String  UNIQUE NOT NULL,
            }
        
        ",
        )
        .unwrap();

        let _mutation = Mutation::parse(
            r#"
            mutation mutmut {
                Person {
                    id : $id1
                    name : $id2
                    surname : "dridri"
                    parents : [$id3]
                    age: 10
                    weight: 123
                    pet : {$id3}
                }

                Person {
                    name : "Silvia"
                    is_human : true
                }
            }
        "#,
            &data_model,
        )
        .unwrap();

        println!("{:#?}", _mutation);
    }
}
