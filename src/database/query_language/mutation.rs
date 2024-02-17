use std::collections::HashMap;

use crate::{base64_decode, database::query_language::VariableType};

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
    pub name: String,
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
            name: "".to_string(),
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
}

#[derive(Debug)]
pub struct MutationField {
    pub name: String,
    pub field_type: FieldType,
    pub field_value: FieldValue,
}
impl Default for MutationField {
    fn default() -> Self {
        MutationField::new()
    }
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
        for entity_pair in pair.into_inner() {
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

    fn validate_base64(var: &str, name: &String) -> Result<(), Error> {
        if base64_decode(var.as_bytes()).is_err() {
            return Err(Error::InvalidQuery(format!(
                "Entity Field '{}' value '{}' is not a valid base64 ",
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
                variables.add(var.to_string(), VariableType::Base64(field.nullable))?;
                mutation_field.field_value = FieldValue::Variable(var.to_string());
            }
            Rule::string => {
                let var = var_pair.into_inner().next().unwrap().as_str();
                let name = &mutation_field.name;
                Mutation::validate_base64(var, name)?;
                mutation_field.field_value = FieldValue::Value(Value::String(var.to_string()));
            }

            _ => {
                return Err(Error::InvalidQuery(format!(
                    "Entity Field '{}' must contain a variable or an base64 string.  value '{}' ",
                    mutation_field.name,
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
                variables.add(var.to_string(), VariableType::Base64(field.nullable))?;
                mutation_field.field_value = FieldValue::Variable(var.to_string());
            }
            Rule::string => {
                let var = var_pair.into_inner().next().unwrap().as_str();
                let name = &mutation_field.name;
                Mutation::validate_base64(var, name)?;
                mutation_field.field_value = FieldValue::Value(Value::String(var.to_string()));
            }

            _ => {
                return Err(Error::InvalidQuery(format!(
                    "Entity Field '{}' must contain a variable or a base64 string.  value '{}' ",
                    mutation_field.name,
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
            FieldType::Base64 => {
                Mutation::validate_base64(value, &field.name)?;
                mutation_field.field_value = FieldValue::Value(Value::String(value.to_string()));
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
                    parents : [$father_id]
                    age: $age
                    weight: $weight
                    pet : {$pet_id}
                    is_human : $human
                }

                Person {
                    name : "Doe"
                    surname : "John"
                    parents : ["emV0emV0"]
                    age: 32
                    weight: 123.4
                    pet : {"emV0emV0"}
                    is_human : true
                }
            }
        "#,
            &data_model,
        )
        .unwrap();

        // println!("{:#?}", _mutation);
    }
    #[test]
    fn non_scalar_field() {
        let data_model = DataModel::parse(
            "
            Person {
                name : String ,
                parents : [Person],
                someone : Person,
            }
        
        ",
        )
        .unwrap();

        let _mutation = Mutation::parse(
            r#"
            mutation mutmut {
                Person {
                    id : $id
                    parents : $father_id
                    
                }
            }
        "#,
            &data_model,
        )
        .expect_err("parents need to use the syntax parents : [..]");

        let _mutation = Mutation::parse(
            r#"
            mutation mutmut {
                Person {
                    id : $id
                    someone : $someone_id
                    
                }
            }
        "#,
            &data_model,
        )
        .expect_err("someone need to use the syntax someone : {..}");

        let _mutation = Mutation::parse(
            r#"
            mutation mutmut {
                Person {
                    id : $id
                    parents : [$father_id]
                    someone : {$someone_id}
                }
            }
        "#,
            &data_model,
        )
        .expect("valid syntax");

        let _mutation = Mutation::parse(
            r#"
            mutation mutmut {
                Person {
                    id : $id
                    parents : ["qsdgqzaddfq"]
                }
            }
        "#,
            &data_model,
        )
        .expect_err("parents require a valid base64");

        let _mutation = Mutation::parse(
            r#"
            mutation mutmut {
                Person {
                    id : $id
                    someone : {"qsdgqzaddfq"}
                }
            }
        "#,
            &data_model,
        )
        .expect_err("parents require a valid base64");

        let _mutation = Mutation::parse(
            r#"
            mutation mutmut {
                Person {
                    id : $id
                    parents : ["emV0emV0"]
                    someone : {"emV0emV0"}
                }
            }
        "#,
            &data_model,
        )
        .expect("valid syntax");
    }

    #[test]
    fn scalar_field() {
        let data_model = DataModel::parse(
            "
            Person {
                name : String ,
                surname : String ,
                age : Integer,
                weight : Float,
                is_human : Boolean 
            }
        
        ",
        )
        .unwrap();

        let _mutation = Mutation::parse(
            r#"
            mutation mutmut {
                Person {
                    id : $id
                    name : [$name]
                }
            }
        "#,
            &data_model,
        )
        .expect_err("scalar field cannot use the syntax name : [$name]");

        let _mutation = Mutation::parse(
            r#"
            mutation mutmut {
                Person {
                    id : $id
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
}
