use super::Error;
use pest::iterators::Pair;
use pest::Parser;
use pest_derive::Parser;
use std::collections::HashMap;

#[derive(Parser)]
#[grammar = "database/query_language/data_model.pest"]
struct PestParser;

#[derive(Debug)]
pub struct DataModel {
    entities: HashMap<String, Entity>,
}

#[derive(Debug)]
pub struct Entity {
    name: String,
    fields: HashMap<String, Field>,
    deprecated: bool,
}

#[derive(Debug)]
pub struct Field {
    name: String,
    field_type: FieldType,
    nullable: bool,
    indexed: bool,
    unique: bool,
}

#[derive(Debug)]
pub enum FieldType {
    Entity(String),
    Array(String),
    String,
    Integer,
    Float,
    Boolean,
}

impl DataModel {
    pub fn parse(query: &str) -> Result<DataModel, Error> {
        let mut data_model = DataModel {
            entities: HashMap::new(),
        };

        let parse = match PestParser::parse(Rule::datamodel, query) {
            Err(e) => {
                let message = format!("{}", e);
                return Err(Error::ParserError(message));
            }
            Ok(f) => f,
        }
        .next()
        .unwrap();

        match parse.as_rule() {
            Rule::datamodel => {
                let namespace_pairs = parse.into_inner();

                for pair in namespace_pairs.into_iter() {
                    match pair.as_rule() {
                        Rule::entity => {
                            let entity = Self::parse_entity(pair)?;
                            data_model.entities.insert(entity.name.clone(), entity);
                        }
                        _ => {}
                    }
                }
            }
            _ => unreachable!(),
        }
        data_model.check_consistency()?;
        Ok(data_model)
    }

    fn parse_entity(pair: Pair<'_, Rule>) -> Result<Entity, Error> {
        let mut entity = Entity {
            name: "".to_string(),
            fields: HashMap::new(),
            deprecated: true,
        };
        for entity_pair in pair.into_inner().into_iter() {
            match entity_pair.as_rule() {
                Rule::deprecated => {
                    entity.deprecated = true;
                }
                Rule::identifier => {
                    entity.name = entity_pair.as_str().to_string();
                }
                Rule::field => {
                    let mut field_pair = entity_pair.into_inner();
                    let name = field_pair.next().unwrap().as_str();
                    let mut field = Field {
                        name: name.to_string(),
                        field_type: FieldType::Boolean,
                        indexed: false,
                        nullable: true,
                        unique: false,
                    };

                    let field_type = field_pair.next().unwrap();

                    match field_type.as_rule() {
                        Rule::scalar_field => {
                            let mut scalar_field = field_type.into_inner();
                            let scalar_type = scalar_field.next().unwrap().as_str();

                            match scalar_type {
                                "Integer" => field.field_type = FieldType::Integer,
                                "Float" => field.field_type = FieldType::Float,
                                "Boolean" => field.field_type = FieldType::Boolean,
                                "String" => field.field_type = FieldType::String,
                                _ => unreachable!(),
                            }

                            for pair in scalar_field.into_iter() {
                                match pair.as_rule() {
                                    Rule::not_null => field.nullable = false,
                                    Rule::unique => field.unique = true,
                                    Rule::indexed => field.indexed = true,
                                    _ => unreachable!(),
                                }
                            }

                            entity.fields.insert(field.name.clone(), field);
                        }
                        Rule::entity_field => {
                            let mut entity_field = field_type.into_inner();

                            let name = entity_field.next().unwrap().as_str().to_string();
                            field.field_type = FieldType::Entity(name);

                            if let Some(_next) = entity_field.next() {
                                field.nullable = false;
                            }
                            entity.fields.insert(field.name.clone(), field);
                        }
                        Rule::entity_array => {
                            let name = field_type.into_inner().next().unwrap().as_str();
                            field.nullable = false;
                            match name {
                                "Integer" | "Float" | "Boolean" | "String" => {
                                    return Err(Error::ParserError(format! ("{}.{} [{}] only Entity are supported in array, NOT scalar fields (Integer, Float, Boolean, String ) ",entity.name , field.name, name)));
                                }
                                _ => field.field_type = FieldType::Array(name.to_string()),
                            }
                            entity.fields.insert(field.name.clone(), field);
                        }

                        _ => unreachable!(),
                    }
                }
                _ => unreachable!(),
            }
        }

        Ok(entity)
    }

    pub fn check_consistency(&self) -> Result<(), Error> {
        for entry in &self.entities {
            let entity = entry.1;
            for field_entry in &entity.fields {
                let field = field_entry.1;
                match &field.field_type {
                    FieldType::Array(e) => {
                        if !self.entities.contains_key(e) {
                            return Err(Error::ParserError(format!(
                            "entity {} does not exist. Please check the definition of the {}.{}:[{}] field",
                            e, entity.name, field.name, e
                        )));
                        }
                    }
                    FieldType::Entity(e) => {
                        if !self.entities.contains_key(e) {
                            return Err(Error::ParserError(format!(
                        "entity {} does not exist. Please check the definition of the {}.{}:{} field",
                        e, entity.name, field.name, e
                    )));
                        }
                    }
                    _ => {}
                }
            }
        }

        Ok(())
    }
}

#[cfg(test)]
mod tests {

    use std::any::Any;

    use super::*;

    #[test]
    fn parse_valid_model_test() {
        let datamodel = DataModel::parse(
            "
                @deprecated Person {
                    name : String NOT NULL UNIQUE,
                    surname : String INDEXED,
                    child : [Person],
                    mother : Person not null,
                    father : Person, 
                }

                Pet {
                    name : String  UNIQUE NOT NULL,
                    surname : String INDEXED,
                    owners : [Person],
                    age : Float,
                    weight : Integer,
                    is_vaccinated: Boolean
                }
            
          ",
        )
        .unwrap();

        assert_eq!(2, datamodel.entities.len());

        let pet = datamodel.entities.get("Pet").unwrap();
        assert_eq!("Pet", pet.name);

        let age = pet.fields.get("age").unwrap();
        assert_eq!(FieldType::Float.type_id(), age.field_type.type_id());
        assert_eq!(true, age.nullable);
        assert_eq!(false, age.unique);
        assert_eq!(false, age.indexed);

        let name = pet.fields.get("name").unwrap();
        assert_eq!(FieldType::String.type_id(), name.field_type.type_id());
        assert_eq!(false, name.nullable);
        assert_eq!(true, name.unique);
        assert_eq!(false, name.indexed);

        let surname = pet.fields.get("surname").unwrap();
        assert_eq!(FieldType::String.type_id(), surname.field_type.type_id());
        assert_eq!(true, surname.nullable);
        assert_eq!(false, surname.unique);
        assert_eq!(true, surname.indexed);

        let owner = pet.fields.get("owners").unwrap();
        match &owner.field_type {
            FieldType::Array(e) => assert_eq!("Person", e),
            _ => unreachable!(),
        }
        assert_eq!(false, owner.nullable);
        assert_eq!(false, owner.unique);
        assert_eq!(false, owner.indexed);

        let weight = pet.fields.get("weight").unwrap();
        assert_eq!(FieldType::Integer.type_id(), weight.field_type.type_id());
        assert_eq!(true, weight.nullable);
        assert_eq!(false, weight.unique);
        assert_eq!(false, weight.indexed);

        let is_vaccinated = pet.fields.get("is_vaccinated").unwrap();
        assert_eq!(
            FieldType::Boolean.type_id(),
            is_vaccinated.field_type.type_id()
        );
        assert_eq!(true, is_vaccinated.nullable);
        assert_eq!(false, is_vaccinated.unique);
        assert_eq!(false, is_vaccinated.indexed);

        let person = datamodel.entities.get("Person").unwrap();
        assert_eq!("Person", person.name);
        let name = person.fields.get("name").unwrap();
        assert_eq!(FieldType::String.type_id(), name.field_type.type_id());
        assert_eq!(false, name.nullable);
        assert_eq!(true, name.unique);
        assert_eq!(false, name.indexed);

        let surname = person.fields.get("surname").unwrap();
        assert_eq!(FieldType::String.type_id(), surname.field_type.type_id());
        assert_eq!(true, surname.nullable);
        assert_eq!(false, surname.unique);
        assert_eq!(true, surname.indexed);

        let child = person.fields.get("child").unwrap();
        match &child.field_type {
            FieldType::Array(e) => assert_eq!("Person", e),
            _ => unreachable!(),
        }
        assert_eq!(false, child.nullable);
        assert_eq!(false, child.unique);
        assert_eq!(false, child.indexed);

        let mother = person.fields.get("mother").unwrap();
        match &mother.field_type {
            FieldType::Entity(e) => assert_eq!("Person", e),
            _ => unreachable!(),
        }
        assert_eq!(false, mother.nullable);
        assert_eq!(false, mother.unique);
        assert_eq!(false, mother.indexed);

        let father = person.fields.get("father").unwrap();
        match &father.field_type {
            FieldType::Entity(e) => assert_eq!("Person", e),
            _ => unreachable!(),
        }
        assert_eq!(true, father.nullable);
        assert_eq!(false, father.unique);
        assert_eq!(false, father.indexed);

        //println!("{:#?}", datamodel)
    }

    #[test]
    fn parse_invalid_entity_test() {
        let _datamodel = DataModel::parse(
            "
                Person {
                    child : [InvalidEntity],
                }
            
          ",
        )
        .expect_err("InvalidEntity is not defined in the datamodel");

        let _datamodel = DataModel::parse(
            "
                Person {
                    mother : InvalidEntity,
                }
            
          ",
        )
        .expect_err("InvalidEntity is not defined in the datamodel");
    }

    #[test]
    fn parse_invalid_string_test() {
        let _datamodel = DataModel::parse(
            "
                Person {
                    child : Person],
                }
            
          ",
        )
        .expect_err("missing [ before person");

        let _datamodel = DataModel::parse(
            "
                Person @deprecated {
                    mother : Person,
                }
            
          ",
        )
        .expect_err("@deprecated must be before the entity name");
    }
}
