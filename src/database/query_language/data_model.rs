use super::{Error, FieldType, VariableType};
use pest::iterators::Pair;
use pest::Parser;
use pest_derive::Parser;
use std::collections::HashMap;

#[derive(Parser)]
#[grammar = "database/query_language/data_model.pest"]
struct PestParser;

const AUTHOR_TABLE: &str = "__SysAuthor";
const ID_FIELD: &str = "id";
const CREATION_DATE_FIELD: &str = "cdate";
const MODIFICATION_DATE_FIELD: &str = "mdate";
const AUTHORS_FIELD: &str = "__authors";
const ENTITY_FIELD: &str = "__entity";
const FLAG_FIELD: &str = "__sys_flag";
const JSON_FIELD: &str = "__sys_json";
const PUB_KEY_FIELD: &str = "__pub_key";
const SIGNATURE_FIELD: &str = "__signature";

lazy_static::lazy_static! {
    //
    // constant map of the system field definition
    //
    pub static ref SYSTEM_FIELDS: HashMap<String, Field> = {
        let mut fields = HashMap::new();
        fields.insert(
            ID_FIELD.to_string(),
            Field {
                name: ID_FIELD.to_string(),
                field_type: FieldType::Hex,
                nullable: false,
                indexed: false,
                unique: false,
                mutable: true,
                readable: true,
            },
        );

        fields.insert(
            CREATION_DATE_FIELD.to_string(),
            Field {
                name: CREATION_DATE_FIELD.to_string(),
                field_type: FieldType::Integer,
                nullable: false,
                indexed: false,
                unique: false,
                mutable: false,
                readable: true,
            },
        );

       fields.insert(
            MODIFICATION_DATE_FIELD.to_string(),
            Field {
                name: MODIFICATION_DATE_FIELD.to_string(),
                field_type: FieldType::Integer,
                nullable: false,
                indexed: false,
                unique: false,
                mutable: false,
                readable: true,
            },
        );

        fields.insert(
            AUTHORS_FIELD.to_string(),
            Field {
                name: AUTHORS_FIELD.to_string(),
                field_type: FieldType::Array(AUTHOR_TABLE.to_string()),
                nullable: false,
                indexed: false,
                unique: false,
                mutable: false,
                readable: true,
            },
        );

       fields.insert(
            ENTITY_FIELD.to_string(),
            Field {
                name: ENTITY_FIELD.to_string(),
                field_type: FieldType::String,
                nullable: false,
                indexed: false,
                unique: false,
                mutable: false,
                readable: true,
            },
        );

        fields.insert(
            FLAG_FIELD.to_string(),
            Field {
                name: FLAG_FIELD.to_string(),
                field_type: FieldType::Hex,
                nullable: false,
                indexed: false,
                unique: false,
                mutable: false,
                readable: false,
            },
        );

        fields.insert(
            JSON_FIELD.to_string(),
            Field {
                name: JSON_FIELD.to_string(),
                field_type: FieldType::String,
                nullable: false,
                indexed: false,
                unique: false,
                mutable: false,
                readable: false,
            },
        );

        fields.insert(
            PUB_KEY_FIELD.to_string(),
            Field {
                name: PUB_KEY_FIELD.to_string(),
                field_type: FieldType::Hex,
                nullable: false,
                indexed: false,
                unique: false,
                mutable: false,
                readable: true,
            },
        );

        fields.insert(
            SIGNATURE_FIELD.to_string(),
            Field {
                name: SIGNATURE_FIELD.to_string(),
                field_type: FieldType::Hex,
                nullable: false,
                indexed: false,
                unique: false,
                mutable: false,
                readable: true,
            },
        );
        fields
    };
}

#[derive(Debug)]
pub struct DataModel {
    entities: HashMap<String, Entity>,
}
impl DataModel {
    pub fn new() -> Self {
        let mut dm = Self {
            entities: HashMap::new(),
        };
        let mut sys_author = Entity::new();
        sys_author.name = AUTHOR_TABLE.to_string();
        dm.entities.insert(AUTHOR_TABLE.to_string(), sys_author);
        dm
    }

    pub fn add_entity(&mut self, entity: Entity) -> Result<(), Error> {
        if self.entities.contains_key(&entity.name) {
            return Err(Error::DuplicatedEntity(entity.name.clone()));
        }
        self.entities.insert(entity.name.clone(), entity);
        Ok(())
    }

    pub fn get_entity(&self, name: &String) -> Result<&Entity, Error> {
        if let Some(entity) = self.entities.get(name) {
            Ok(entity)
        } else {
            Err(Error::InvalidQuery(format!(
                "Entity '{}' not found in the data model",
                name
            )))
        }
    }

    pub fn parse(query: &str) -> Result<DataModel, Error> {
        let mut data_model = DataModel::new();

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
                            data_model.add_entity(entity)?;
                        }
                        Rule::EOI => {}
                        _ => unreachable!(),
                    }
                }
            }
            _ => unreachable!(),
        }
        data_model.check_consistency()?;
        Ok(data_model)
    }

    fn parse_entity(pair: Pair<'_, Rule>) -> Result<Entity, Error> {
        let mut entity = Entity::new();
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
                        readable: true,
                        mutable: true,
                    };

                    let field_type = field_pair.next().unwrap();

                    match field_type.as_rule() {
                        Rule::scalar_field => {
                            let mut scalar_field = field_type.into_inner();
                            let scalar_type = scalar_field.next().unwrap().as_str();

                            match scalar_type {
                                "Boolean" => field.field_type = FieldType::Boolean,
                                "Float" => field.field_type = FieldType::Float,
                                "Integer" => field.field_type = FieldType::Integer,
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
                            entity.add_field(field)?;
                        }
                        Rule::entity_field => {
                            let mut entity_field = field_type.into_inner();

                            let name = entity_field.next().unwrap().as_str().to_string();
                            field.field_type = FieldType::Entity(name);

                            if let Some(_next) = entity_field.next() {
                                field.nullable = false;
                            }
                            entity.add_field(field)?;
                        }
                        Rule::entity_array => {
                            let name = field_type.into_inner().next().unwrap().as_str();
                            field.nullable = false;
                            match name {
                                "Boolean" | "Float" | "Integer" | "String" => {
                                    return Err(Error::ParserError(format! ("{}.{} [{}] only Entity is supported in array definition. Scalar fields (Boolean, Float, Integer, String) are not supported",entity.name , field.name, name)));
                                }
                                _ => field.field_type = FieldType::Array(name.to_string()),
                            }
                            entity.add_field(field)?;
                        }

                        _ => unreachable!(),
                    }
                }
                _ => unreachable!(),
            }
        }
        Ok(entity)
    }

    fn check_consistency(&self) -> Result<(), Error> {
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
#[derive(Debug)]
pub struct Entity {
    pub name: String,
    pub fields: HashMap<String, Field>,
    pub deprecated: bool,
}
impl Entity {
    pub fn new() -> Self {
        Self {
            name: "".to_string(),
            fields: HashMap::new(),
            deprecated: false,
        }
    }

    pub fn add_field(&mut self, field: Field) -> Result<(), Error> {
        if self.fields.contains_key(&field.name) {
            return Err(Error::DuplicatedField(field.name.clone()));
        }
        if SYSTEM_FIELDS.contains_key(&field.name) {
            return Err(Error::SystemFieldConflict(field.name.clone()));
        }
        self.fields.insert(field.name.clone(), field);
        Ok(())
    }
    pub fn get_field(&self, name: &String) -> Result<&Field, Error> {
        if let Some(field) = self.fields.get(name) {
            Ok(field)
        } else if let Some(field) = SYSTEM_FIELDS.get(name) {
            Ok(field)
        } else {
            Err(Error::InvalidQuery(format!(
                "Field '{}' does not exist in entity '{}' ",
                name, self.name
            )))
        }
    }
}

#[derive(Debug)]
pub struct Field {
    pub name: String,
    pub field_type: FieldType,
    pub nullable: bool,
    pub indexed: bool,
    pub unique: bool,
    pub mutable: bool,
    pub readable: bool,
}
impl Field {
    pub fn new() -> Self {
        Self {
            name: "".to_string(),
            field_type: FieldType::Boolean,
            nullable: false,
            indexed: false,
            unique: false,
            mutable: false,
            readable: false,
        }
    }

    pub fn get_variable_type(&self) -> VariableType {
        match self.field_type {
            FieldType::Array(_) | FieldType::Entity(_) | FieldType::Hex => {
                VariableType::Hex(self.nullable)
            }
            FieldType::Boolean => VariableType::Boolean(self.nullable),
            FieldType::Integer => VariableType::Integer(self.nullable),
            FieldType::Float => VariableType::Float(self.nullable),
            FieldType::String => VariableType::String(self.nullable),
        }
    }
}

#[cfg(test)]
mod tests {

    use std::any::Any;

    use super::*;

    #[test]
    fn parse_valid_model() {
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
    fn invalid_entity() {
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
                    child : [Person],
                }
            
          ",
        )
        .expect("Person a valid entity");

        let _datamodel = DataModel::parse(
            "
                Person {
                    mother : InvalidEntity,
                }
            
          ",
        )
        .expect_err("InvalidEntity is not defined in the datamodel");

        let _datamodel = DataModel::parse(
            "
                Person {
                    mother : Person,
                }
            
          ",
        )
        .expect("Person is a valid entity");
    }

    #[test]
    fn duplicates() {
        let _datamodel = DataModel::parse(
            "
                Person {
                    child : [Person],
                }

                Person {
                    name : String,
                }
            
          ",
        )
        .expect_err("Person is duplicated");

        let _datamodel = DataModel::parse(
            "
                Person {
                    child : [Person],
                }

            
          ",
        )
        .expect("Person is not duplicated anymore");

        let _datamodel = DataModel::parse(
            "
                Person {
                    child : String,
                    child : [Person],
                }            
          ",
        )
        .expect_err("child is duplicated");

        let _datamodel = DataModel::parse(
            "
                Person {
                    name : String,
                    child : [Person],
                }            
          ",
        )
        .expect("child is not duplicated anymore");
    }

    #[test]
    fn parse_invalid_string() {
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

    #[test]
    fn system_field_collision() {
        let mut entity = Entity::new();

        let mut field = Field::new();
        field.name = AUTHORS_FIELD.to_string();
        entity
            .add_field(field)
            .expect_err("system field allready defined");

        let mut field = Field::new();
        field.name = AUTHORS_FIELD.to_string();
        entity
            .add_field(field)
            .expect_err("system field allready defined");

        let mut field = Field::new();
        field.name = CREATION_DATE_FIELD.to_string();
        entity
            .add_field(field)
            .expect_err("system field allready defined");

        let mut field = Field::new();
        field.name = ENTITY_FIELD.to_string();
        entity
            .add_field(field)
            .expect_err("system field allready defined");

        let mut field = Field::new();
        field.name = FLAG_FIELD.to_string();
        entity
            .add_field(field)
            .expect_err("system field allready defined");

        let mut field = Field::new();
        field.name = ID_FIELD.to_string();
        entity
            .add_field(field)
            .expect_err("system field allready defined");

        let mut field = Field::new();
        field.name = JSON_FIELD.to_string();
        entity
            .add_field(field)
            .expect_err("system field allready defined");

        let mut field = Field::new();
        field.name = MODIFICATION_DATE_FIELD.to_string();
        entity
            .add_field(field)
            .expect_err("system field allready defined");

        let mut field = Field::new();
        field.name = PUB_KEY_FIELD.to_string();
        entity
            .add_field(field)
            .expect_err("system field allready defined");

        let mut field = Field::new();
        field.name = SIGNATURE_FIELD.to_string();
        entity
            .add_field(field)
            .expect_err("system field allready defined");
    }
}
