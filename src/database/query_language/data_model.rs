use crate::base64_decode;

use super::{Error, FieldType, Value, VariableType};
use pest::iterators::Pair;
use pest::Parser;
use pest_derive::Parser;
use std::collections::HashMap;

#[derive(Parser)]
#[grammar = "database/query_language/data_model.pest"]
struct PestParser;

const AUTHOR_TABLE: &str = "_SysAuthor";
const AUTHORS_FIELD: &str = "_authors";

pub const ID_FIELD: &str = "id";
const CREATION_DATE_FIELD: &str = "cdate";
const MODIFICATION_DATE_FIELD: &str = "mdate";
const ENTITY_FIELD: &str = "_entity";
const JSON_FIELD: &str = "_json";
const BINARY_FIELD: &str = "_binary";
const PUB_KEY_FIELD: &str = "_pub_key";
const SIGNATURE_FIELD: &str = "_signature";

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
                short_name: ID_FIELD.to_string(),
                field_type: FieldType::Base64,
                default_value: None,
                nullable: false,
                deprecated: false,
                mutable: true,
                is_system: true,
            },
        );

        fields.insert(
            CREATION_DATE_FIELD.to_string(),
            Field {
                name: CREATION_DATE_FIELD.to_string(),
                short_name: CREATION_DATE_FIELD.to_string(),
                field_type: FieldType::Integer,
                default_value: None,
                nullable: false,
                deprecated: false,
                mutable: false,
                is_system: true,
            },
        );

       fields.insert(
            MODIFICATION_DATE_FIELD.to_string(),
            Field {
                name: MODIFICATION_DATE_FIELD.to_string(),
                short_name: MODIFICATION_DATE_FIELD.to_string(),
                field_type: FieldType::Integer,
                default_value: None,
                nullable: false,
                deprecated: false,
                mutable: false,
                is_system: true,
            },
        );

        fields.insert(
            AUTHORS_FIELD.to_string(),
            Field {
                name: AUTHORS_FIELD.to_string(),
                short_name: AUTHORS_FIELD.to_string(),
                field_type: FieldType::Array(AUTHOR_TABLE.to_string()),
                default_value: None,
                nullable: false,
                deprecated: false,
                mutable: false,
                is_system: true,
            },
        );

       fields.insert(
            ENTITY_FIELD.to_string(),
            Field {
                name: ENTITY_FIELD.to_string(),
                short_name: ENTITY_FIELD.to_string(),
                field_type: FieldType::String,
                default_value: None,
                nullable: false,
                deprecated: false,
                mutable: false,
                is_system: true,
            },
        );

        fields.insert(
            BINARY_FIELD.to_string(),
            Field {
                name: BINARY_FIELD.to_string(),
                short_name: BINARY_FIELD.to_string(),
                field_type: FieldType::Base64,
                default_value: None,
                nullable: false,
                deprecated: false,
                mutable: true,
                is_system: true,
            },
        );

        fields.insert(
            JSON_FIELD.to_string(),
            Field {
                name: JSON_FIELD.to_string(),
                short_name: JSON_FIELD.to_string(),
                field_type: FieldType::String,
                default_value: None,
                nullable: false,
                deprecated: false,
                mutable: false,
                is_system: true,
            },
        );

        fields.insert(
            PUB_KEY_FIELD.to_string(),
            Field {
                name: PUB_KEY_FIELD.to_string(),
                short_name: PUB_KEY_FIELD.to_string(),
                field_type: FieldType::Base64,
                default_value: None,
                nullable: false,
                deprecated: false,
                mutable: false,
                is_system: true,
            },
        );

        fields.insert(
            SIGNATURE_FIELD.to_string(),
            Field {
                name: SIGNATURE_FIELD.to_string(),
                short_name: SIGNATURE_FIELD.to_string(),
                field_type: FieldType::Base64,
                default_value: None,
                nullable: false,
                deprecated: false,
                mutable: false,
                is_system: true,
            },
        );
        fields
    };
}

/// Reserve the first 64 short_id for system usage.
/// This is an arbitrary value wich should be plenty enought
/// applies to entity and field
const RESERVED_SHORT_NAMES: usize = 32;

#[derive(Debug)]
pub struct DataModel {
    entities: HashMap<String, Entity>,
}
impl Default for DataModel {
    fn default() -> Self {
        DataModel::new()
    }
}
impl DataModel {
    pub fn new() -> Self {
        Self {
            entities: HashMap::new(),
        }
    }

    pub fn add_entity(&mut self, entity: Entity) -> Result<(), Error> {
        if self.entities.contains_key(&entity.name) {
            return Err(Error::DuplicatedEntity(entity.name.clone()));
        }
        self.insert(entity.name.clone(), entity)?;
        Ok(())
    }

    fn insert(&mut self, name: String, mut entity: Entity) -> Result<(), Error> {
        entity.short_name = (RESERVED_SHORT_NAMES + self.entities.len()).to_string();
        let old = self.entities.insert(name, entity);
        if old.is_some() {
            panic!("Cannot insert an existing entity in the datamodel")
        }
        Ok(())
    }

    pub fn get_entity(&self, name: &str) -> Result<&Entity, Error> {
        if let Some(entity) = self.entities.get(name) {
            Ok(entity)
        } else {
            Err(Error::InvalidQuery(format!(
                "Entity '{}' not found in the data model",
                name
            )))
        }
    }

    pub fn update(&mut self, query: &str) -> Result<(), Error> {
        let mut new_data_model = Self::parse(query)?;
        for entity in &mut self.entities {
            let new_entity_op = new_data_model.entities.remove(entity.0);
            match new_entity_op {
                Some(new_entity) => entity.1.update(new_entity)?,
                None => return Err(Error::MissingEntity(String::from(entity.0))),
            }
        }
        for entity in new_data_model.entities {
            self.insert(entity.0, entity.1)?;
        }
        Ok(())
    }

    fn parse(query: &str) -> Result<DataModel, Error> {
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
        for entity_pair in pair.into_inner() {
            match entity_pair.as_rule() {
                Rule::deprecable_identifier => {
                    for i in entity_pair.into_inner() {
                        match i.as_rule() {
                            Rule::deprecated => entity.deprecated = true,
                            Rule::identifier => {
                                let name = i.as_str();
                                if name.starts_with('_') {
                                    return Err(Error::InvalidName(name.to_string()));
                                }
                                if Self::is_reserved(name) {
                                    return Err(Error::ReservedKeyword(name.to_string()));
                                }
                                entity.name = name.to_string();
                            }
                            _ => unreachable!(),
                        }
                    }
                }
                Rule::entry => {
                    for i in entity_pair.into_inner() {
                        match i.as_rule() {
                            Rule::field => {
                                let field = Self::parse_field_type(i)?;
                                entity.add_field(field)?;
                            }
                            Rule::index => {
                                let index = Self::parse_index(i)?;
                                entity.add_index(index)?;
                            }

                            _ => unreachable!(),
                        }
                    }
                }
                Rule::comma => {}
                _ => unreachable!(),
            }
        }
        entity.check_consistency()?;
        Ok(entity)
    }

    fn parse_index(entity_pair: Pair<'_, Rule>) -> Result<Index, Error> {
        let mut index = Index::new();

        for field in entity_pair.into_inner() {
            match field.as_rule() {
                Rule::identifier => index.add_field(field.as_str().to_string())?,
                Rule::comma => {}
                _ => unreachable!(),
            }
        }
        //   println!("{:#?}", entity_pair);
        Ok(index)
    }

    fn is_reserved(value: &str) -> bool {
        match value.to_lowercase().as_str() {
            "boolean" | "float" | "integer" | "string" | "base64" | "json" => true,
            _ => false,
        }
    }

    fn parse_field_type(entity_pair: Pair<'_, Rule>) -> Result<Field, Error> {
        let mut field = Field::new();
        let mut field_pairs = entity_pair.into_inner();

        let name_pair = field_pairs.next().unwrap();

        for i in name_pair.into_inner() {
            match i.as_rule() {
                Rule::deprecated => field.deprecated = true,
                Rule::identifier => {
                    let name = i.as_str();
                    if name.starts_with('_') {
                        return Err(Error::InvalidName(name.to_string()));
                    }
                    if Self::is_reserved(name) {
                        return Err(Error::ReservedKeyword(name.to_string()));
                    }
                    field.name = name.to_string();
                }
                _ => unreachable!(),
            }
        }

        let field_type = field_pairs.next().unwrap();

        match field_type.as_rule() {
            Rule::scalar_field => {
                let mut scalar_field = field_type.into_inner();
                let scalar_type = scalar_field.next().unwrap().as_str().to_lowercase();

                match scalar_type.as_str() {
                    "boolean" => field.field_type = FieldType::Boolean,
                    "float" => field.field_type = FieldType::Float,
                    "integer" => field.field_type = FieldType::Integer,
                    "string" => field.field_type = FieldType::String,
                    "base64" => field.field_type = FieldType::Base64,
                    "json" => field.field_type = FieldType::Json,
                    _ => unreachable!(),
                }

                if let Some(pair) = scalar_field.next() {
                    match pair.as_rule() {
                        Rule::nullable => field.nullable = true,
                        Rule::default => {
                            let value_pair = pair
                                .into_inner()
                                .next()
                                .unwrap()
                                .into_inner()
                                .next()
                                .unwrap();
                            match value_pair.as_rule() {
                                Rule::boolean => {
                                    let value = value_pair.as_str();
                                    match field.field_type {
                                        FieldType::Boolean => {
                                            field.default_value =
                                                Some(Value::Boolean(value.parse()?))
                                        }
                                        _ => {
                                            return Err(Error::InvalidDefaultValue(
                                                field.name.clone(),
                                                "Boolean".to_string(),
                                                field.field_type.to_string(),
                                            ))
                                        }
                                    }
                                }
                                Rule::float => {
                                    let value = value_pair.as_str();
                                    match field.field_type {
                                        FieldType::Float => {
                                            field.default_value = Some(Value::Float(value.parse()?))
                                        }
                                        _ => {
                                            return Err(Error::InvalidDefaultValue(
                                                field.name.clone(),
                                                "Float".to_string(),
                                                field.field_type.to_string(),
                                            ))
                                        }
                                    }
                                }

                                Rule::integer => {
                                    let value = value_pair.as_str();
                                    match field.field_type {
                                        FieldType::Float => {
                                            field.default_value = Some(Value::Float(value.parse()?))
                                        }
                                        FieldType::Integer => {
                                            field.default_value =
                                                Some(Value::Integer(value.parse()?))
                                        }
                                        _ => {
                                            return Err(Error::InvalidDefaultValue(
                                                field.name.clone(),
                                                "Integer".to_string(),
                                                field.field_type.to_string(),
                                            ))
                                        }
                                    }
                                }

                                Rule::string => {
                                    let value = value_pair.into_inner().next().unwrap().as_str();
                                    match field.field_type {
                                        FieldType::String => {
                                            field.default_value =
                                                Some(Value::String(value.to_string()))
                                        }
                                        FieldType::Base64 => {
                                            let decode = base64_decode(value.as_bytes());
                                            if decode.is_err() {
                                                return Err(Error::InvalidBase64(
                                                    value.to_string(),
                                                ));
                                            }
                                            field.default_value =
                                                Some(Value::String(value.to_string()))
                                        }
                                        FieldType::Json => {
                                            let v: std::result::Result<
                                                serde_json::Value,
                                                serde_json::Error,
                                            > = serde_json::from_str(value);
                                            if v.is_err() {
                                                return Err(Error::InvalidJson(value.to_string()));
                                            }
                                            field.default_value =
                                                Some(Value::String(value.to_string()))
                                        }
                                        _ => {
                                            return Err(Error::InvalidDefaultValue(
                                                field.name.clone(),
                                                "String".to_string(),
                                                field.field_type.to_string(),
                                            ))
                                        }
                                    }
                                }

                                _ => unreachable!(),
                            }
                        }

                        _ => unreachable!(),
                    }
                }
            }
            Rule::entity_field => {
                let mut entity_field = field_type.into_inner();

                let name = entity_field.next().unwrap().as_str();
                if Self::is_reserved(name) {
                    return Err(Error::ReservedKeyword(name.to_string()));
                }

                field.field_type = FieldType::Entity(String::from(name));

                if let Some(_next) = entity_field.next() {
                    field.nullable = true;
                }
            }
            Rule::entity_array => {
                let mut entity_field = field_type.into_inner();
                let name = entity_field.next().unwrap().as_str();
                if Self::is_reserved(name) {
                    return Err(Error::ReservedKeyword(name.to_string()));
                }

                field.field_type = FieldType::Array(String::from(name));

                if let Some(_next) = entity_field.next() {
                    field.nullable = true;
                }
            }

            _ => unreachable!(),
        }
        Ok(field)
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
pub struct Index {
    fields: Vec<String>,
}

impl Index {
    pub fn new() -> Self {
        Self { fields: Vec::new() }
    }
    pub fn add_field(&mut self, name: String) -> Result<(), Error> {
        if self.fields.contains(&name) {
            return Err(Error::InvalidQuery(format!(
                "'{}' is duplicated in the Index",
                name
            )));
        }
        self.fields.push(name);
        Ok(())
    }

    pub fn name(&self) -> String {
        let mut name = String::new();
        for i in &self.fields {
            name.push('$');
            name.push_str(i);
        }
        name
    }
}

///
/// The entity data structure
///
/// An existing entity can be updated with a new entity.
/// The new entity must contains the complete entity definition along with the modification.
/// The following rules are enforced to ensure backward compatibility:
/// - fields cannot be removed
/// - existing fields can be deprecated and 'undeprecated'
/// - exiting field types cannot be changed
/// - existing fields can be changed from not nullable to nullable
/// - existing fields can be changed from nullable to not nullable only if a default value is provided
/// - new fields must provide a default value if not nullable
///
#[derive(Debug)]
pub struct Entity {
    pub name: String,
    pub short_name: String,
    pub fields: HashMap<String, Field>,
    pub indexes: HashMap<String, Index>,
    pub indexes_to_remove: HashMap<String, Index>,
    pub deprecated: bool,
}
impl Default for Entity {
    fn default() -> Self {
        Entity::new()
    }
}
impl Entity {
    pub fn new() -> Self {
        Self {
            name: "".to_string(),
            short_name: "".to_string(),
            fields: HashMap::new(),
            indexes: HashMap::new(),
            indexes_to_remove: HashMap::new(),
            deprecated: false,
        }
    }

    ///
    /// update an existing entity
    ///
    pub fn update(&mut self, mut new_entity: Entity) -> Result<(), Error> {
        self.deprecated = new_entity.deprecated;
        for field in &mut self.fields {
            let new_field_opt = new_entity.fields.remove(field.0);
            match new_field_opt {
                Some(new_field) => {
                    let field = field.1;

                    if !field.field_type.eq(&new_field.field_type) {
                        return Err(Error::CannotUpdateFieldType(
                            String::from(&self.name),
                            String::from(&field.name),
                            field.field_type.to_string(),
                            new_field.field_type.to_string(),
                        ));
                    }
                    if field.nullable && !new_field.nullable && new_field.default_value.is_none() {
                        return Err(Error::MissingDefaultValue(
                            String::from(&self.name),
                            String::from(&field.name),
                        ));
                    }
                    field.nullable = new_field.nullable;
                    field.default_value = new_field.default_value;
                    field.deprecated = new_field.deprecated;
                }
                None => {
                    return Err(Error::MissingField(
                        String::from(&self.name),
                        String::from(field.0),
                    ))
                }
            }
        }
        for field in new_entity.fields {
            if !field.1.nullable && field.1.default_value.is_none() {
                return Err(Error::MissingDefaultValue(
                    String::from(&self.name),
                    String::from(&field.1.name),
                ));
            }
            self.insert_field(field.0, field.1);
        }

        let mut index_map = HashMap::new();
        for new_index in new_entity.indexes {
            self.indexes.remove(&new_index.0);
            index_map.insert(new_index.0, new_index.1);
        }
        for to_remove in self.indexes.drain() {
            self.indexes_to_remove.insert(to_remove.0, to_remove.1);
        }
        self.indexes = index_map;
        Ok(())
    }

    pub fn add_field(&mut self, field: Field) -> Result<(), Error> {
        if self.fields.contains_key(&field.name) {
            return Err(Error::DuplicatedField(field.name.clone()));
        }
        if SYSTEM_FIELDS.contains_key(&field.name) {
            return Err(Error::SystemFieldConflict(field.name.clone()));
        }
        self.insert_field(field.name.clone(), field);
        Ok(())
    }

    fn insert_field(&mut self, name: String, mut field: Field) {
        field.short_name = (RESERVED_SHORT_NAMES + self.fields.len()).to_string();
        let old = self.fields.insert(name, field);
        if old.is_some() {
            panic!("Cannot insert an existing field into an entity");
        }
    }

    pub fn add_index(&mut self, index: Index) -> Result<(), Error> {
        let name = index.name();
        if self.indexes.contains_key(&name) {
            return Err(Error::InvalidQuery(format!(
                "Index '{}' allready exists",
                name
            )));
        }
        self.indexes.insert(name, index);
        Ok(())
    }

    ///
    /// retrieve an entity field definition
    ///
    pub fn get_field(&self, name: &str) -> Result<&Field, Error> {
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

    fn check_consistency(&self) -> Result<(), Error> {
        for index in self.indexes.values() {
            for field in &index.fields {
                if let Some(e) = self.fields.get(field) {
                    match e.field_type {
                        FieldType::Array(_) | FieldType::Entity(_) => {
                            return Err(Error::InvalidQuery(format!(
                                "Invalid Index: field '{}' cannot be indexed because of its type '{}'. Only scalar values can be indexed ",
                                field, e.field_type
                            )));
                        }
                        _ => {}
                    }
                } else {
                    return Err(Error::InvalidQuery(format!(
                        "Invalid Index: field '{}' does not exist in entity '{}' ",
                        field, self.name
                    )));
                }
            }
        }
        Ok(())
    }
}

#[derive(Debug, Clone)]
pub struct Field {
    pub name: String,
    pub short_name: String,
    pub field_type: FieldType,
    pub default_value: Option<Value>,
    pub nullable: bool,
    pub deprecated: bool,
    pub mutable: bool,
    pub is_system: bool,
}
impl Default for Field {
    fn default() -> Self {
        Field::new()
    }
}
impl Field {
    pub fn new() -> Self {
        Self {
            name: "".to_string(),
            short_name: "".to_string(),
            field_type: FieldType::Boolean,
            default_value: None,
            nullable: false,
            deprecated: false,
            mutable: true,
            is_system: false,
        }
    }

    pub fn get_variable_type(&self) -> VariableType {
        match self.field_type {
            FieldType::Array(_) | FieldType::Entity(_) => VariableType::Invalid,
            FieldType::Base64 => VariableType::Base64(self.nullable),
            FieldType::Boolean => VariableType::Boolean(self.nullable),
            FieldType::Integer => VariableType::Integer(self.nullable),
            FieldType::Float => VariableType::Float(self.nullable),
            FieldType::String | FieldType::Json => VariableType::String(self.nullable),
        }
    }

    pub fn get_variable_type_non_nullable(&self) -> VariableType {
        match self.field_type {
            FieldType::Array(_) | FieldType::Entity(_) => VariableType::Invalid,
            FieldType::Base64 => VariableType::Base64(false),
            FieldType::Boolean => VariableType::Boolean(false),
            FieldType::Integer => VariableType::Integer(false),
            FieldType::Float => VariableType::Float(false),
            FieldType::String | FieldType::Json => VariableType::String(false),
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
            r#"
                @deprecated Person {
                    name : String ,
                    surname : String nullable,
                    child : [Person] nullable,
                    mother : Person ,
                    father : Person NULLABLE, 
                    index(name, surname),
                     
                }

                Pet {
                    name : String default "John",
                    surname : String NULLABLE,
                    owners : [Person],
                    @deprecated  age : Float NULLABLE,
                    weight : Integer NULLABLE,
                    is_vaccinated: Boolean NULLABLE,
                    INDEX(weight)
                }
          "#,
        )
        .unwrap();

        let pet = datamodel.entities.get("Pet").unwrap();
        assert_eq!("Pet", pet.name);

        let age = pet.fields.get("age").unwrap();
        assert_eq!(FieldType::Float.type_id(), age.field_type.type_id());
        assert_eq!(true, age.nullable);

        let name = pet.fields.get("name").unwrap();
        assert_eq!(FieldType::String.type_id(), name.field_type.type_id());
        assert_eq!(false, name.nullable);
        if let Some(Value::String(e)) = &name.default_value {
            assert_eq!("John", e);
        }

        let surname = pet.fields.get("surname").unwrap();
        assert_eq!(FieldType::String.type_id(), surname.field_type.type_id());
        assert_eq!(true, surname.nullable);

        let owner = pet.fields.get("owners").unwrap();
        match &owner.field_type {
            FieldType::Array(e) => assert_eq!("Person", e),
            _ => unreachable!(),
        }
        assert_eq!(false, owner.nullable);

        let index = &pet.indexes;
        assert_eq!(1, index.len());
        for i in index.values() {
            assert_eq!("weight", i.fields[0])
        }

        let weight = pet.fields.get("weight").unwrap();
        assert_eq!(FieldType::Integer.type_id(), weight.field_type.type_id());
        assert_eq!(true, weight.nullable);

        let is_vaccinated = pet.fields.get("is_vaccinated").unwrap();
        assert_eq!(
            FieldType::Boolean.type_id(),
            is_vaccinated.field_type.type_id()
        );
        assert_eq!(true, is_vaccinated.nullable);

        let person = datamodel.entities.get("Person").unwrap();
        assert_eq!("Person", person.name);
        let name = person.fields.get("name").unwrap();
        assert_eq!(FieldType::String.type_id(), name.field_type.type_id());
        assert_eq!(false, name.nullable);

        let surname = person.fields.get("surname").unwrap();
        assert_eq!(FieldType::String.type_id(), surname.field_type.type_id());
        assert_eq!(true, surname.nullable);

        let child = person.fields.get("child").unwrap();
        match &child.field_type {
            FieldType::Array(e) => assert_eq!("Person", e),
            _ => unreachable!(),
        }
        assert_eq!(true, child.nullable);

        let mother = person.fields.get("mother").unwrap();
        match &mother.field_type {
            FieldType::Entity(e) => assert_eq!("Person", e),
            _ => unreachable!(),
        }
        assert_eq!(false, mother.nullable);

        let father = person.fields.get("father").unwrap();
        match &father.field_type {
            FieldType::Entity(e) => assert_eq!("Person", e),
            _ => unreachable!(),
        }
        assert_eq!(true, father.nullable);

        //println!("{:#?}", datamodel)
    }

    #[test]
    fn invalid_entity() {
        let _datamodel = DataModel::parse(
            "
                Person {
                    child : [InvalidEntity],
                }",
        )
        .expect_err("InvalidEntity is not defined in the datamodel");

        let _datamodel = DataModel::parse(
            "
                Person {
                    child : [Boolean],
                }",
        )
        .expect_err("Cannot reference scalar field");

        let _datamodel = DataModel::parse(
            "
                Person {
                    child : [integer],
                }",
        )
        .expect_err("Cannot reference scalar field");

        let _datamodel = DataModel::parse(
            "
                Person {
                    child : [float],
                }",
        )
        .expect_err("Cannot reference scalar field");

        let _datamodel = DataModel::parse(
            "
                Person {
                    child : [json],
                }",
        )
        .expect_err("Cannot reference scalar field");

        let _datamodel = DataModel::parse(
            "
                Person {
                    child : [base64],
                }",
        )
        .expect_err("Cannot reference scalar field");

        let _datamodel = DataModel::parse(
            "
                Person {
                    child : [Person],
                }",
        )
        .expect("Person a valid entity");

        let _datamodel = DataModel::parse(
            "
                Person {
                    mother : InvalidEntity,
                }",
        )
        .expect_err("InvalidEntity is not defined in the datamodel");

        let _datamodel = DataModel::parse(
            "
                Person {
                    mother : Person,
                }",
        )
        .expect("Person is a valid entity");
    }

    #[test]
    fn reserved_names() {
        let _datamodel = DataModel::parse(
            "
                _Person {
                    name : String,
                }",
        )
        .expect_err("entity name cannot start with a _");

        let _datamodel = DataModel::parse(
            "
                Person {
                    _name : String,
                }",
        )
        .expect_err("entity field name cannot start with a _");

        let _datamodel = DataModel::parse(
            "
                Per_son_ {
                    na_me_ : String,
                }",
        )
        .expect("entity and field name can contain _");

        let _datamodel = DataModel::parse(
            "
                Person {
                    String : String,
                }",
        )
        .expect_err("scalar field names are reserved");

        let _datamodel = DataModel::parse(
            "
                json {
                    name : String,
                }",
        )
        .expect_err("scalar field names are reserved");
        let _datamodel = DataModel::parse(
            "
            baSe64 {
                name : String,
            }",
        )
        .expect_err("scalar field names are reserved");
        let _datamodel = DataModel::parse(
            "
        String {
            name : String,
        }",
        )
        .expect_err("scalar field names are reserved");
        let _datamodel = DataModel::parse(
            "
        floAt {
            name : String,
        }",
        )
        .expect_err("scalar field names are reserved");
        let _datamodel = DataModel::parse(
            "
        INTEGer {
            name : String,
        }",
        )
        .expect_err("scalar field names are reserved");
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
                }",
        )
        .expect_err("Person is duplicated");

        let _datamodel = DataModel::parse(
            "
                Person {
                    child : [Person],
                }",
        )
        .expect("Person is not duplicated anymore");

        let _datamodel = DataModel::parse(
            "
                Person {
                    child : String,
                    child : [Person],
                } ",
        )
        .expect_err("child is duplicated");

        let _datamodel = DataModel::parse(
            "
                Person {
                    name : String,
                    child : [Person],
                }",
        )
        .expect("child is not duplicated anymore");
    }

    #[test]
    fn parse_invalid_string() {
        let _datamodel = DataModel::parse(
            "
                Person {
                    child : [Person],
                    name: String
                }",
        )
        .expect("missing [ before person");

        let _datamodel = DataModel::parse(
            "
                Person @deprecated {
                    mother : Person,
                }",
        )
        .expect_err("@deprecated must be before the entity name");

        let _datamodel = DataModel::parse(
            "
                @deprecated Person  {
                    mother : Person,
                }",
        )
        .expect("@deprecated must be before the entity name");
    }

    #[test]
    fn default_value() {
        let _datamodel = DataModel::parse(
            r#"
                Person {
                    is_vaccinated : Boolean default "true" ,
                }"#,
        )
        .expect_err("default must be a boolean not a string");

        let _datamodel = DataModel::parse(
            r#"
                Person {
                    is_vaccinated : Boolean default false ,
                }"#,
        )
        .expect("default is a boolean");

        let _datamodel = DataModel::parse(
            r#"
                Person {
                    weight : Float default true ,
                }"#,
        )
        .expect_err("default must be a Float not a boolean");

        let _datamodel = DataModel::parse(
            r#"
                Person {
                    weight : Float default 12 ,
                }"#,
        )
        .expect("default is an Integer which will be parsed to a Float");

        let _datamodel = DataModel::parse(
            r#"
                Person {
                    weight : Float default 12.5 ,
                }"#,
        )
        .expect("default is an Float");

        let _datamodel = DataModel::parse(
            r#"
                Person {
                    age : Integer default 12.5 ,
                }"#,
        )
        .expect_err("default must be a Integer not a Float");

        let _datamodel = DataModel::parse(
            r#"
                Person {
                    age : Integer default 12 ,
                }"#,
        )
        .expect("default is an Integer");

        let _datamodel = DataModel::parse(
            "
                Person {
                    name : String default 12.2 ,
                }",
        )
        .expect_err("default must be a string not a float");

        let _datamodel = DataModel::parse(
            r#"
                Person {
                    name : String default "test" ,
                }"#,
        )
        .expect("default is a string");
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
        field.name = BINARY_FIELD.to_string();
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

    #[test]
    fn index() {
        let _datamodel = DataModel::parse(
            "
                Person {
                    name : String,
                    child : [Person],
                    father: Person,
                    index(invalid_field)
                }",
        )
        .expect_err("index has an invalid field name");

        let _datamodel = DataModel::parse(
            "
                Person {
                    name : String,
                    child : [Person],
                    father: Person,
                    index(child)
                }",
        )
        .expect_err("child cannot be indexed because it is not a scalar type");

        let _datamodel = DataModel::parse(
            "
                Person {
                    name : String,
                    child : [Person],
                    father: Person,
                    index(father)
                }",
        )
        .expect_err("father cannot be indexed because it is not a scalar type");

        let _datamodel = DataModel::parse(
            "
                Person {
                    name : String,
                    child : [Person],
                    father: Person,
                    index(name, name)
                }",
        )
        .expect_err("name is repeated twice");

        let _datamodel = DataModel::parse(
            "
                Person {
                    name : String,
                    child : [Person],
                    father: Person,
                    index(name),
                    index(name)
                }",
        )
        .expect_err("index(name) is defined twice");

        let _datamodel = DataModel::parse(
            "
                Person {
                    name : String,
                    child : [Person],
                    father: Person,
                    index(name)
                }",
        )
        .expect("index is valid");
    }

    #[test]
    fn entity_update() {
        let mut datamodel = DataModel::new();
        datamodel
            .update(
                "
                Person {
                    name : String,
                }",
            )
            .unwrap();

        let person = datamodel.entities.get("Person").unwrap();
        assert_eq!(RESERVED_SHORT_NAMES.to_string(), person.short_name);

        datamodel
            .update(
                "
                Pesrson {
                    name : String,
                }",
            )
            .expect_err("missing Person");

        datamodel
            .update(
                "
                @deprecated Pet {
                    name : String,
                }

                Person {
                    name : String,
                } ",
            )
            .unwrap();
        //entity order in the updated datamodel does not change the existing short names
        let person = datamodel.entities.get("Person").unwrap();
        assert_eq!(RESERVED_SHORT_NAMES.to_string(), person.short_name);
        let pet = datamodel.entities.get("Pet").unwrap();
        assert_eq!((RESERVED_SHORT_NAMES + 1).to_string(), pet.short_name);
        assert!(pet.deprecated);

        datamodel
            .update(
                "
            Pet {
                name : String,
            }

            @deprecated Person {
                name : String,
            } ",
            )
            .unwrap();

        let person = datamodel.entities.get("Person").unwrap();
        assert!(person.deprecated);
        let pet = datamodel.entities.get("Pet").unwrap();
        assert!(!pet.deprecated);
    }

    #[test]
    fn field_update() {
        let mut datamodel = DataModel::new();
        datamodel
            .update(
                "Person {
                    name : String,
                }",
            )
            .unwrap();

        let person = datamodel.entities.get("Person").unwrap();
        let name = person.get_field("name").unwrap();
        assert_eq!(RESERVED_SHORT_NAMES.to_string(), name.short_name);

        datamodel
            .update(
                "Person {
                name : Integer,
            }",
            )
            .expect_err("Cannot change a field type");

        datamodel
            .update(
                "Person {
                name : String nullable,
            }",
            )
            .expect("Field can be changed to nullable");

        datamodel
            .update(
                "Person {
                name : String,
            }",
            )
            .expect_err("Field cannot be changed to not nullable without a default value");

        datamodel
            .update(
                r#"Person {
                name : String default "",
            }"#,
            )
            .expect(
                "Field can be changed to not nullable with a default value, even an empty string",
            );

        datamodel
            .update(
                r#"Person {
                name : String default "",
                age : Integer
            }"#,
            )
            .expect_err("New Field that are not nullable must have a default value");

        datamodel
            .update(
                r#"Person {
                age : Integer default 0,
                name : String default "",
            }"#,
            )
            .expect("New Field that are not nullable must have a default value");

        let person = datamodel.entities.get("Person").unwrap();
        let name = person.get_field("name").unwrap();
        assert_eq!(RESERVED_SHORT_NAMES.to_string(), name.short_name);
        let age = person.get_field("age").unwrap();
        assert_eq!((RESERVED_SHORT_NAMES + 1).to_string(), age.short_name);
    }

    #[test]
    fn index_update() {
        let mut datamodel = DataModel::new();
        datamodel
            .update(
                "Person {
                    name : String,
                    index(name)
                }",
            )
            .unwrap();

        datamodel
            .update(
                "Person {
                    name : String,
                    index(name)
                }",
            )
            .unwrap();

        datamodel
            .update(
                "Person {
                    name : String,
                }",
            )
            .unwrap();
        let person = datamodel.get_entity("Person").unwrap();
        assert_eq!(0, person.indexes.len());
        assert_eq!(1, person.indexes_to_remove.len());
    }

    #[test]
    fn base64_field() {
        let mut datamodel = DataModel::new();
        datamodel
            .update(
                "Person {
                    name : Base64,
                }",
            )
            .expect("valid");

        let mut datamodel = DataModel::new();
        datamodel
            .update(
                r#"Person {
                        name : Base64 default "?%&JVBQS0pP",
                    }"#,
            )
            .expect_err("invalid default value");

        let mut datamodel = DataModel::new();
        datamodel
            .update(
                r#"Person {
                            name : Base64 default "JVBQS0pP",
                        }"#,
            )
            .expect("valid default value");
    }

    #[test]
    fn json_field() {
        let mut datamodel = DataModel::new();
        datamodel
            .update(
                "Person {
                    name : Json,
                }",
            )
            .expect("valid Json");

        let mut datamodel = DataModel::new();
        datamodel
            .update(
                r#"Person {
                        name : Json default "qsd",
                    }"#,
            )
            .expect_err("invalid default value");

        let mut datamodel = DataModel::new();
        datamodel
            .update(
                r#"Person {
                            name : Json default "[1,2,3]",
                        }"#,
            )
            .expect("valid default value");
    }
}
