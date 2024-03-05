use crate::{
    cryptography::base64_decode,
    database::{
        configuration::{
            AUTHORS_FIELD, AUTHORS_FIELD_SHORT, AUTHOR_ENT, BINARY_FIELD, CREATION_DATE_FIELD,
            ENTITY_FIELD, ID_FIELD, JSON_FIELD, MODIFICATION_DATE_FIELD, PUB_KEY_FIELD,
            ROOMS_FIELD, ROOMS_FIELD_SHORT, ROOM_ENT, SIGNATURE_FIELD,
        },
        node::ARCHIVED_CHAR,
    },
};

use super::{Error, FieldType, Value, VariableType};
use pest::iterators::Pair;
use pest::Parser;
use pest_derive::Parser;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

#[derive(Parser)]
#[grammar = "database/query_language/data_model.pest"]
struct PestParser;

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

        fields.insert(
            AUTHORS_FIELD.to_string(),
            Field {
                name: AUTHORS_FIELD.to_string(),
                short_name: AUTHORS_FIELD_SHORT.to_string(),
                field_type: FieldType::Array(AUTHOR_ENT.to_string()),
                default_value: None,
                nullable: false,
                deprecated: false,
                mutable: false,
                is_system: false,
            },
        );


        fields.insert(
            ROOMS_FIELD.to_string(),
            Field {
                name: ROOMS_FIELD.to_string(),
                short_name: ROOMS_FIELD_SHORT.to_string(),
                field_type: FieldType::Array(ROOM_ENT.to_string()),
                default_value: None,
                nullable: true,
                deprecated: false,
                mutable: true,
                is_system: false,
            },
        );




        fields

    };
}

/// Reserve the first 64 short_id for system usage.
/// This is an arbitrary value wich should be plenty enought
/// applies to entity and field
pub const RESERVED_SHORT_NAMES: usize = 32;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DataModel {
    model: String,
    entities: HashMap<String, Entity>,
    entities_short: HashMap<String, String>,
    entities_archive: HashMap<String, Entity>,
}
impl Default for DataModel {
    fn default() -> Self {
        DataModel::new()
    }
}
impl DataModel {
    pub fn new() -> Self {
        Self {
            model: String::from(""),
            entities: HashMap::new(),
            entities_short: HashMap::new(),
            entities_archive: HashMap::new(),
        }
    }

    pub fn add_entity(&mut self, entity: Entity, system: bool) -> Result<(), Error> {
        if self.entities.contains_key(&entity.name) {
            return Err(Error::DuplicatedEntity(entity.name.clone()));
        }
        if system {
            self.insert(entity.name.clone(), entity, 0)?;
        } else {
            self.insert(entity.name.clone(), entity, RESERVED_SHORT_NAMES)?;
        }
        Ok(())
    }

    fn insert(&mut self, name: String, mut entity: Entity, name_decal: usize) -> Result<(), Error> {
        entity.short_name = (name_decal + self.entities.len()).to_string();
        let old = self.entities.insert(name, entity);
        if old.is_some() {
            panic!("Cannot insert an existing entity in the datamodel")
        }
        Ok(())
    }

    pub fn get_entity(&self, name: &str) -> Result<&Entity, Error> {
        if name.starts_with(ARCHIVED_CHAR) {
            if let Some(entity) = self.entities_archive.get(name) {
                Ok(entity)
            } else {
                Err(Error::InvalidQuery(format!(
                    "Deletion Entity '{}' not found in the data model",
                    name
                )))
            }
        } else if let Some(entity) = self.entities.get(name) {
            Ok(entity)
        } else {
            Err(Error::InvalidQuery(format!(
                "Entity '{}' not found in the data model",
                name
            )))
        }
    }

    pub fn update(&mut self, model: &str) -> Result<(), Error> {
        let new_data_model = Self::parse_internal(model, false)?;
        self.update_with(new_data_model, false)?;
        Ok(())
    }

    pub fn update_system(&mut self, model: &str) -> Result<(), Error> {
        let new_data_model = Self::parse_internal(model, true)?;
        self.update_with(new_data_model, true)?;
        Ok(())
    }

    pub fn update_with(&mut self, mut new_data_model: Self, system: bool) -> Result<(), Error> {
        for entity in &mut self.entities {
            if (system && entity.1.name.starts_with('_'))
                || (!system && !entity.1.name.starts_with('_'))
            {
                let new_entity_op = new_data_model.entities.remove(entity.0);
                match new_entity_op {
                    Some(new_entity) => {
                        let old_entity = entity.1;
                        if !old_entity.short_name.eq(&new_entity.short_name) {
                            let mut new_pos: usize = new_entity.short_name.parse()?;
                            new_pos -= RESERVED_SHORT_NAMES;
                            let mut previous_pos: usize = old_entity.short_name.parse()?;
                            previous_pos -= RESERVED_SHORT_NAMES;

                            return Err(Error::InvalidEntityOrdering(
                                String::from(&old_entity.name),
                                new_pos,
                                previous_pos,
                            ));
                        }
                        old_entity.update(new_entity)?
                    }
                    None => return Err(Error::MissingEntity(String::from(entity.0))),
                }
            }
        }
        for entity in new_data_model.entities {
            if (system && entity.1.name.starts_with('_'))
                || (!system && !entity.1.name.starts_with('_'))
            {
                let mut deletion = entity.1.clone();
                deletion.short_name = format!("{}{}", ARCHIVED_CHAR, deletion.short_name);
                deletion.name = format!("{}{}", ARCHIVED_CHAR, deletion.name);

                self.entities_short
                    .insert(deletion.short_name.clone(), deletion.name.clone());

                self.entities_archive
                    .insert(deletion.name.clone(), deletion.clone());

                self.entities_short
                    .insert(entity.1.short_name.clone(), entity.1.name.clone());

                self.entities.insert(entity.0, entity.1);
            }
        }
        self.model = new_data_model.model;
        Ok(())
    }

    pub fn name_for(&self, short_name: &str) -> Option<&String> {
        self.entities_short.get(short_name)
    }

    fn parse_internal(model: &str, system: bool) -> Result<DataModel, Error> {
        let mut data_model = DataModel::new();
        data_model.model = String::from(model);
        let parse = match PestParser::parse(Rule::datamodel, model) {
            Err(e) => {
                let message = format!("{}", e);
                return Err(Error::Parser(message));
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
                            let entity = Self::parse_entity(pair, system)?;
                            data_model.add_entity(entity, system)?;
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

    fn parse_entity(pair: Pair<'_, Rule>, system: bool) -> Result<Entity, Error> {
        let mut entity = Entity::new();
        for entity_pair in pair.into_inner() {
            match entity_pair.as_rule() {
                Rule::deprecable_identifier => {
                    for i in entity_pair.into_inner() {
                        match i.as_rule() {
                            Rule::deprecated => entity.deprecated = true,
                            Rule::identifier => {
                                let name = i.as_str();
                                if (name.starts_with('_') && !system)
                                    || (!name.starts_with('_') && system)
                                {
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
        matches!(
            value.to_lowercase().as_str(),
            "boolean" | "float" | "integer" | "string" | "base64" | "json"
        )
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
                                    let pair = value_pair.into_inner().next().unwrap();
                                    let value = pair.as_str().replace("\\\"", "\"");
                                    match field.field_type {
                                        FieldType::String => {
                                            field.default_value =
                                                Some(Value::String(value.to_string()))
                                        }
                                        FieldType::Base64 => {
                                            let decode = base64_decode(value.as_bytes());
                                            if decode.is_err() {
                                                return Err(Error::InvalidBase64(value));
                                            }
                                            field.default_value = Some(Value::String(value))
                                        }
                                        FieldType::Json => {
                                            let v: std::result::Result<
                                                serde_json::Value,
                                                serde_json::Error,
                                            > = serde_json::from_str(&value);
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
                field.nullable = false;
            }
            Rule::entity_array => {
                let mut entity_field = field_type.into_inner();
                let name = entity_field.next().unwrap().as_str();
                if Self::is_reserved(name) {
                    return Err(Error::ReservedKeyword(name.to_string()));
                }

                field.field_type = FieldType::Array(String::from(name));
                field.nullable = false;
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
                            return Err(Error::Parser(format!(
                            "entity {} does not exist. Please check the definition of the {}.{}:[{}] field",
                            e, entity.name, field.name, e
                        )));
                        }
                    }
                    FieldType::Entity(e) => {
                        if !self.entities.contains_key(e) {
                            return Err(Error::Parser(format!(
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

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Index {
    pub fields: Vec<String>,
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
#[derive(Debug, Clone, Serialize, Deserialize)]
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
                    if !field.short_name.eq(&new_field.short_name) {
                        let mut new_pos: usize = new_field.short_name.parse()?;
                        new_pos -= RESERVED_SHORT_NAMES;
                        let mut previous_pos: usize = field.short_name.parse()?;
                        previous_pos -= RESERVED_SHORT_NAMES;

                        return Err(Error::InvalidFieldOrdering(
                            String::from(&self.name),
                            String::from(&field.name),
                            new_pos,
                            previous_pos,
                        ));
                    }
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

#[derive(Debug, Clone, Serialize, Deserialize)]
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
