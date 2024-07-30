use crate::{
    database::system_entities::{
        BINARY_FIELD, CREATION_DATE_FIELD, ENTITY_FIELD, ID_FIELD, JSON_FIELD,
        MODIFICATION_DATE_FIELD, PEER_ENT, PEER_FIELD, ROOM_ENT, ROOM_FIELD, ROOM_ID_FIELD,
        SIGNATURE_FIELD, SYSTEM_NAMESPACE, VERIFYING_KEY_FIELD,
    },
    security::base64_decode,
};

use super::{Error, FieldType, ParamValue, VariableType};
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
            ROOM_ID_FIELD.to_string(),
            Field {
                name: ROOM_ID_FIELD.to_string(),
                short_name: ROOM_ID_FIELD.to_string(),
                field_type: FieldType::Base64,
                default_value: None,
                nullable: true,
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
            PEER_FIELD.to_string(),
            Field {
                name: PEER_FIELD.to_string(),
                short_name: PEER_FIELD.to_string(),
                field_type: FieldType::Entity(PEER_ENT.to_string()),
                default_value: None,
                nullable: false,
                deprecated: false,
                mutable: false,
                is_system: true,
            },
        );

        fields.insert(
            ROOM_FIELD.to_string(),
            Field {
                name: ROOM_FIELD.to_string(),
                short_name: ROOM_FIELD.to_string(),
                field_type: FieldType::Entity(ROOM_ENT.to_string()),
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
            VERIFYING_KEY_FIELD.to_string(),
            Field {
                name: VERIFYING_KEY_FIELD.to_string(),
                short_name: VERIFYING_KEY_FIELD.to_string(),
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
pub const RESERVED_SHORT_NAMES: usize = 32;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DataModel {
    model: String,
    namespace_ids: HashMap<String, usize>,
    namespaces: HashMap<String, HashMap<String, Entity>>,
    entities_short: HashMap<String, (String, String)>,
}
impl Default for DataModel {
    fn default() -> Self {
        DataModel::new()
    }
}
impl DataModel {
    pub fn new() -> Self {
        Self {
            model: String::new(),
            namespace_ids: HashMap::new(),
            namespaces: HashMap::new(),
            entities_short: HashMap::new(),
        }
    }

    pub fn namespaces(&self) -> &HashMap<String, HashMap<String, Entity>> {
        &self.namespaces
    }

    pub fn get_entity(&self, name: &str) -> Result<&Entity, Error> {
        let split: Vec<&str> = name.split('.').collect();
        let (namespace, name) = if split.len() == 2 {
            let namespace = split[0].to_lowercase();
            (namespace.clone(), format!("{}.{}", namespace, split[1]))
        } else {
            ("".to_string(), name.to_string())
        };

        let namespace = self
            .namespaces
            .get(&namespace)
            .ok_or(Error::NamespaceNotFound(namespace.to_string()))?;

        let entity = namespace
            .get(&name)
            .ok_or(Error::EntityNotFound(name.to_string()))?;
        Ok(entity)
    }

    fn insert(&mut self, name_space: &str, mut entity: Entity, decal: usize) -> Result<(), Error> {
        let namespace_short = match self.namespaces.contains_key(name_space) {
            true => *self.namespace_ids.get(name_space).unwrap(),
            false => {
                let ns_id = self.namespace_ids.len() + decal;
                self.namespace_ids.insert(name_space.to_string(), ns_id);
                self.namespaces
                    .insert(name_space.to_string(), HashMap::new());
                ns_id
            }
        };

        let entities = self.namespaces.get_mut(name_space).unwrap();

        if entities.contains_key(&entity.name) {
            return Err(Error::DuplicatedEntity(entity.name.clone()));
        }
        if name_space.is_empty() {
            entity.short_name = format!("{}", entities.len());
        } else {
            entity.short_name = format!("{}.{}", namespace_short, entities.len());
        }

        self.entities_short.insert(
            entity.short_name.clone(),
            (name_space.to_string(), entity.name.clone()),
        );
        entities.insert(entity.name.clone(), entity);
        Ok(())
    }

    fn add_index(&mut self, name_space: &str, entity: &str, index: Index) -> Result<(), Error> {
        let namespace = self
            .namespaces
            .get_mut(name_space)
            .ok_or(Error::NamespaceNotFound(name_space.to_string()))?;

        let ent = namespace
            .get_mut(entity)
            .ok_or(Error::EntityNotFound(entity.to_string()))?;

        if ent.indexes.get(&index.name()).is_some() {
            return Err(Error::IndexAllreadyExists(
                index.name(),
                name_space.to_string(),
                entity.to_string(),
            ));
        }
        ent.indexes.insert(index.name(), index);

        Ok(())
    }

    pub fn update_system(&mut self, model: &str) -> Result<(), Error> {
        let new_data_model = Self::parse_internal(model, 0)?;
        self.update_with(new_data_model, true)?;
        Ok(())
    }

    pub fn update(&mut self, model: &str) -> Result<(), Error> {
        let new_data_model = Self::parse_internal(model, 1)?; //decal namespace id by one to reserce the first id to the sys namespace
        self.update_with(new_data_model, false)?;
        Ok(())
    }

    pub fn update_with(&mut self, mut new_data_model: Self, system: bool) -> Result<(), Error> {
        for namespace in &new_data_model.namespace_ids {
            if system && !SYSTEM_NAMESPACE.eq(namespace.0) {
                return Err(Error::NamespaceUpdate(format!(
                    "DataModel System update can only contains the {} namespace",
                    SYSTEM_NAMESPACE
                )));
            }
            if !system && SYSTEM_NAMESPACE.eq(namespace.0) {
                return Err(Error::NamespaceUpdate(format!(
                    "{} is a reserved namespace",
                    SYSTEM_NAMESPACE
                )));
            }
        }

        for ns in &mut self.namespaces {
            match new_data_model.namespaces.remove(ns.0) {
                Some(mut new_entity) => {
                    let new_ns_id = new_data_model.namespace_ids.remove(ns.0).unwrap();
                    let old_ns_id = *self.namespace_ids.get(ns.0).unwrap();
                    if new_ns_id != old_ns_id {
                        return Err(Error::InvalidNamespaceOrdering(
                            ns.0.to_string(),
                            new_ns_id,
                            old_ns_id,
                        ));
                    }

                    for entity in ns.1.iter_mut() {
                        let new_entity_op = new_entity.remove(entity.0);
                        match new_entity_op {
                            Some(new_entity) => {
                                let old_entity = entity.1;
                                if !old_entity.short_name.eq(&new_entity.short_name) {
                                    return Err(Error::InvalidEntityOrdering(
                                        String::from(&old_entity.name),
                                        old_entity.short_name.to_string(),
                                        new_entity.short_name.to_string(),
                                    ));
                                }
                                old_entity.update(new_entity)?
                            }
                            None => return Err(Error::MissingEntity(String::from(entity.0))),
                        }
                    }

                    for entity in new_entity {
                        self.entities_short.insert(
                            entity.1.short_name.clone(),
                            (ns.0.clone(), entity.1.name.clone()),
                        );
                        ns.1.insert(entity.0, entity.1);
                    }
                }
                None => {
                    if !system && !SYSTEM_NAMESPACE.eq(ns.0) {
                        return Err(Error::MissingNamespace(ns.0.to_string()));
                    }
                }
            }
        }
        for ns in new_data_model.namespaces {
            let ns_id = *new_data_model.namespace_ids.get(&ns.0).unwrap();
            self.namespace_ids.insert(ns.0.clone(), ns_id);
            for entity in &ns.1 {
                self.entities_short.insert(
                    entity.1.short_name.clone(),
                    (ns.0.clone(), entity.1.name.clone()),
                );
            }
            self.namespaces.insert(ns.0, ns.1);
        }
        self.model = new_data_model.model;
        Ok(())
    }

    pub fn name_for(&self, short_name: &str) -> Option<String> {
        match self.entities_short.get(short_name) {
            Some(v) => Some(v.1.to_string()),

            None => None,
        }
    }

    fn parse_internal(model: &str, decal: usize) -> Result<DataModel, Error> {
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
                for pair in parse.into_inner() {
                    let namespace_pairs = pair.into_inner();
                    let mut name_space = String::from("");
                    for pair in namespace_pairs.into_iter() {
                        match pair.as_rule() {
                            Rule::identifier => {
                                name_space = pair.as_str().to_lowercase();
                            }
                            Rule::entity => {
                                let entry = Self::parse_entity(pair)?;
                                let mut entity = entry.0;
                                if !name_space.is_empty() {
                                    entity.name = format!("{}.{}", name_space, entity.name);
                                }
                                let name = entity.name.clone();
                                data_model.insert(&name_space, entity, decal)?;

                                for index_vec in entry.1 {
                                    let ent = data_model.get_entity(&name)?;
                                    let mut index =
                                        Index::new(name.clone(), ent.short_name.clone());
                                    for field_name in &index_vec {
                                        let field = ent.get_field(field_name)?;
                                        index.add_field(field.clone())?;
                                    }
                                    data_model.add_index(&name_space, &name, index)?;
                                }
                            }
                            Rule::EOI => {}
                            _ => unreachable!(),
                        }
                    }
                }
            }
            _ => unreachable!(),
        }
        data_model.check_consistency()?;
        Ok(data_model)
    }

    fn parse_entity(pair: Pair<'_, Rule>) -> Result<(Entity, Vec<Vec<String>>), Error> {
        let mut entity = Entity::new();
        let mut parsed_index = Vec::new();
        for entity_pair in pair.into_inner() {
            match entity_pair.as_rule() {
                Rule::deprecable_identifier => {
                    for i in entity_pair.into_inner() {
                        match i.as_rule() {
                            Rule::deprecated => entity.deprecated = true,
                            Rule::identifier => {
                                let name = i.as_str();
                                if Self::is_reserved(name) {
                                    return Err(Error::ReservedKeyword(name.to_string()));
                                }
                                entity.name = name.to_string();
                            }
                            _ => unreachable!(),
                        }
                    }
                }
                Rule::entity_param => {
                    for pair in entity_pair.into_inner() {
                        match pair.as_rule() {
                            Rule::disable_feature => {
                                let disable = pair.into_inner().next().unwrap();
                                match disable.as_rule() {
                                    Rule::no_full_text_index => entity.enable_full_text = false,
                                    _ => unreachable!(),
                                }
                            }
                            Rule::comma => {}
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
                                let index = Self::parse_index(i);
                                parsed_index.push(index);
                            }

                            _ => unreachable!(),
                        }
                    }
                }
                Rule::comma => {}
                _ => unreachable!(),
            }
        }

        //     entity.check_consistency()?;
        Ok((entity, parsed_index))
    }

    fn parse_index(entity_pair: Pair<'_, Rule>) -> Vec<String> {
        let mut index = Vec::new();

        for field in entity_pair.into_inner() {
            match field.as_rule() {
                Rule::identifier => index.push(field.as_str().to_string()),
                Rule::comma => {}
                _ => unreachable!(),
            }
        }
        index
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
                                                Some(ParamValue::Boolean(value.parse()?))
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
                                            field.default_value =
                                                Some(ParamValue::Float(value.parse()?))
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
                                            field.default_value =
                                                Some(ParamValue::Float(value.parse()?))
                                        }
                                        FieldType::Integer => {
                                            field.default_value =
                                                Some(ParamValue::Integer(value.parse()?))
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
                                                Some(ParamValue::String(value.to_string()))
                                        }
                                        FieldType::Base64 => {
                                            let decode = base64_decode(value.as_bytes());
                                            if decode.is_err() {
                                                return Err(Error::InvalidBase64(value));
                                            }
                                            field.default_value = Some(ParamValue::String(value))
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
                                                Some(ParamValue::String(value.to_string()))
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
                field.nullable = entity_field.next().is_some();
            }
            Rule::entity_array => {
                let mut entity_field = field_type.into_inner();
                let name = entity_field.next().unwrap().as_str();
                if Self::is_reserved(name) {
                    return Err(Error::ReservedKeyword(name.to_string()));
                }

                field.field_type = FieldType::Array(String::from(name));
                field.nullable = entity_field.next().is_some();
            }

            _ => unreachable!(),
        }
        Ok(field)
    }

    fn check_consistency(&self) -> Result<(), Error> {
        for namespace in &self.namespaces {
            for entry in namespace.1 {
                let entity = entry.1;
                for field_entry in &entity.fields {
                    let field = field_entry.1;
                    match &field.field_type {
                        FieldType::Array(e) => {
                            if self.get_entity(e).is_err() {
                                return Err(Error::Parser(format!(
                                    "entity {} does not exist. Please check the definition of the {}.{}:[{}] field",
                                    e, entity.name, field.name, e
                                )));
                            }
                        }
                        FieldType::Entity(e) => {
                            if self.get_entity(e).is_err() {
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
        }
        Ok(())
    }
}

pub fn validate_json_for_entity(
    entity: &Entity,
    json: &Option<String>,
) -> Result<(), crate::database::Error> {
    if let Some(json_str) = json {
        let json: serde_json::Value = serde_json::from_str(json_str)?;
        if !json.is_object() {
            return Err(crate::database::Error::InvalidJsonObject(
                "in NodeFull".to_string(),
            ));
        }
        let json = json.as_object().unwrap();
        for f in &entity.fields {
            let name = f.0;
            let field = f.1;
            let short_name = &field.short_name;
            if !field.is_system {
                match field.field_type {
                    FieldType::Boolean => {
                        match json.get(short_name) {
                            Some(value) => {
                                if value.as_bool().is_none() {
                                    return Err(crate::database::Error::InvalidJsonFieldValue(
                                        name.to_string(),
                                        "Boolean".to_string(),
                                    ));
                                }
                            }
                            None => {
                                if !field.nullable && field.default_value.is_none() {
                                    return Err(crate::database::Error::MissingJsonField(
                                        name.to_string(),
                                    ));
                                }
                            }
                        };
                    }
                    FieldType::Float => {
                        match json.get(short_name) {
                            Some(value) => {
                                if value.as_f64().is_none() {
                                    return Err(crate::database::Error::InvalidJsonFieldValue(
                                        name.to_string(),
                                        "Float".to_string(),
                                    ));
                                }
                            }
                            None => {
                                if !field.nullable && field.default_value.is_none() {
                                    return Err(crate::database::Error::MissingJsonField(
                                        name.to_string(),
                                    ));
                                }
                            }
                        };
                    }
                    FieldType::Base64 => {
                        match json.get(short_name) {
                            Some(value) => {
                                match value.as_str() {
                                    Some(str) => base64_decode(str.as_bytes())?,
                                    None => {
                                        return Err(crate::database::Error::InvalidJsonFieldValue(
                                            name.to_string(),
                                            "Base64".to_string(),
                                        ))
                                    }
                                };
                            }
                            None => {
                                if !field.nullable && field.default_value.is_none() {
                                    return Err(crate::database::Error::MissingJsonField(
                                        name.to_string(),
                                    ));
                                };
                            }
                        };
                    }
                    FieldType::Integer => {
                        match json.get(short_name) {
                            Some(value) => {
                                if value.as_i64().is_none() {
                                    return Err(crate::database::Error::InvalidJsonFieldValue(
                                        name.to_string(),
                                        "Integer".to_string(),
                                    ));
                                }
                            }
                            None => {
                                if !field.nullable && field.default_value.is_none() {
                                    return Err(crate::database::Error::MissingJsonField(
                                        name.to_string(),
                                    ));
                                }
                            }
                        };
                    }
                    FieldType::String => {
                        match json.get(short_name) {
                            Some(value) => {
                                if value.as_str().is_none() {
                                    return Err(crate::database::Error::InvalidJsonFieldValue(
                                        name.to_string(),
                                        "String".to_string(),
                                    ));
                                }
                            }
                            None => {
                                if !field.nullable && field.default_value.is_none() {
                                    return Err(crate::database::Error::MissingJsonField(
                                        name.to_string(),
                                    ));
                                }
                            }
                        };
                    }
                    FieldType::Json => {
                        match json.get(short_name) {
                            Some(value) => {
                                if !value.is_object() && !value.is_array() {
                                    return Err(crate::database::Error::InvalidJsonFieldValue(
                                        name.to_string(),
                                        "Json".to_string(),
                                    ));
                                }
                            }
                            None => {
                                if !field.nullable && field.default_value.is_none() {
                                    return Err(crate::database::Error::MissingJsonField(
                                        name.to_string(),
                                    ));
                                }
                            }
                        };
                    }
                    FieldType::Array(_) | FieldType::Entity(_) => {}
                };
            }
        }
    }
    Ok(())
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Index {
    pub entity_name: String,
    pub entity_short: String,
    pub fields: Vec<Field>,
}

impl Index {
    pub fn new(entity_name: String, entity_short: String) -> Self {
        Self {
            entity_name,
            entity_short,
            fields: Vec::new(),
        }
    }
    pub fn add_field(&mut self, field: Field) -> Result<(), Error> {
        match field.field_type {
            FieldType::Array(_) | FieldType::Entity(_) | FieldType::Json => {
                return Err(Error::InvalidQuery(format!(
                    "'{}' 's type {} is not allowed in an index",
                    &field.name, field.field_type
                )));
            }
            FieldType::Boolean
            | FieldType::Float
            | FieldType::Base64
            | FieldType::Integer
            | FieldType::String => {}
        }

        if self.fields.iter().any(|f| f.name.eq(&field.name)) {
            return Err(Error::InvalidQuery(format!(
                "'{}' is duplicated in the Index",
                &field.name
            )));
        }
        self.fields.push(field);
        Ok(())
    }

    pub fn name(&self) -> String {
        let mut name = String::new();
        name.push_str("idx$");
        name.push_str(&self.entity_name.replace(".", "$"));
        for i in &self.fields {
            name.push('$');
            name.push_str(&i.name);
        }
        name
    }

    pub fn create_query(&self) -> String {
        let mut q = String::new();
        q.push_str(&format!("CREATE INDEX {} ON _node (", self.name()));
        let it = &mut self.fields.iter().peekable();
        while let Some(field) = it.next() {
            if field.is_system {
                q.push_str(&field.name);
            } else {
                q.push_str(&format!("_json->>'$.{}'", &field.name));
            }
            if it.peek().is_some() {
                q.push(',');
            }
        }
        q.push(')');
        q.push_str(&format!(" WHERE _entity='{}' ", self.entity_short));
        q
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
    pub enable_full_text: bool,
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
            enable_full_text: true,
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
                        match field.field_type {
                            FieldType::Array(_) | FieldType::Entity(_) => {}
                            _ => {
                                return Err(Error::MissingDefaultValue(
                                    String::from(&self.name),
                                    String::from(&field.name),
                                ));
                            }
                        }
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
                match field.1.field_type {
                    FieldType::Array(_) | FieldType::Entity(_) => {}
                    _ => {
                        return Err(Error::MissingDefaultValue(
                            String::from(&self.name),
                            String::from(&field.1.name),
                        ));
                    }
                }
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
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Field {
    pub name: String,
    pub short_name: String,
    pub field_type: FieldType,
    pub default_value: Option<ParamValue>,
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
            FieldType::Base64 => {
                if self.is_system {
                    VariableType::Binary(self.nullable)
                } else {
                    VariableType::Base64(self.nullable)
                }
            }
            FieldType::Boolean => VariableType::Boolean(self.nullable),
            FieldType::Integer => VariableType::Integer(self.nullable),
            FieldType::Float => VariableType::Float(self.nullable),
            FieldType::String | FieldType::Json => VariableType::String(self.nullable),
        }
    }

    pub fn get_variable_type_non_nullable(&self) -> VariableType {
        match self.field_type {
            FieldType::Array(_) | FieldType::Entity(_) => VariableType::Invalid,
            FieldType::Base64 => {
                if self.is_system {
                    VariableType::Binary(false)
                } else {
                    VariableType::Base64(false)
                }
            }
            FieldType::Boolean => VariableType::Boolean(false),
            FieldType::Integer => VariableType::Integer(false),
            FieldType::Float => VariableType::Float(false),
            FieldType::String | FieldType::Json => VariableType::String(false),
        }
    }
}
