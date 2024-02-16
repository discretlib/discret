use super::{Error, FieldType, Value, VariableType};
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
                field_type: FieldType::Base64,
                default_value: None,
                nullable: false,
                deprecated: false,
                mutable: true,
                readable: true,
            },
        );

        fields.insert(
            CREATION_DATE_FIELD.to_string(),
            Field {
                name: CREATION_DATE_FIELD.to_string(),
                field_type: FieldType::Integer,
                default_value: None,
                nullable: false,
                deprecated: false,
                mutable: false,
                readable: true,
            },
        );

       fields.insert(
            MODIFICATION_DATE_FIELD.to_string(),
            Field {
                name: MODIFICATION_DATE_FIELD.to_string(),
                field_type: FieldType::Integer,
                default_value: None,
                nullable: false,
                deprecated: false,
                mutable: false,
                readable: true,
            },
        );

        fields.insert(
            AUTHORS_FIELD.to_string(),
            Field {
                name: AUTHORS_FIELD.to_string(),
                field_type: FieldType::Array(AUTHOR_TABLE.to_string()),
                default_value: None,
                nullable: false,
                deprecated: false,
                mutable: false,
                readable: true,
            },
        );

       fields.insert(
            ENTITY_FIELD.to_string(),
            Field {
                name: ENTITY_FIELD.to_string(),
                field_type: FieldType::String,
                default_value: None,
                nullable: false,
                deprecated: false,
                mutable: false,
                readable: true,
            },
        );

        fields.insert(
            FLAG_FIELD.to_string(),
            Field {
                name: FLAG_FIELD.to_string(),
                field_type: FieldType::Base64,
                default_value: None,
                nullable: false,
                deprecated: false,
                mutable: false,
                readable: false,
            },
        );

        fields.insert(
            JSON_FIELD.to_string(),
            Field {
                name: JSON_FIELD.to_string(),
                field_type: FieldType::String,
                default_value: None,
                nullable: false,
                deprecated: false,
                mutable: false,
                readable: false,
            },
        );

        fields.insert(
            PUB_KEY_FIELD.to_string(),
            Field {
                name: PUB_KEY_FIELD.to_string(),
                field_type: FieldType::Base64,
                default_value: None,
                nullable: false,
                deprecated: false,
                mutable: false,
                readable: true,
            },
        );

        fields.insert(
            SIGNATURE_FIELD.to_string(),
            Field {
                name: SIGNATURE_FIELD.to_string(),
                field_type: FieldType::Base64,
                default_value: None,
                nullable: false,
                deprecated: false,
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
impl Default for DataModel {
    fn default() -> Self {
        DataModel::new()
    }
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
        for entity_pair in pair.into_inner() {
            match entity_pair.as_rule() {
                Rule::deprecable_identifier => {
                    for i in entity_pair.into_inner() {
                        match i.as_rule() {
                            Rule::deprecated => entity.deprecated = true,
                            Rule::identifier => entity.name = i.as_str().to_string(),
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
                                let index = Self::parse_index(i, false)?;
                                entity.add_index(index)?;
                            }
                            Rule::unique_index => {
                                let index = Self::parse_index(i, true)?;
                                entity.add_index(index)?;
                            }
                            _ => unreachable!(),
                        }
                    }
                }

                _ => unreachable!(),
            }
        }
        entity.check_consistency()?;
        Ok(entity)
    }

    fn parse_index(entity_pair: Pair<'_, Rule>, unique: bool) -> Result<Index, Error> {
        let mut index = Index::new(unique);

        for field in entity_pair.into_inner() {
            index.add_field(field.as_str().to_string())?;
        }
        //   println!("{:#?}", entity_pair);
        Ok(index)
    }

    fn parse_field_type(entity_pair: Pair<'_, Rule>) -> Result<Field, Error> {
        let mut field = Field::new();
        let mut field_pairs = entity_pair.into_inner();

        let name_pair = field_pairs.next().unwrap();

        for i in name_pair.into_inner() {
            match i.as_rule() {
                Rule::deprecated => field.deprecated = true,
                Rule::identifier => field.name = i.as_str().to_string(),
                _ => unreachable!(),
            }
        }

        let field_type = field_pairs.next().unwrap();

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

                let name = entity_field.next().unwrap().as_str().to_string();
                field.field_type = FieldType::Entity(name);

                if let Some(_next) = entity_field.next() {
                    field.nullable = true;
                }
            }
            Rule::entity_array => {
                let name = field_type.into_inner().next().unwrap().as_str();
                match name {
                    "Boolean" | "Float" | "Integer" | "String" => {
                        return Err(Error::ParserError(format! ("{} [{}] only Entity is supported in array definition. Scalar fields (Boolean, Float, Integer, String) are not supported", field.name, name)));
                    }
                    _ => field.field_type = FieldType::Array(name.to_string()),
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
    unique: bool,
}

impl Index {
    pub fn new(unique: bool) -> Self {
        Self {
            fields: Vec::new(),
            unique,
        }
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

#[derive(Debug)]
pub struct Entity {
    pub name: String,
    pub fields: HashMap<String, Field>,
    pub indexes: HashMap<String, Index>,
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
            fields: HashMap::new(),
            indexes: HashMap::new(),
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

    pub fn check_consistency(&self) -> Result<(), Error> {
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

#[derive(Debug)]
pub struct Field {
    pub name: String,
    pub field_type: FieldType,
    pub default_value: Option<Value>,
    pub nullable: bool,
    pub deprecated: bool,
    pub mutable: bool,
    pub readable: bool,
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
            field_type: FieldType::Boolean,
            default_value: None,
            nullable: false,
            deprecated: false,
            mutable: true,
            readable: true,
        }
    }

    pub fn get_variable_type(&self) -> VariableType {
        match self.field_type {
            FieldType::Array(_) | FieldType::Entity(_) | FieldType::Base64 => {
                VariableType::Base64(self.nullable)
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
            r#"
                @deprecated Person {
                    name : String ,
                    surname : String nullable,
                    child : [Person],
                    mother : Person ,
                    father : Person NULLABLE, 
                    unique_index(name, surname),
                     
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
        assert_eq!(false, child.nullable);

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
    fn default_value() {
        let _datamodel = DataModel::parse(
            r#"
                Person {
                    is_vaccinated : Boolean default "true" ,
                }
            
          "#,
        )
        .expect_err("default must be a boolean not a string");

        let _datamodel = DataModel::parse(
            r#"
                Person {
                    is_vaccinated : Boolean default false ,
                }
            
          "#,
        )
        .expect("default is a boolean");

        let _datamodel = DataModel::parse(
            r#"
                Person {
                    weight : Float default true ,
                }
            
          "#,
        )
        .expect_err("default must be a Float not a boolean");

        let _datamodel = DataModel::parse(
            r#"
                Person {
                    weight : Float default 12 ,
                }
            
          "#,
        )
        .expect("default is an Integer which will be parsed to a Float");

        let _datamodel = DataModel::parse(
            r#"
                Person {
                    weight : Float default 12.5 ,
                }
            
          "#,
        )
        .expect("default is an Float");

        let _datamodel = DataModel::parse(
            r#"
                Person {
                    age : Integer default 12.5 ,
                }
            
          "#,
        )
        .expect_err("default must be a Integer not a Float");

        let _datamodel = DataModel::parse(
            r#"
                Person {
                    age : Integer default 12 ,
                }
            
          "#,
        )
        .expect("default is an Integer");

        let _datamodel = DataModel::parse(
            "
                Person {
                    name : String default 12.2 ,
                }
            
          ",
        )
        .expect_err("default must be a string not a float");

        let _datamodel = DataModel::parse(
            r#"
                Person {
                    name : String default "test" ,
                }
            
          "#,
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

    #[test]
    fn index() {
        let _datamodel = DataModel::parse(
            "
                Person {
                    name : String,
                    child : [Person],
                    father: Person,
                    index(invalid_field)
                }            
          ",
        )
        .expect_err("index has an invalid field name");

        let _datamodel = DataModel::parse(
            "
                Person {
                    name : String,
                    child : [Person],
                    father: Person,
                    index(child)
                }            
          ",
        )
        .expect_err("child cannot be indexed because it is not a scalar type");

        let _datamodel = DataModel::parse(
            "
                Person {
                    name : String,
                    child : [Person],
                    father: Person,
                    index(father)
                }            
          ",
        )
        .expect_err("father cannot be indexed because it is not a scalar type");

        let _datamodel = DataModel::parse(
            "
                Person {
                    name : String,
                    child : [Person],
                    father: Person,
                    index(name, name)
                }            
          ",
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
                }            
          ",
        )
        .expect_err("index(name) is defined twice");

        let _datamodel = DataModel::parse(
            "
                Person {
                    name : String,
                    child : [Person],
                    father: Person,
                    index(name)
                }            
          ",
        )
        .expect("index is valid");
    }
}
