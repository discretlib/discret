#[cfg(test)]
mod tests {

    use crate::database::{
        system_entities::{
            PEER_FIELD, BINARY_FIELD, CREATION_DATE_FIELD, ENTITY_FIELD, ID_FIELD, JSON_FIELD,
            MODIFICATION_DATE_FIELD, SIGNATURE_FIELD, VERIFYING_KEY_FIELD,
        },
        query_language::{data_model_parser::*, FieldType, Value},
    };
    use std::any::Any;

    #[test]
    fn parse_valid_model() {
        let mut datamodel = DataModel::new();
        datamodel
            .update(
                r#"
            Ns{
                @deprecated Person {
                    name : String ,
                    surname : String nullable,
                    child : [Ns.Person] ,
                    mother : ns.Person ,
                    father : ns.Person , 
                    index(name, surname),
                }

                Pet {
                    name : String default "John",
                    surname : String NULLABLE,
                    owners : [ns.Person],
                    @deprecated  age : Float NULLABLE,
                    weight : Integer NULLABLE,
                    is_vaccinated: Boolean NULLABLE,
                    INDEX(weight)
                }
            }
          "#,
            )
            .unwrap();

        let pet = datamodel.get_entity("Ns.Pet").unwrap();
        assert_eq!("ns.Pet", pet.name);

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
            FieldType::Array(e) => assert_eq!("ns.Person", e),
            _ => unreachable!(),
        }
        assert_eq!(false, owner.nullable);

        let index = &pet.indexes;
        assert_eq!(1, index.len());
        for i in index.values() {
            assert_eq!("weight", i.fields[0].name)
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

        let person = datamodel.get_entity("NS.Person").unwrap();
        assert_eq!("ns.Person", person.name);
        let name = person.fields.get("name").unwrap();
        assert_eq!(FieldType::String.type_id(), name.field_type.type_id());
        assert_eq!(false, name.nullable);

        let surname = person.fields.get("surname").unwrap();
        assert_eq!(FieldType::String.type_id(), surname.field_type.type_id());
        assert_eq!(true, surname.nullable);

        let child = person.fields.get("child").unwrap();
        match &child.field_type {
            FieldType::Array(e) => assert_eq!("Ns.Person", e),
            _ => unreachable!(),
        }
        assert_eq!(false, child.nullable);

        let mother = person.fields.get("mother").unwrap();
        match &mother.field_type {
            FieldType::Entity(e) => assert_eq!("ns.Person", e),
            _ => unreachable!(),
        }
        assert_eq!(false, mother.nullable);

        let father = person.fields.get("father").unwrap();
        match &father.field_type {
            FieldType::Entity(e) => assert_eq!("ns.Person", e),
            _ => unreachable!(),
        }
        assert_eq!(false, father.nullable);

        //println!("{:#?}", datamodel)
    }

    #[test]
    fn comments() {
        let mut datamodel = DataModel::new();
        datamodel
            .update(
                "
            {//acomment
                Person {
                    //comment
                    child : String,
                }
            }",
            )
            .expect("Comments ");
    }

    #[test]
    fn invalid_entity() {
        let mut datamodel = DataModel::new();
        datamodel
            .update(
                "
                Person {
                    name : String,
                }",
            )
            .expect_err("missing openning brackets ");

        let mut datamodel = DataModel::new();
        datamodel
            .update(
                "
                {
                    Person {
                        child : [InvalidEntity],
                    }
                }",
            )
            .expect_err("InvalidEntity is not defined in the datamodel");

        let mut datamodel = DataModel::new();
        datamodel
            .update(
                "
                {
                    Person {
                        child : [Boolean],
                    }
                }",
            )
            .expect_err("Cannot reference scalar field");

        let mut datamodel = DataModel::new();
        datamodel
            .update(
                "
                {
                    Person {
                        child : [integer],
                    }
                }",
            )
            .expect_err("Cannot reference scalar field");

        let mut datamodel = DataModel::new();
        datamodel
            .update(
                "
                {
                    Person {
                        child : [float],
                    }
                }",
            )
            .expect_err("Cannot reference scalar field");

        let mut datamodel = DataModel::new();
        datamodel
            .update(
                "
                {
                    Person {
                        child : [json],
                    }
                }",
            )
            .expect_err("Cannot reference scalar field");

        let mut datamodel = DataModel::new();
        datamodel
            .update(
                "
                {
                    Person {
                        child : [base64],
                    }
                }",
            )
            .expect_err("Cannot reference scalar field");

        let mut datamodel = DataModel::new();
        datamodel
            .update(
                "
                {
                    Person {
                        child : [Person],
                    }
                }",
            )
            .expect("Person a valid entity");

        let mut datamodel = DataModel::new();
        datamodel
            .update(
                "
                {
                    Person {
                        mother : InvalidEntity,
                    }
                }",
            )
            .expect_err("InvalidEntity is not defined in the datamodel");

        let mut datamodel = DataModel::new();
        datamodel
            .update(
                "
                {
                    Person {
                        mother : Person,
                    }
                }",
            )
            .expect("Person is a valid entity");
    }

    #[test]
    fn reserved_names() {
        let mut datamodel = DataModel::new();
        datamodel
            .update(
                "
                {
                    _Person {
                        name : String,
                    }
                }",
            )
            .expect("entity name can start with a _");

        let mut datamodel = DataModel::new();
        datamodel
            .update(
                "
                {
                    Person {
                        _name : String,
                    }
                }",
            )
            .expect_err("entity field name cannot start with a _");

        let mut datamodel = DataModel::new();
        datamodel
            .update(
                "
                {
                    Per_son_ {
                        na_me_ : String,
                    }
                }",
            )
            .expect("entity and field name can contain _");

        let mut datamodel = DataModel::new();
        datamodel
            .update(
                "
                {
                    Person {
                        String : String,
                    }
                }",
            )
            .expect_err("scalar field names are reserved");

        let mut datamodel = DataModel::new();
        datamodel
            .update(
                "
                {
                    json {
                        name : String,
                    }
                }",
            )
            .expect_err("scalar field names are reserved");
        let mut datamodel = DataModel::new();
        datamodel
            .update(
                "
            {   
                baSe64 {
                    name : String,
                }
            }",
            )
            .expect_err("scalar field names are reserved");
        let mut datamodel = DataModel::new();
        datamodel
            .update(
                "
            {   
                String {
                    name : String,
                }
            }",
            )
            .expect_err("scalar field names are reserved");
        let mut datamodel = DataModel::new();
        datamodel
            .update(
                "
            {
                floAt {
                    name : String,
                }
            }",
            )
            .expect_err("scalar field names are reserved");
        let mut datamodel = DataModel::new();
        datamodel
            .update(
                "
            {
                INTEGer {
                    name : String,
                }
            }",
            )
            .expect_err("scalar field names are reserved");
    }

    #[test]
    fn duplicates() {
        let mut datamodel = DataModel::new();
        datamodel
            .update(
                "
            {
                Person {
                    child : [Person],
                }

                Person {
                    name : String,
                }
            }",
            )
            .expect_err("Person is duplicated");

        let mut datamodel = DataModel::new();
        datamodel
            .update(
                "
            {
                Person {
                    child : [Person],
                }
            }",
            )
            .expect("Person is not duplicated anymore");

        let mut datamodel = DataModel::new();
        datamodel
            .update(
                "
            {
                Person {
                    child : String,
                    child : [Person],
                } 
            }",
            )
            .expect_err("child is duplicated");

        let mut datamodel = DataModel::new();
        datamodel
            .update(
                "
            {
                Person {
                    name : String,
                    child : [Person],
                }
            }",
            )
            .expect("child is not duplicated anymore");
    }

    #[test]
    fn parse_invalid_string() {
        let mut datamodel = DataModel::new();
        datamodel
            .update(
                "
            {
                Person {
                    child : [Person],
                    name: String
                }
            }",
            )
            .expect("missing [ before person");

        let mut datamodel = DataModel::new();
        datamodel
            .update(
                "
            {
                Person @deprecated {
                    mother : Person,
                }
            }",
            )
            .expect_err("@deprecated must be before the entity name");

        let mut datamodel = DataModel::new();
        datamodel
            .update(
                "
            {
                @deprecated Person  {
                    mother : Person,
                }
            }",
            )
            .expect("@deprecated must be before the entity name");
    }

    #[test]
    fn default_value() {
        let mut datamodel = DataModel::new();
        datamodel
            .update(
                r#"
            {
                Person {
                    is_vaccinated : Boolean default "true" ,
                }
            }"#,
            )
            .expect_err("default must be a boolean not a string");

        let mut datamodel = DataModel::new();
        datamodel
            .update(
                r#"
            {
                Person {
                    is_vaccinated : Boolean default false ,
                }
            }"#,
            )
            .expect("default is a boolean");

        let mut datamodel = DataModel::new();
        datamodel
            .update(
                r#"
            {
                Person {
                    weight : Float default true ,
                }
            }"#,
            )
            .expect_err("default must be a Float not a boolean");

        let mut datamodel = DataModel::new();
        datamodel
            .update(
                r#"
            {
                Person {
                    weight : Float default 12 ,
                }
            }"#,
            )
            .expect("default is an Integer which will be parsed to a Float");

        let mut datamodel = DataModel::new();
        datamodel
            .update(
                r#"
            {
                Person {
                    weight : Float default 12.5 ,
                }
            }"#,
            )
            .expect("default is an Float");

        let mut datamodel = DataModel::new();
        datamodel
            .update(
                r#"
            {
                Person {
                    age : Integer default 12.5 ,
                }
            }"#,
            )
            .expect_err("default must be a Integer not a Float");

        let mut datamodel = DataModel::new();
        datamodel
            .update(
                r#"
            {
                Person {
                    age : Integer default 12 ,
                }
            }"#,
            )
            .expect("default is an Integer");

        let mut datamodel = DataModel::new();
        datamodel
            .update(
                "
            {
                Person {
                    name : String default 12.2 ,
                }
            }",
            )
            .expect_err("default must be a string not a float");

        let mut datamodel = DataModel::new();
        datamodel
            .update(
                r#"
            {
                Person {
                    name : String default "test" ,
                }
            }"#,
            )
            .expect("default is a string");
    }

    #[test]
    fn system_field_collision() {
        let mut entity = Entity::new();

        let mut field = Field::new();
        field.name = PEER_FIELD.to_string();
        entity
            .add_field(field)
            .expect_err("system field allready defined");

        let mut field = Field::new();
        field.name = PEER_FIELD.to_string();
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
        field.name = VERIFYING_KEY_FIELD.to_string();
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
        let mut datamodel = DataModel::new();
        datamodel
            .update(
                "
            {
                Person {
                    name : String,
                    child : [Person],
                    father: Person,
                    index(invalid_field)
                }
            }",
            )
            .expect_err("index has an invalid field name");

        let mut datamodel = DataModel::new();
        datamodel
            .update(
                "
            {
                Person {
                    name : String,
                    child : [Person],
                    father: Person,
                    index(child)
                }
            }",
            )
            .expect_err("child cannot be indexed because it is not a scalar type");

        let mut datamodel = DataModel::new();
        datamodel
            .update(
                "
            {
                Person {
                    name : String,
                    child : [Person],
                    father: Person,
                    index(father)
                }
            }",
            )
            .expect_err("father cannot be indexed because it is not a scalar type");

        let mut datamodel = DataModel::new();
        datamodel
            .update(
                "
            {
                Person {
                    name : String,
                    child : [Person],
                    father: Person,
                    index(name, name)
                }
            }",
            )
            .expect_err("name is repeated twice");

        let mut datamodel = DataModel::new();
        datamodel
            .update(
                "
            {
                Person {
                    name : String,
                    child : [Person],
                    father: Person,
                    index(name),
                    index(name)
                }
            }",
            )
            .expect_err("index(name) is defined twice");

        let mut datamodel = DataModel::new();
        datamodel
            .update(
                "
            {
                Person {
                    name : String,
                    child : [Person],
                    father: Person,
                    index(name)
                }
            }",
            )
            .expect("index is valid");
    }

    #[test]
    fn nullable_entity() {
        let mut datamodel = DataModel::new();
        datamodel
            .update(
                "
            {
                Person {
                    name : String,
                    parent: [Person] nullable,
                    other: Person nullable,
                }
            }",
            )
            .unwrap();

        let field = datamodel
            .get_entity("Person")
            .unwrap()
            .get_field("parent")
            .unwrap();
        assert!(field.nullable);

        let field = datamodel
            .get_entity("Person")
            .unwrap()
            .get_field("other")
            .unwrap();
        assert!(field.nullable);

        let mut datamodel = DataModel::new();
        datamodel
            .update(
                "
            {
                Person {
                    name : String,
                    parent: [Person],
                    other: Person ,
                }
            }",
            )
            .unwrap();

        let field = datamodel
            .get_entity("Person")
            .unwrap()
            .get_field("parent")
            .unwrap();
        assert!(!field.nullable);

        let field = datamodel
            .get_entity("Person")
            .unwrap()
            .get_field("other")
            .unwrap();
        assert!(!field.nullable);
    }

    #[test]
    fn entity_update() {
        let mut datamodel = DataModel::new();
        datamodel
            .update(
                "
            {
                Person {
                    name : String,
                }
            }",
            )
            .unwrap();

        let person = datamodel.get_entity("Person").unwrap();
        assert_eq!(0.to_string(), person.short_name);

        datamodel
            .update(
                "
            {
                Pesssssrson {
                    name : String,
                }
            }",
            )
            .expect_err("missing Person");

        datamodel
            .update(
                "
            {
                @deprecated Pet {
                    name : String,
                }

                Person {
                    name : String,
                }
            }",
            )
            .expect_err("updates must preserve entity ordering");

        datamodel
            .update(
                "
            {
                @deprecated Person {
                    name : String,
                } 
                Pet {
                    name : String,
                }
            }
           ",
            )
            .unwrap();

        let person = datamodel.get_entity("Person").unwrap();
        assert!(person.deprecated);
        let pet = datamodel.get_entity("Pet").unwrap();
        assert!(!pet.deprecated);
    }

    #[test]
    fn field_update() {
        let mut datamodel = DataModel::new();
        datamodel
            .update(
                "
            {
                Person {
                    name : String,
                }
            }",
            )
            .unwrap();

        let person = datamodel.get_entity("Person").unwrap();
        let name = person.get_field("name").unwrap();
        assert_eq!(RESERVED_SHORT_NAMES.to_string(), name.short_name);

        datamodel
            .update(
                "
            {
                Person {
                    name : Integer,
                }
            }",
            )
            .expect_err("Cannot change a field type");

        datamodel
            .update(
                "
            {
                Person {
                    name : String nullable,
                }
            }",
            )
            .expect("Field can be changed to nullable");

        datamodel
            .update(
                "
            {
                Person {
                    name : String,
                }
            }",
            )
            .expect_err("Field cannot be changed to not nullable without a default value");

        datamodel
            .update(
                r#"
            {
                Person {
                    name : String default "",
                }
            }"#,
            )
            .expect(
                "Field can be changed to not nullable with a default value, even an empty string",
            );

        datamodel
            .update(
                r#"
            {
                Person {
                    name : String default "",
                    age : Integer
                }
            }"#,
            )
            .expect_err("New Field that are not nullable must have a default value");

        datamodel
            .update(
                r#"
            {
                Person {
                    age : Integer default 0,
                    name : String default "",
                }
            }"#,
            )
            .expect_err("Field Ordering must be respected");

        datamodel
            .update(
                r#"
            {
                Person {
                    name : String default "",
                    age : Integer default 0,
                }
            }"#,
            )
            .expect("Field Ordering is respected");

        let person = datamodel.get_entity("Person").unwrap();
        let name = person.get_field("name").unwrap();
        assert_eq!(RESERVED_SHORT_NAMES.to_string(), name.short_name);
        let age = person.get_field("age").unwrap();
        assert_eq!((RESERVED_SHORT_NAMES + 1).to_string(), age.short_name);

        datamodel
            .update(
                r#"
            {
                Person {
                    name : String default "",
                    age : Integer default 0,
                    other: Person
                }
            }"#,
            )
            .expect("Entity Field don't need default value");
    }

    #[test]
    fn index_update() {
        let mut datamodel = DataModel::new();
        datamodel
            .update(
                "
            {
                Person {
                    name : String,
                    index(name)
                }
            }",
            )
            .unwrap();

        datamodel
            .update(
                "
            {
                Person {
                    name : String,
                    index(name)
                }
            }",
            )
            .unwrap();

        datamodel
            .update(
                "
            {
                Person {
                    name : String,
                }
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
                "
            {
                Person {
                    name : Base64,
                }
            }",
            )
            .expect("valid");

        let mut datamodel = DataModel::new();
        datamodel
            .update(
                r#"
            {
                Person {
                    name : Base64 default "?%&JVBQS0pP",
                }
            }"#,
            )
            .expect_err("invalid default value");

        let mut datamodel = DataModel::new();
        datamodel
            .update(
                r#"
            {
                Person {
                    name : Base64 default "JVBQS0pP",
                }
            }"#,
            )
            .expect("valid default value");
    }

    #[test]
    fn json_field() {
        let mut datamodel = DataModel::new();
        datamodel
            .update(
                "
            {
                Person {
                    name : Json,
                }
            }",
            )
            .expect("valid Json");

        let mut datamodel = DataModel::new();
        datamodel
            .update(
                r#"
            {
                Person {
                    name : Json default "qsd",
                }
            }"#,
            )
            .expect_err("invalid default value");

        let mut datamodel = DataModel::new();
        datamodel
            .update(
                r#"
            {
                Person {
                    name : Json default "[1,2,3]",
                }
            }"#,
            )
            .expect("valid default value");
    }

    #[test]
    fn system() {
        let mut datamodel = DataModel::new();
        datamodel
            .update_system(
                "
            {
                Person {
                    name : String,
                }
            }",
            )
            .expect_err("DataModel System update can only contains the sys namespace");

        let mut datamodel = DataModel::new();
        datamodel
            .update_system(
                "
            sys {
                Person {
                    name : String,
                }
            }",
            )
            .expect("valid system entity name");
    }

    #[test]
    fn short_mapping() {
        let mut datamodel = DataModel::new();
        datamodel
            .update(
                "
            {
                Person {
                    name : String,
                }
                Pet {
                    name: String
                }
            }",
            )
            .unwrap();

        let name = datamodel.name_for("0").unwrap();
        assert_eq!("Person", name);

        let name = datamodel.name_for("1").unwrap();
        assert_eq!("Pet", name);

        datamodel
            .update(
                "
                {
                    Person {
                        name : String,
                    }
                    Pet {
                        name: String
                    }
                }
                ns {
                    Person {
                        name : String,
                    }
                    Pet {
                        name: String
                    }
                }",
            )
            .unwrap();

        let name = datamodel.name_for("0").unwrap();
        assert_eq!("Person", name);

        let name = datamodel.name_for("1").unwrap();
        assert_eq!("Pet", name);

        let name = datamodel.name_for("2.0").unwrap();
        assert_eq!("ns.Person", name);

        let name = datamodel.name_for("2.1").unwrap();
        assert_eq!("ns.Pet", name);
    }

    #[test]
    fn disable_feature() {
        let mut datamodel = DataModel::new();
        datamodel
            .update(
                "
            {
                Person( no_full_text_index) {
                    name : String,
                }
            }",
            )
            .unwrap();

        let person = datamodel.get_entity("Person").unwrap();
        assert!(!person.enable_full_text);
    }

    #[test]
    fn namespace_update() {
        let mut datamodel = DataModel::new();
        datamodel
            .update(
                "
            ns1 {
                Person {
                    name : String,
                }
            }",
            )
            .unwrap();

        datamodel
            .update(
                "
            ns2 {
                Person {
                    name : String,
                }
            }",
            )
            .expect_err("MissingNamespace(ns1)");

        datamodel
            .update(
                "
            ns2 {
                Person {
                    name : String,
                }
            }
            ns1 {
                Person {
                    name : String,
                }
            }
            ",
            )
            .expect_err("InvalidNamespaceOrdering");

        datamodel
            .update(
                "
            ns1 {
                Person {
                    name : String,
                }
            }
            ns2 {
                Person {
                    name : String,
                }
            }
            ",
            )
            .expect("all good");
    }
}
