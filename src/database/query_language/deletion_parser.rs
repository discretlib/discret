use super::{data_model_parser::DataModel, parameter::Variables, Error};
use super::{FieldType, VariableType};
use pest::iterators::Pair;
use pest::Parser;
use pest_derive::Parser;

#[derive(Parser)]
#[grammar = "database/query_language/deletion.pest"]
struct PestParser;

#[derive(Debug)]
pub struct DeletionParser {
    pub name: String,
    pub variables: Variables,
    pub deletions: Vec<EntityDeletion>,
}

#[derive(Debug)]
pub struct EntityDeletion {
    pub name: String,
    pub short_name: String,
    pub alias: Option<String>,
    pub id_param: String,
    pub references: Vec<ReferenceDeletion>,
}
impl Default for EntityDeletion {
    fn default() -> Self {
        EntityDeletion::new()
    }
}
impl EntityDeletion {
    pub fn new() -> Self {
        Self {
            name: "".to_string(),
            short_name: "".to_string(),
            alias: None,
            id_param: "".to_string(),
            references: Vec::new(),
        }
    }
}

#[derive(Debug)]
pub struct ReferenceDeletion {
    pub entity_name: String,
    pub label: String,
    pub dest_param: String,
}
impl Default for DeletionParser {
    fn default() -> Self {
        DeletionParser::new()
    }
}
impl DeletionParser {
    pub fn new() -> Self {
        Self {
            name: "".to_string(),
            variables: Variables::new(),
            deletions: Vec::new(),
        }
    }

    pub fn parse(query: &str, data_model: &DataModel) -> Result<DeletionParser, Error> {
        let parse = match PestParser::parse(Rule::deletion, query) {
            Err(e) => {
                let message = format!("{}", e);
                return Err(Error::Parser(message));
            }
            Ok(f) => f,
        }
        .next()
        .unwrap();

        let mut deletion = DeletionParser::new();

        match parse.as_rule() {
            Rule::deletion => {
                let mut deletion_pairs = parse.into_inner();
                deletion.name = deletion_pairs.next().unwrap().as_str().to_string();

                for entity_pair in deletion_pairs {
                    match entity_pair.as_rule() {
                        Rule::entity => {
                            let ent = Self::parse_entity(
                                data_model,
                                entity_pair,
                                &mut deletion.variables,
                            )?;
                            deletion.deletions.push(ent);
                        }
                        Rule::EOI => {}
                        _ => unreachable!(),
                    }
                }
            }
            _ => unreachable!(),
        }

        Ok(deletion)
    }

    fn parse_entity(
        data_model: &DataModel,
        pair: Pair<'_, Rule>,
        variables: &mut Variables,
    ) -> Result<EntityDeletion, Error> {
        let mut entity = EntityDeletion::new();

        let mut entity_pairs = pair.into_inner();
        let mut name_pair = entity_pairs.next().unwrap().into_inner();
        let entity_name = if name_pair.len() == 2 {
            let alias = name_pair.next().unwrap().as_str().to_string();
            if alias.starts_with('_') {
                return Err(Error::InvalidName(alias));
            }

            entity.alias = Some(alias);
            name_pair.next().unwrap().as_str()
        } else {
            name_pair.next().unwrap().as_str()
        };
        let model_entity = data_model.get_entity(entity_name)?;
        entity.name = entity_name.to_string();
        entity.short_name = model_entity.short_name.clone();

        for entity_pair in entity_pairs {
            match entity_pair.as_rule() {
                Rule::id_field => {
                    let var = &entity_pair.as_str()[1..]; //remove $
                    variables.add(var, VariableType::Base64(false))?;
                    entity.id_param = var.to_string();
                }
                Rule::array_field => {
                    let mut array_field_pairs = entity_pair.into_inner();
                    let name = array_field_pairs.next().unwrap().as_str().to_string();
                    let model_field = match model_entity.fields.get(&name) {
                        None => {
                            return Err(Error::InvalidQuery(format!(
                                "Unknown field '{}' in entity '{}'",
                                name, entity_name
                            )))
                        }
                        Some(e) => match e.field_type {
                            FieldType::Array(_) => e,
                            _ => {
                                return Err(Error::InvalidQuery(format!(
                                "'{}' in entity '{}' is not defined as an array in the data model",
                                name, entity_name
                            )))
                            }
                        },
                    };

                    for param_pair in array_field_pairs {
                        let id_param = param_pair.as_str()[1..].to_string(); //remove $

                        variables.add(&id_param, VariableType::Base64(false))?;

                        entity.references.push(ReferenceDeletion {
                            label: model_field.short_name.clone(),
                            dest_param: id_param,
                            entity_name: entity_name.to_string(),
                        });
                    }
                }

                _ => unreachable!(),
            }
        }

        Ok(entity)
    }
}

#[cfg(test)]
mod tests {

    use super::*;
    #[test]
    fn parse_valid_deletion() {
        let mut data_model = DataModel::new();
        data_model
            .update(
                "
            Person {
                name : String ,
                surname : String ,
                parent : [Person],
                pet : [Pet]
            }

            Pet {
                name : String ,
            }
        
        ",
            )
            .unwrap();

        let deletion = DeletionParser::parse(
            "
            //comment
            deletion delete_person {
                //comment
                del1: Person {
                    //comment
                    $id //comment
                    parent[$id2, $id3]
                    pet[$id4]
                }

                Pet {
                    $id3
                }
            }
            
          ",
            &data_model,
        )
        .unwrap();

        assert_eq!("delete_person", deletion.name);

        assert_eq!(2, deletion.deletions.len());

        let query = deletion.deletions.get(0).unwrap();
        assert_eq!("Person", query.name);
        assert_eq!("32", query.short_name);
        let alias = query.alias.as_ref().unwrap();
        assert_eq!("del1", alias);
        assert_eq!("id", query.id_param);
        assert_eq!(3, query.references.len());

        let reference = query.references.get(0).unwrap();
        assert_eq!("34", reference.label);
        assert_eq!("id2".to_string(), reference.dest_param);

        let reference = query.references.get(1).unwrap();
        assert_eq!("34", reference.label);
        assert_eq!("id3".to_string(), reference.dest_param);

        let reference = query.references.get(2).unwrap();
        assert_eq!("35", reference.label);
        assert_eq!("id4".to_string(), reference.dest_param);

        let query = deletion.deletions.get(1).unwrap();
        assert_eq!("Pet", query.name);
        assert_eq!("33", query.short_name);
        assert_eq!(None, query.alias);
        assert_eq!("id3", query.id_param);
        assert_eq!(0, query.references.len());

        //println!("{:#?}", deletion);
    }

    #[test]
    fn parse_invalid_datamodel() {
        let mut data_model = DataModel::new();
        data_model
            .update(
                "
            Person {
                name : String ,
                surname : String ,
                parent : [Person],
                pet : [Pet]
            }

            Pet {
                name : String,
            }
        
        ",
            )
            .unwrap();

        let _ = DeletionParser::parse(
            "
            deletion delete_pet {
                pet {
                    $id3
                }
            }
            
          ",
            &data_model,
        )
        .expect_err("Entity name is case sensitives. 'pet' is not a valid entity but 'Pet' is");

        let _ = DeletionParser::parse(
            "
            deletion delete_pet {
                Pet {
                    $id3
                }
            }
            
          ",
            &data_model,
        )
        .expect("'Pet' is corectly defined");

        let _ = DeletionParser::parse(
            "
            deletion delete_pet{
                Person {
                    $id1
                    Parent[$id2]
                }
            }
            
          ",
            &data_model,
        )
        .expect_err(
            "Entity field is case sensitives. 'Parent' is not a valid entity but 'parent' is",
        );

        let _ = DeletionParser::parse(
            "
            deletion delete_pet{
                Person {
                    $id1
                    parent[$id2]
                }
            }
            
          ",
            &data_model,
        )
        .expect("'Parent' is defined correctly");

        let _ = DeletionParser::parse(
            "
            deletion delete_pet{
                Person {
                    $id1
                    parent[]
                }
            }
            
          ",
            &data_model,
        )
        .expect_err(
            "'parent' cannot be empty to delete it compretely set it to null in a mutation query",
        );

        //println!("{:#?}", deletion);
    }

    #[test]
    fn parse_invalid_field_type() {
        let mut data_model = DataModel::new();
        data_model
            .update(
                "
            Person {
                name : String ,
                surname : String ,
                parent : [Person],
                pet : [Person]
            }        
        ",
            )
            .unwrap();

        let _ = DeletionParser::parse(
            "
            deletion delete_person{
                Person {
                    $id1
                    surname[$id2]
                }
            }",
            &data_model,
        )
        .expect_err("'surname' type is not defined as an array");

        let _ = DeletionParser::parse(
            "
            deletion delete_person{
                Person {
                    $id1
                    parent[$id2]
                }
            }",
            &data_model,
        )
        .expect("'parent' type is an array");
    }
}
