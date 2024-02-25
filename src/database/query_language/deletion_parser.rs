use super::{data_model::DataModel, parameter::Variables, Error};
use super::{FieldType, VariableType};
use pest::iterators::Pair;
use pest::Parser;
use pest_derive::Parser;

#[derive(Parser)]
#[grammar = "database/query_language/deletion.pest"]
struct PestParser;

#[derive(Debug)]
pub struct DeletionParser {
    name: String,
    variables: Variables,
    deletions: Vec<EntityDeletion>,
}

#[derive(Debug)]
struct EntityDeletion {
    entity_name: String,
    id_param: String,
    references: Vec<ReferenceDeletion>,
}
impl Default for EntityDeletion {
    fn default() -> Self {
        EntityDeletion::new()
    }
}
impl EntityDeletion {
    pub fn new() -> Self {
        Self {
            entity_name: "".to_string(),
            id_param: "".to_string(),
            references: Vec::new(),
        }
    }
}

#[derive(Debug)]
struct ReferenceDeletion {
    name: String,
    id_param: Option<String>,
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
                return Err(Error::ParserError(message));
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

        for entity_pair in pair.into_inner() {
            match entity_pair.as_rule() {
                Rule::identifier => {
                    let name = entity_pair.as_str().to_string();
                    data_model.get_entity(&name)?;
                    entity.entity_name = name;
                }

                Rule::id_field => {
                    let var = &entity_pair.as_str()[1..]; //remove $
                    variables.add(var, VariableType::Base64(false))?;
                    entity.id_param = var.to_string();
                }
                Rule::array_field => {
                    let dm_entity = data_model.get_entity(&entity.entity_name).unwrap();
                    let mut array_field_pairs = entity_pair.into_inner();
                    let name = array_field_pairs.next().unwrap().as_str().to_string();
                    match dm_entity.fields.get(&name) {
                        None => {
                            return Err(Error::InvalidQuery(format!(
                                "Unknown field '{}' in entity '{}'",
                                name, entity.entity_name
                            )))
                        }
                        Some(e) => match e.field_type {
                            FieldType::Array(_) => {}
                            _ => {
                                return Err(Error::InvalidQuery(format!(
                                "'{}' in entity '{}' is not defined as an array in the data model",
                                name, entity.entity_name
                            )))
                            }
                        },
                    };
                    let id_param: Option<String>;
                    if let Some(param_pair) = array_field_pairs.next() {
                        let var = &param_pair.as_str()[1..]; //remove $

                        variables.add(var, VariableType::Base64(false))?;

                        id_param = Some(String::from(var));
                    } else {
                        id_param = None;
                    }
                    entity.references.push(ReferenceDeletion { name, id_param });
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
            deletion delete_person {
  
                Person {
                    $id
                    parent[$id2]
                    pet[]
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
        assert_eq!("Person", query.entity_name);
        assert_eq!("id", query.id_param);
        assert_eq!(2, query.references.len());

        let reference = query.references.get(0).unwrap();
        assert_eq!("parent", reference.name);
        assert_eq!(Some("id2".to_string()), reference.id_param);

        let reference = query.references.get(1).unwrap();
        assert_eq!("pet", reference.name);
        assert_eq!(None, reference.id_param);

        let query = deletion.deletions.get(1).unwrap();
        assert_eq!("Pet", query.entity_name);
        assert_eq!("id3".to_string(), query.id_param);
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
                    pet[]
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
                    pet[]
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
                    parent[$id2]
                    pe[]
                }
            }
            
          ",
            &data_model,
        )
        .expect_err("'pe' field does not exists");

        let _ = DeletionParser::parse(
            "
            deletion delete_pet{
                Person {
                    $id1
                    parent[$id2]
                    pet[]
                }
            }
            
          ",
            &data_model,
        )
        .expect("'pet' field exists");

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
