use super::{
    data_model::{DataModel, FieldType},
    parameter::{VariableType, Variables},
    Error,
};
use pest::iterators::Pair;
use pest::Parser;
use pest_derive::Parser;

#[derive(Parser)]
#[grammar = "database/query_language/deletion.pest"]
struct PestParser;

#[derive(Debug)]
struct Deletion {
    name: String,
    variables: Variables,
    queries: Vec<EntityDeletion>,
}

#[derive(Debug)]
struct EntityDeletion {
    entity_name: String,
    id_param: String,
    references: Vec<ReferenceDeletion>,
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

impl Deletion {
    pub fn new() -> Self {
        Self {
            name: "".to_string(),
            variables: Variables::new(),
            queries: Vec::new(),
        }
    }

    pub fn parse(query: &str, data_model: &DataModel) -> Result<Deletion, Error> {
        let parse = match PestParser::parse(Rule::deletion, query) {
            Err(e) => {
                let message = format!("{}", e);
                return Err(Error::ParserError(message));
            }
            Ok(f) => f,
        }
        .next()
        .unwrap();

        let mut deletion = Deletion::new();

        match parse.as_rule() {
            Rule::deletion => {
                let mut deletion_pairs = parse.into_inner();
                deletion.name = deletion_pairs.next().unwrap().as_str().to_string();

                for entity_pair in deletion_pairs.into_iter() {
                    match entity_pair.as_rule() {
                        Rule::entity => {
                            let ent = Self::parse_entity(
                                data_model,
                                entity_pair,
                                &mut deletion.variables,
                            )?;
                            deletion.queries.push(ent);
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

        for entity_pair in pair.into_inner().into_iter() {
            match entity_pair.as_rule() {
                Rule::identifier => {
                    let name = entity_pair.as_str().to_string();
                    if data_model.get_entity(&name).is_none() {
                        return Err(Error::InvalidQuery(format!(
                            "Entity name '{}' not found in the data model",
                            name
                        )));
                    }
                    entity.entity_name = name;
                }
                Rule::field => {
                    let dm_entity = data_model.get_entity(&entity.entity_name).unwrap();

                    for field in entity_pair.into_inner().into_iter() {
                        match field.as_rule() {
                            Rule::id_field => {
                                let var = field.as_str()[1..].to_string(); //remove $
                                variables.add(var.clone(), VariableType::UID(false))?;
                                entity.id_param = var;
                            }
                            Rule::array_field => {
                                let mut array_field_pairs = field.into_inner();
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
                                    let var = param_pair.as_str()[1..].to_string(); //remove $

                                    variables.add(var.clone(), VariableType::UID(false))?;

                                    id_param = Some(var);
                                } else {
                                    id_param = None;
                                }
                                entity.references.push(ReferenceDeletion { name, id_param });
                            }

                            _ => unreachable!(),
                        }
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
        let data_model = DataModel::parse(
            "
            Person {
                name : String NOT NULL UNIQUE,
                surname : String INDEXED,
                parent : [Person],
                pet : [Pet]
            }

            Pet {
                name : String  UNIQUE NOT NULL,
            }
        
        ",
        )
        .unwrap();

        let deletion = Deletion::parse(
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

        assert_eq!(2, deletion.queries.len());

        let query = deletion.queries.get(0).unwrap();
        assert_eq!("Person", query.entity_name);
        assert_eq!("id", query.id_param);
        assert_eq!(2, query.references.len());

        let reference = query.references.get(0).unwrap();
        assert_eq!("parent", reference.name);
        assert_eq!(Some("id2".to_string()), reference.id_param);

        let reference = query.references.get(1).unwrap();
        assert_eq!("pet", reference.name);
        assert_eq!(None, reference.id_param);

        let query = deletion.queries.get(1).unwrap();
        assert_eq!("Pet", query.entity_name);
        assert_eq!("id3".to_string(), query.id_param);
        assert_eq!(0, query.references.len());

        //println!("{:#?}", deletion);
    }

    #[test]
    fn parse_invalid_datamodel() {
        let data_model = DataModel::parse(
            "
            Person {
                name : String NOT NULL UNIQUE,
                surname : String INDEXED,
                parent : [Person],
                pet : [Pet]
            }

            Pet {
                name : String  UNIQUE NOT NULL,
            }
        
        ",
        )
        .unwrap();

        let _ = Deletion::parse(
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

        let _ = Deletion::parse(
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

        let _ = Deletion::parse(
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

        let _ = Deletion::parse(
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

        let _ = Deletion::parse(
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

        let _ = Deletion::parse(
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
        let data_model = DataModel::parse(
            "
            Person {
                name : String NOT NULL UNIQUE,
                surname : String INDEXED,
                parent : [Person],
                pet : [Person]
            }        
        ",
        )
        .unwrap();

        let _ = Deletion::parse(
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

        let _ = Deletion::parse(
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
