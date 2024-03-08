#[cfg(test)]
mod tests {
    use crate::database::query_language::{
        data_model_parser::DataModel, query_parser::QueryParser,
    };

    #[test]
    fn parse_valid_query() {
        let mut data_model = DataModel::new();
        data_model
            .update(
                "
            Person {
                name : String,
                surname : String,
                parents : [Person],
                pet : Pet,
                age : Integer,
                weight : Float,
                is_human : Boolean
            }

            Pet {
                name : String ,
                age : Integer
            }
        
        ",
            )
            .unwrap();

        let _query = QueryParser::parse(
            r#"
            query aquery {
                Person(
                    name = "someone",
                    is_human = true, 
                    age >= 1,
                    weight <= 200,
                    order_by(surname asc),
                    first 30,
                    skip 2,
                    before ("didi"),
                ){
                    a_name:name 
                    surname 
                    parents {
                       age
                       pet {
                            name
                       }
                    }
                    age
                    weight
                    pet {
                        name
                    }
                }

                Parametrized : Person (
                    name = $name,
                    is_human = $human, 
                    age >= $age,
                    weight <= $weight,
                    order_by(surname asc, name desc ),
                    first $limit,
                    skip $skip,
                    after ($after_id),
                ){
                    name 
                    surname 
                    parents {
                       age
                       pet {
                            name
                       }
                    }
                    age
                    weight
                    pet {
                        name
                    }
                }

                Pet () {
                    name 
                    asum: sum( age )
                    avg: avg(age)
                    min: min(age)
                    max : max(age)
                    count: count()
                }

                PetAndOwner : Pet (id=$id) {
                    name 
                }

            }
        "#,
            &data_model,
        )
        .unwrap();

        // println!("{:#?}", _query);
    }

    #[test]
    fn query_depth() {
        let mut data_model = DataModel::new();
        data_model
            .update(
                "
            Person {
                name : String,
                parents : [Person],
            }        
        ",
            )
            .unwrap();

        let query = QueryParser::parse(
            r#"
            query aquery {
                Person {
                    name 
                   
                }
            } "#,
            &data_model,
        )
        .unwrap();
        assert_eq!(0, query.queries[0].depth);

        let query = QueryParser::parse(
            r#"
            query aquery {
                Person {
                    name 
                    parents{
                        name
                    }
                }
            } "#,
            &data_model,
        )
        .unwrap();
        assert_eq!(1, query.queries[0].depth);

        let query = QueryParser::parse(
            r#"
            query aquery {
                Person {
                    name 
                    aliased : parents {
                        name
                        parents {
                            name
                        }
                    }
                    parents {
                        name
                    }
                }
            } "#,
            &data_model,
        )
        .unwrap();
        assert_eq!(2, query.queries[0].depth);
    }

    #[test]
    fn query_complexity() {
        let mut data_model = DataModel::new();
        data_model
            .update(
                "
            Person {
                name : String,
                parents : [Person],
            }        
        ",
            )
            .unwrap();

        let query = QueryParser::parse(
            r#"
            query aquery {
                Person {
                    name 
                }
            } "#,
            &data_model,
        )
        .unwrap();
        assert_eq!(0, query.queries[0].complexity);

        let query = QueryParser::parse(
            r#"
            query aquery {
                Person {
                    name 
                    parents{
                        name
                    }
                }
            } "#,
            &data_model,
        )
        .unwrap();
        assert_eq!(1, query.queries[0].complexity);

        let query = QueryParser::parse(
            r#"
            query aquery {
                Person {
                    name 
                    aliased : parents {
                        name
                        parents {
                            name
                        }
                    }
                    parents {
                        name
                    }
                }
            } "#,
            &data_model,
        )
        .unwrap();
        assert_eq!(3, query.queries[0].complexity);
    }

    #[test]
    fn duplicated_field() {
        let mut data_model = DataModel::new();
        data_model
            .update(
                "
            Person {
                name : String,
                age : Integer,
                parents : [Person],
            }        
        ",
            )
            .unwrap();

        let _query = QueryParser::parse(
            r#"
            query aquery {
                Person {
                    name 
                    name
                }
            } "#,
            &data_model,
        )
        .expect_err("name is defined twice ");

        let _query = QueryParser::parse(
            r#"
            query aquery {
                Person {
                    aname : name 
                    aname : name
                }
            } "#,
            &data_model,
        )
        .expect_err("aname is defined twice ");

        let _query = QueryParser::parse(
            r#"
            query aquery {
                Person {
                    name 
                    aname : name
                }
            } "#,
            &data_model,
        )
        .expect("name is correctly aliased ");

        let _query = QueryParser::parse(
            r#"
            query aquery {
                Person {
                    name 
                }
                Person {
                    name 
                }
            } "#,
            &data_model,
        )
        .expect_err("Person is defined twice ");

        let _query = QueryParser::parse(
            r#"
            query aquery {
                Person {
                    name 
                }
                Aperson: Person {
                    name 
                }
            } "#,
            &data_model,
        )
        .expect("Person is correctly aliased ");
    }

    #[test]
    fn function() {
        let mut data_model = DataModel::new();
        data_model
            .update(
                "
            Person {
                name : String,
                age : Integer,
                parents : [Person],
            }        
        ",
            )
            .unwrap();

        let _query = QueryParser::parse(
            r#"
            query aquery {
                Person {
                    name 
                    fn : avg(name)
                }
            } "#,
            &data_model,
        )
        .expect_err("avg can only be done on Integer or float ");

        let _query = QueryParser::parse(
            r#"
            query aquery {
                Person {
                    name 
                    fn : avg(age)
                }
            } "#,
            &data_model,
        )
        .expect("avg is valid");

        let _query = QueryParser::parse(
            r#"
            query aquery {
                Person {
                    name 
                    fn : sum(name)
                }
            } "#,
            &data_model,
        )
        .expect_err("sum can only be done on Integer or float ");

        let _query = QueryParser::parse(
            r#"
            query aquery {
                Person {
                    name 
                    fn : sum(age)
                }
            } "#,
            &data_model,
        )
        .expect("sum is valid");

        let _query = QueryParser::parse(
            r#"
            query aquery {
                Person {

                    name 
                    fn : min(parents)
                }
            } "#,
            &data_model,
        )
        .expect_err("min can only be done on scalar field");

        let _query = QueryParser::parse(
            r#"
            query aquery {
                Person {
                    age 
                    fn : min(name)
                }
            } "#,
            &data_model,
        )
        .expect("strange but valid");

        let _query = QueryParser::parse(
            r#"
            query aquery {
                Person {
                    name 
                    fn : max(parents)
                }
            } "#,
            &data_model,
        )
        .expect_err("min can only be done on scalar field");

        let _query = QueryParser::parse(
            r#"
            query aquery {
                Person {
                    age 
                    fn : max(name)
                }
            } "#,
            &data_model,
        )
        .expect("strange but valid");

        let _query = QueryParser::parse(
            r#"
            query aquery {
                Person {
                    age 
                    fn : max(not_exist)
                }
            } "#,
            &data_model,
        )
        .expect_err("field does not exists");

        let _query = QueryParser::parse(
            r#"
            query aquery {
                Person {
                    parents{
                        name
                    } 
                    fn : count()
                }
            } "#,
            &data_model,
        )
        .expect_err("when a function is used, 'entity' sub query is not allowed");

        let _query = QueryParser::parse(
            r#"
            query aquery {
                Person {
                    age 
                    fn : count()
                }
            } "#,
            &data_model,
        )
        .expect("count wil be grouped by age");
    }

    #[test]
    fn start_with_underscore() {
        let mut data_model = DataModel::new();
        data_model
            .update(
                "
            Person {
                name : String,
                age : Integer,
                parents : [Person],
                pets : [Pet],
                someone : Person
            } 

            Pet {
                name: String
            }
        ",
            )
            .unwrap();

        let _query = QueryParser::parse(
            r#"
            query aquery {
                Person {
                    name
                }

                _pet: Person {
                    name
                }

            } "#,
            &data_model,
        )
        .expect_err("alias cannot starts with an _");

        let _query = QueryParser::parse(
            r#"
            query aquery {
                Person {
                    name
                }

                pet: Person {
                   _name : name
                }

            } "#,
            &data_model,
        )
        .expect_err("alias cannot starts with an _");

        let _query = QueryParser::parse(
            r#"
            query aquery {
                Person {
                    name
                }

                pet: Person {
                    _verifying_key
                }

            } "#,
            &data_model,
        )
        .expect("_verifying_key is a valid system field");
    }

    #[test]
    fn aliases() {
        let mut data_model = DataModel::new();
        data_model
            .update(
                "
            Person {
                name : String,
                age : Integer,
                parents : [Person],
                pets : [Pet],
                someone : Person
            } 

            Pet {
                name: String
            }
        ",
            )
            .unwrap();

        let _query = QueryParser::parse(
            r#"
            query aquery {
                Person {
                    name
                }

                Pet: Person {
                    name
                }

            } "#,
            &data_model,
        )
        .expect_err("alias is conflicting with the Pet entity");

        let _query = QueryParser::parse(
            r#"
            query aquery {
                Person {
                    name
                    someone : name
                }

            } "#,
            &data_model,
        )
        .expect_err("alias is conflicting with the someone field");

        let _query = QueryParser::parse(
            r#"
            query aquery {
                Person {
                    name : someone{name}
                }

            } "#,
            &data_model,
        )
        .expect_err("alias is conflicting with the name field");

        let _query = QueryParser::parse(
            r#"
            query aquery {
                Person {
                    aname : someone{name}
                }

            } "#,
            &data_model,
        )
        .expect("alias is not conflicting");
    }

    #[test]
    fn entity_field() {
        let mut data_model = DataModel::new();
        data_model
            .update(
                "
            Person {
                parents : [Person],
                someone : Person
            } 

        ",
            )
            .unwrap();

        let _query = QueryParser::parse(
            r#"
            query aquery {
                Person {
                    parents
                }
            } "#,
            &data_model,
        )
        .expect_err("parents must be used with syntax parents{..}");

        let _query = QueryParser::parse(
            r#"
            query aquery {
                Person {
                    someone
                }
            } "#,
            &data_model,
        )
        .expect_err("someone must be used with syntax someone{..}");

        let _query = QueryParser::parse(
            r#"
            query aquery {
                Person {
                    parents{id}
                    someone{id}
                }
            } "#,
            &data_model,
        )
        .expect("good syntax");
    }

    #[test]
    fn filters() {
        let mut data_model = DataModel::new();
        data_model
            .update(
                "
            Person {
                name : String,
                age : Integer,
                weight : Float,
                parents : [Person] ,
                someone : Person
            } 

        ",
            )
            .unwrap();

        let _query = QueryParser::parse(
            r#"
            query aquery {
                Person (parents > 0) {
                    name
                }
            } "#,
            &data_model,
        )
        .expect_err("non scalar field cannot be used in filters");

        let _query = QueryParser::parse(
            r#"
            query aquery {
                Person (parents = null) {
                    name
                }
            } "#,
            &data_model,
        )
        .expect("nullable non scalar fields can check for the null value");

        let _query = QueryParser::parse(
            r#"
            query aquery {
                Person (parents != null) {
                    name
                }
            } "#,
            &data_model,
        )
        .expect("nullable non scalar fields can check for the null value");

        let _query = QueryParser::parse(
            r#"
            query aquery {
                Person (someone > 0) {
                    name
                }
            } "#,
            &data_model,
        )
        .expect_err("non scalar field cannot be used in filters");

        let _query = QueryParser::parse(
            r#"
            query aquery {
                Person (aage > 10) {
                    name
                }
            } "#,
            &data_model,
        )
        .expect_err("aage does not exists");

        let _query = QueryParser::parse(
            r#"
            query aquery {
                Person (age > 10.5) {
                    name
                }
            } "#,
            &data_model,
        )
        .expect_err("age is not a float");

        let _query = QueryParser::parse(
            r#"
            query aquery {
                Person (weight > 10) {
                    name
                }
            } "#,
            &data_model,
        )
        .expect("weight is a float and integer value will be cast as float");

        let _query = QueryParser::parse(
            r#"
            query aquery {
                Person (age > 10) {
                    name
                }
            } "#,
            &data_model,
        )
        .expect("age is an integer");
    }

    #[test]
    fn before_after() {
        let mut data_model = DataModel::new();
        data_model
            .update(
                "
            Person {
                name : String,
                age: Integer
            } 

        ",
            )
            .unwrap();

        let _query = QueryParser::parse(
            r#"
            query aquery {
                Person (
                    before($id, "someone"),   after($id, "someone")
                ) {
                    name
                }
            } "#,
            &data_model,
        )
        .expect_err("'after' and 'before' filters cannot be used at the same time");

        let _query = QueryParser::parse(
            r#"
            query aquery {
                Person (
                    before($id, $mdate)
                ) {
                    name, 
                }
            } "#,
            &data_model,
        )
        .expect_err("too many parameters ");

        let _query = QueryParser::parse(
            r#"
            query aquery {
                Person (
                    before(12345),
                    order_by (mdate asc, id desc)
                ) {
                    
                    id
                    name
                }
            } "#,
            &data_model,
        )
        .expect("valid  ");

        let _query = QueryParser::parse(
            r#"
            query aquery {
                Person (
                    before( "YXplYQ", 12345),
                    order_by (mdate asc, id desc)
                ) {
                    mdate
                    name
                }
            } "#,
            &data_model,
        )
        .expect_err("invalid parameter datatype  ");

        let _query = QueryParser::parse(
            r#"
            query aquery {
                Person (
                    before(12345, "YXplYQ"),
                    order_by (mdate asc, id desc)
                ) {
                    mdate
                    name
                    id
                }
            } "#,
            &data_model,
        )
        .expect("valid  ");

        let _query = QueryParser::parse(
            r#"
            query aquery {
                Person (
                    after(12345, "YXplYQ"),
                    order_by (mdate asc, id desc)
                ) {
                    mdate
                    name
                    id
                }
            } "#,
            &data_model,
        )
        .expect("valid  ");
    }

    #[test]
    fn search() {
        let mut data_model = DataModel::new();
        data_model
            .update(
                "
            Person {
                name : String,
                age: Integer
            } 

        ",
            )
            .unwrap();

        let _query = QueryParser::parse(
            r#"
            query aquery {
                Person (
                   search("hello")
                ) {
                    name
                }
            } "#,
            &data_model,
        )
        .expect("valid query");

        let _query = QueryParser::parse(
            r#"
            query aquery {
                Person (
                   search("hello"),
                   order_by(name asc)
                ) {
                    name
                }
            } "#,
            &data_model,
        )
        .expect_err("Cannot add sort field when using search()");

        let _query = QueryParser::parse(
            r#"
            query aquery {
                Person (
                   search("hello"),
                   before("invalid")
                ) {
                    name
                }
            } "#,
            &data_model,
        )
        .expect_err(" 'before' is not compatible with search()");

        let _query = QueryParser::parse(
            r#"
            query aquery {
                Person (
                   search("hello"),
                   after("invalid")
                ) {
                    name
                }
            } "#,
            &data_model,
        )
        .expect_err(" 'before' is not compatible with search()");
    }

    #[test]
    fn json() {
        let mut data_model = DataModel::new();
        data_model
            .update(
                "
            Person {
                name : String,
                data: Json
            } 

        ",
            )
            .unwrap();

        let _query = QueryParser::parse(
            r#"
            query aquery {
                Person (
                   data->1 = "tesst"
                ) {
                    name
                }
            } "#,
            &data_model,
        )
        .expect("valid query");

        let _query = QueryParser::parse(
            r#"
            query aquery {
                Person (
                  data->$.a[1].b = 1
                ) {
                    name
                }
            } "#,
            &data_model,
        )
        .expect("valid query");

        let _query = QueryParser::parse(
            r#"
            query aquery {
                Person (
                   data->1 = 1
                ) {
                    name
                    internal : data->1
                }
            } "#,
            &data_model,
        )
        .expect("valid query");

        let _query = QueryParser::parse(
            r#"
            query aquery {
                Person (
                   data->$.c[2].f = 1
                ) {
                    name
                    internal : data->$.c[2].f
                }
            } "#,
            &data_model,
        )
        .expect("valid query");

        let _query = QueryParser::parse(
            r#"
            query aquery {
                Person (
                   data->$.c[2].f = 1
                ) {
                    wrong: name->$.c[2].f
                    internal : data->$.c[2].f
                }
            } "#,
            &data_model,
        )
        .expect_err("name is not a json_type");
    }

    #[test]
    fn nullable_filter() {
        let mut data_model = DataModel::new();
        data_model
            .update(
                "
            Person {
                name : String,
                parent: [Person],
                someone: Person,
            } 

        ",
            )
            .unwrap();

        let _query = QueryParser::parse(
            r#"
            query aquery {
                Person (
                   nullable(parent)
                ) {
                    name
                }
            } "#,
            &data_model,
        )
        .expect_err("parent is not in the query fields");

        let _query = QueryParser::parse(
            r#"
            query aquery {
                Person (
                   nullable(name)
                ) {
                    name
                }
            } "#,
            &data_model,
        )
        .expect_err("name is not an entity type");

        let _query = QueryParser::parse(
            r#"
            query aquery {
                Person (
                   nullable(parent, someone)
                ) {
                    name
                    parent{ name }
                    someone{ name }
                }
            } "#,
            &data_model,
        )
        .expect("valid query");

        let _query = QueryParser::parse(
            r#"
            query aquery {
                Person (
                   nullable(parent, some)
                ) {
                    name
                    parent{ name }
                    some : someone{ name }
                }
            } "#,
            &data_model,
        )
        .expect("aliases are supported");
    }
}
