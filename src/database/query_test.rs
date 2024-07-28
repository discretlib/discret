#[cfg(test)]
mod tests {

    use rusqlite::Connection;
    use serde::Deserialize;

    use std::sync::Arc;

    use crate::database::mutation_query::MutationQuery;
    use crate::database::query_language::parameter::ParametersAdd;
    use crate::database::sqlite_database::Writeable;
    use crate::database::system_entities::SYSTEM_DATA_MODEL;
    use crate::database::ResultParser;
    use crate::database::{
        query::{PreparedQueries, Query},
        query_language::{
            data_model_parser::DataModel, mutation_parser::MutationParser, parameter::Parameters,
            query_parser::QueryParser,
        },
        sqlite_database::prepare_connection,
    };
    use crate::security::{uid_encode, Ed25519SigningKey};

    #[test]
    fn simple_scalar() {
        let mut data_model = DataModel::new();
        data_model
            .update(
                "
            {
                Person {
                    name : String ,
                    age : Integer,
                    weight : Float,
                    is_human : Boolean,
                    some_nullable : String nullable,
                }
            }",
            )
            .unwrap();

        let mutation = MutationParser::parse(
            r#"
            mutate {
                Person {
                    name : $name
                    age: $age
                    weight: $weight
                    is_human : $human
                    some_nullable : $null
                }
            } "#,
            &data_model,
        )
        .unwrap();

        let mut param = Parameters::new();
        param.add("name", String::from("John")).unwrap();
        param.add("age", 100).unwrap();
        param.add("weight", 42.2).unwrap();
        param.add("human", true).unwrap();
        param.add_null("null").unwrap();

        let conn = Connection::open_in_memory().unwrap();
        prepare_connection(&conn).unwrap();
        let mutation = Arc::new(mutation);
        let mut mutation_query = MutationQuery::execute(&mut param, mutation, &conn).unwrap();
        mutation_query.write(&conn).unwrap();

        let query_parser = QueryParser::parse(
            "
            query sample{
                Person {
                    name
                    age
                    weight
                    is_human
                    some_nullable
                }
                same_person: Person {
                    name
                    age
                    weight
                    is_human
                    some_nullable
                }
            }
        ",
            &data_model,
        )
        .unwrap();

        let query = PreparedQueries::build(&query_parser).unwrap();
        let param = Parameters::new();
        let mut sql = Query {
            parameters: param,
            parser: Arc::new(query_parser),
            sql_queries: Arc::new(query),
        };
        let result = sql.read(&conn).unwrap();

        let expected = "{\n\"Person\":[{\"name\":\"John\",\"age\":100,\"weight\":42.2,\"is_human\":true,\"some_nullable\":null}],\n\"same_person\":[{\"name\":\"John\",\"age\":100,\"weight\":42.2,\"is_human\":true,\"some_nullable\":null}]\n}";
        assert_eq!(expected, result);

        let query_parser = QueryParser::parse(
            r#"
            query sample{
                Person (
                    name = "John",
                    age = 100,
                    weight = 42.2,
                    is_human = true,
                    some_nullable = null
                ){
                    name
                    age
                    weight
                    is_human
                    some_nullable
                }
                same_person: Person {
                    name
                    age
                    weight
                    is_human
                    some_nullable
                }
            }
        "#,
            &data_model,
        )
        .unwrap();

        let query = PreparedQueries::build(&query_parser).unwrap();
        let param = Parameters::new();
        let mut sql = Query {
            parameters: param,
            parser: Arc::new(query_parser),
            sql_queries: Arc::new(query),
        };
        let result = sql.read(&conn).unwrap();

        let expected = "{\n\"Person\":[{\"name\":\"John\",\"age\":100,\"weight\":42.2,\"is_human\":true,\"some_nullable\":null}],\n\"same_person\":[{\"name\":\"John\",\"age\":100,\"weight\":42.2,\"is_human\":true,\"some_nullable\":null}]\n}";
        assert_eq!(expected, result);
    }

    #[test]
    fn system() {
        let mut data_model = DataModel::new();
        data_model
            .update(
                "{
            Person {
                name : String
            }
        }
        ",
            )
            .unwrap();

        let mutation = MutationParser::parse(
            r#"
            mutate {
                Person {
                    name : "hello"
                }
            } "#,
            &data_model,
        )
        .unwrap();

        let mut param = Parameters::new();
        let conn = Connection::open_in_memory().unwrap();
        prepare_connection(&conn).unwrap();

        let mutation = Arc::new(mutation);
        let mut mutation_query = MutationQuery::execute(&mut param, mutation, &conn).unwrap();

        let signing_key = Ed25519SigningKey::new();

        mutation_query.sign_all(&signing_key).unwrap();
        mutation_query.write(&conn).unwrap();

        let query_parser = QueryParser::parse(
            "
            query sample{
                Person {
                    id
                    cdate
                    mdate
                    _entity
                    _json
                    _binary
                    verifying_key
                    _signature
                }

            }
        ",
            &data_model,
        )
        .unwrap();

        let query = PreparedQueries::build(&query_parser).unwrap();
        let param = Parameters::new();
        let mut sql = Query {
            parameters: param,
            parser: Arc::new(query_parser),
            sql_queries: Arc::new(query),
        };
        let _ = sql
            .read(&conn)
            .expect("result changes everytime, just test that it creates a valid query");

        let query_parser = QueryParser::parse(
            r#"
            query sample{
                Person (
                id != "ZXRzZXRzNDMx",
                cdate < 1234341,
                mdate > 12345,
                _entity ="0",
                _json="",
                _binary = "ZXRzZXRzNDMx",
                verifying_key <="ZXRzZXRzNDMx",
                verifying_key >= "ZXRzZXRzNDMx",
            ){
                    id
                    cdate
                    mdate
                    _entity
                    _json
                    _binary
                    verifying_key
                    _signature
                }

            }
        "#,
            &data_model,
        )
        .unwrap();

        let query = PreparedQueries::build(&query_parser).unwrap();
        let param = Parameters::new();
        let mut sql = Query {
            parameters: param,
            parser: Arc::new(query_parser),
            sql_queries: Arc::new(query),
        };

        let _ = sql
            .read(&conn)
            .expect("result changes everytime, just test that it creates a valid query");
    }

    #[test]
    fn sub_system_entities() {
        let mut data_model = DataModel::new();
        data_model
            .update(
                "{
            Person {
                name : String,
                pet : Pet
            }

            Pet {
                name: String
            }
        }
        ",
            )
            .unwrap();

        let mutation = MutationParser::parse(
            r#"
            mutate {
                Person {
                    name: "hello"
                    pet: {name: "kitty"}
                }
            } "#,
            &data_model,
        )
        .unwrap();

        let mut param = Parameters::new();
        let conn = Connection::open_in_memory().unwrap();
        prepare_connection(&conn).unwrap();

        let mutation = Arc::new(mutation);
        let mut mutation_query = MutationQuery::execute(&mut param, mutation, &conn).unwrap();

        let signing_key = Ed25519SigningKey::new();

        mutation_query.sign_all(&signing_key).unwrap();
        mutation_query.write(&conn).unwrap();

        let query_parser = QueryParser::parse(
            "
            query sample{
                Person {
                    id
                    cdate
                    mdate
                    _entity
                    _json
                    _binary
                    verifying_key
                    _signature
                    name
                    pet {
                        id
                        cdate
                        mdate
                        _entity
                        _json
                        _binary
                        verifying_key
                        _signature
                        name
                    }
                }
            }
        ",
            &data_model,
        )
        .unwrap();

        let query = PreparedQueries::build(&query_parser).unwrap();
        let param = Parameters::new();
        let mut sql = Query {
            parameters: param,
            parser: Arc::new(query_parser),
            sql_queries: Arc::new(query),
        };
        let _ = sql
            .read(&conn)
            .expect("result changes everytime, just test that it creates a valid query");
    }

    #[test]
    fn id() {
        let conn = Connection::open_in_memory().unwrap();
        prepare_connection(&conn).unwrap();

        let mut data_model = DataModel::new();
        data_model
            .update(
                "{
            Person {
                name : String
            }
        }
        ",
            )
            .unwrap();

        let mutation = MutationParser::parse(
            r#"
            mutate {
                Person {
                    name : "hello"
                }
            } "#,
            &data_model,
        )
        .unwrap();

        let mut param = Parameters::new();

        let mutation = Arc::new(mutation);
        let mut mutation_query = MutationQuery::execute(&mut param, mutation, &conn).unwrap();
        let signing_key = Ed25519SigningKey::new();
        mutation_query.sign_all(&signing_key).unwrap();
        mutation_query.write(&conn).unwrap();

        let id = mutation_query.mutate_entities[0].node_to_mutate.id;

        let query_parser = QueryParser::parse(
            "
            query sample{
                Person(id=$id) {
                    id
                    name
                    _entity
                }
            }
            ",
            &data_model,
        )
        .unwrap();

        let query = PreparedQueries::build(&query_parser).unwrap();

        let mut param = Parameters::new();
        param.add("id", uid_encode(&id)).unwrap();

        let mut sql = Query {
            parameters: param,
            parser: Arc::new(query_parser),
            sql_queries: Arc::new(query),
        };
        let _ = sql.read(&conn).unwrap();
    }

    #[test]
    fn entity() {
        let mut data_model = DataModel::new();
        data_model
            .update(
                "
            {
                Person {
                    name : String ,
                    parents : [Person] ,
                    pet: Pet ,
                    siblings : [Person] ,
                }

                Pet {
                    name : String
                }
            }
        ",
            )
            .unwrap();

        let mutation = MutationParser::parse(
            r#"
            mutate {
                Person {
                    name : $name
                    parents:  [
                        {name : $mother}
                        ,{
                            name:$father
                            pet:{ name:"kiki" }
                        }
                    ]
                    pet: {name:$pet_name}
                    siblings:[{name:"Wallis"},{ name : $sibling }]
                }
            } "#,
            &data_model,
        )
        .unwrap();

        let mut param = Parameters::new();
        param.add("name", String::from("John")).unwrap();
        param.add("mother", String::from("Hello")).unwrap();
        param.add("father", String::from("World")).unwrap();
        param.add("pet_name", String::from("Truffle")).unwrap();
        param.add("sibling", String::from("Futuna")).unwrap();

        let conn = Connection::open_in_memory().unwrap();
        prepare_connection(&conn).unwrap();

        let mutation = Arc::new(mutation);
        let mut mutation_query = MutationQuery::execute(&mut param, mutation, &conn).unwrap();
        mutation_query.write(&conn).unwrap();

        let query_parser = QueryParser::parse(
            r#"
            query sample{
                Person (
                        remps_pets != NULL,
                        id != "zSRIyMbf70V999wyC0KlhQ",
                        name = "John",
                        order_by(name asc)
                    ) {
                    name
                    parents (name="World") {
                        name
                    }
                    pet {name}
                    remps_pets : parents (pet != null) {
                        name
                        pet {name}
                    }
                }

            }
        "#,
            &data_model,
        )
        .unwrap();

        let query = PreparedQueries::build(&query_parser).unwrap();
        let param = Parameters::new();
        let mut sql = Query {
            parameters: param,
            parser: Arc::new(query_parser),
            sql_queries: Arc::new(query),
        };

        let result = sql.read(&conn).unwrap();
        let expected = "{\n\"Person\":[{\"name\":\"John\",\"parents\":[{\"name\":\"World\"}],\"pet\":{\"name\":\"Truffle\"},\"remps_pets\":[{\"name\":\"World\",\"pet\":{\"name\":\"kiki\"}}]}]\n}";
        assert_eq!(expected, result);
    }

    #[test]
    fn entity_namespace() {
        let mut data_model = DataModel::new();
        data_model
            .update(
                "
            ns{
                Person {
                    name : String ,
                    parents : [ns.Person] ,
                    pet: ns.Pet ,
                    siblings : [ns.Person] ,
                }

                Pet {
                    name : String
                }
            }
        ",
            )
            .unwrap();

        let mutation = MutationParser::parse(
            r#"
            mutate {
                ns.Person {
                    name : $name
                    parents:  [
                        {name : $mother}
                        ,{
                            name:$father
                            pet:{ name:"kiki" }
                        }
                    ]
                    pet: {name:$pet_name}
                    siblings:[{name:"Wallis"},{ name : $sibling }]
                }
            } "#,
            &data_model,
        )
        .unwrap();

        let mut param = Parameters::new();
        param.add("name", String::from("John")).unwrap();
        param.add("mother", String::from("Hello")).unwrap();
        param.add("father", String::from("World")).unwrap();
        param.add("pet_name", String::from("Truffle")).unwrap();
        param.add("sibling", String::from("Futuna")).unwrap();

        let conn = Connection::open_in_memory().unwrap();
        prepare_connection(&conn).unwrap();

        let mutation = Arc::new(mutation);
        let mut mutation_query = MutationQuery::execute(&mut param, mutation, &conn).unwrap();
        mutation_query.write(&conn).unwrap();

        let query_parser = QueryParser::parse(
            r#"
            query {
                ns.Person (
                        remps_pets != NULL,
                        id != "zSRIyMbf70V999wyC0KlhQ",
                        name = "John",
                        order_by(name asc)
                    ) {
                    name
                    parents (name="World") {
                        name
                    }
                    pet {name}
                    remps_pets : parents (pet != null) {
                        name
                        pet {name}
                    }
                }

            }
        "#,
            &data_model,
        )
        .unwrap();

        let query = PreparedQueries::build(&query_parser).unwrap();
        let param = Parameters::new();
        let mut sql = Query {
            parameters: param,
            parser: Arc::new(query_parser),
            sql_queries: Arc::new(query),
        };

        let result = sql.read(&conn).unwrap();
        let expected = "{\n\"ns.Person\":[{\"name\":\"John\",\"parents\":[{\"name\":\"World\"}],\"pet\":{\"name\":\"Truffle\"},\"remps_pets\":[{\"name\":\"World\",\"pet\":{\"name\":\"kiki\"}}]}]\n}";
        assert_eq!(expected, result);
    }

    #[test]
    fn order_by_first_next_paging() {
        let conn = Connection::open_in_memory().unwrap();
        prepare_connection(&conn).unwrap();

        let mut data_model = DataModel::new();
        data_model
            .update(
                "ns {
            Person {
                name : String,
                age : Integer,
            }
        }
        ",
            )
            .unwrap();

        let mutation = MutationParser::parse(
            r#"
            mutate {
                ns.Person {
                    name : $name
                    age : $age
                }
            } "#,
            &data_model,
        )
        .unwrap();
        let mutation = Arc::new(mutation);

        let mut param = Parameters::new();
        param.add("name", "John".to_string()).unwrap();
        param.add("age", 42).unwrap();

        let mut mutation_query =
            MutationQuery::execute(&mut param, mutation.clone(), &conn).unwrap();
        mutation_query.write(&conn).unwrap();

        let mut param = Parameters::new();
        param.add("name", "Silvie".to_string()).unwrap();
        param.add("age", 46).unwrap();

        let mut mutation_query =
            MutationQuery::execute(&mut param, mutation.clone(), &conn).unwrap();
        mutation_query.write(&conn).unwrap();

        let mut param = Parameters::new();
        param.add("name", "Kevin".to_string()).unwrap();
        param.add("age", 22).unwrap();

        let mut mutation_query =
            MutationQuery::execute(&mut param, mutation.clone(), &conn).unwrap();
        mutation_query.write(&conn).unwrap();

        let mut param = Parameters::new();
        param.add("name", "Sarah".to_string()).unwrap();
        param.add("age", 12).unwrap();

        let mut mutation_query =
            MutationQuery::execute(&mut param, mutation.clone(), &conn).unwrap();
        mutation_query.write(&conn).unwrap();

        let mut param = Parameters::new();
        param.add("name", "Leonore".to_string()).unwrap();
        param.add("age", 22).unwrap();

        let mut mutation_query =
            MutationQuery::execute(&mut param, mutation.clone(), &conn).unwrap();
        mutation_query.write(&conn).unwrap();

        let query_parser = QueryParser::parse(
            r#"
            query sample{
                ns.Person (
                        order_by(age desc, name asc),
                        first 3,
                        skip 1
                    ) {
                    name
                    age
                }
            }
        "#,
            &data_model,
        )
        .unwrap();
        let query = PreparedQueries::build(&query_parser).unwrap();

        let mut sql = Query {
            parameters: Parameters::new(),
            parser: Arc::new(query_parser),
            sql_queries: Arc::new(query),
        };

        let result = sql.read(&conn).unwrap();
        let expected = "{\n\"ns.Person\":[{\"name\":\"John\",\"age\":42},{\"name\":\"Kevin\",\"age\":22},{\"name\":\"Leonore\",\"age\":22}]\n}";
        assert_eq!(expected, result);

        let query_parser = QueryParser::parse(
            r#"
            query sample{
                ns.Person (
                        order_by(age desc, name asc),
                        after(22)
                    ) {
                    name
                    age
                }
            }
        "#,
            &data_model,
        )
        .unwrap();
        let query = PreparedQueries::build(&query_parser).unwrap();

        let mut sql = Query {
            parameters: Parameters::new(),
            parser: Arc::new(query_parser),
            sql_queries: Arc::new(query),
        };
        let result = sql.read(&conn).unwrap();
        let expected = "{\n\"ns.Person\":[{\"name\":\"Sarah\",\"age\":12}]\n}";
        assert_eq!(expected, result);

        let query_parser = QueryParser::parse(
            r#"
            query sample{
                ns.Person (
                        order_by(age desc, name asc),
                        after (22,"Kevin")
                    ) {
                    name
                    age
                }
            }
        "#,
            &data_model,
        )
        .unwrap();
        let query = PreparedQueries::build(&query_parser).unwrap();

        let mut sql = Query {
            parameters: Parameters::new(),
            parser: Arc::new(query_parser),
            sql_queries: Arc::new(query),
        };

        let result = sql.read(&conn).unwrap();
        let expected =
            "{\n\"ns.Person\":[{\"name\":\"Leonore\",\"age\":22},{\"name\":\"Sarah\",\"age\":12}]\n}";
        assert_eq!(expected, result);

        let query_parser = QueryParser::parse(
            r#"
            query sample{
                ns.Person (
                        order_by(age desc, name desc),
                        after (22,"Leonore")
                    ) {
                    name
                    age
                }
            }
        "#,
            &data_model,
        )
        .unwrap();
        let query = PreparedQueries::build(&query_parser).unwrap();

        let mut sql = Query {
            parameters: Parameters::new(),
            parser: Arc::new(query_parser),
            sql_queries: Arc::new(query),
        };
        let result = sql.read(&conn).unwrap();
        let expected =
            "{\n\"ns.Person\":[{\"name\":\"Kevin\",\"age\":22},{\"name\":\"Sarah\",\"age\":12}]\n}";
        assert_eq!(expected, result);

        let query_parser = QueryParser::parse(
            r#"
            query sample{
                ns.Person (
                        order_by(age desc, name desc),
                        before (22,"Leonore")
                    ) {
                    name
                    age
                }
            }
        "#,
            &data_model,
        )
        .unwrap();
        let query = PreparedQueries::build(&query_parser).unwrap();

        let mut sql = Query {
            parameters: Parameters::new(),
            parser: Arc::new(query_parser),
            sql_queries: Arc::new(query),
        };
        let result = sql.read(&conn).unwrap();
        let expected =
            "{\n\"ns.Person\":[{\"name\":\"Silvie\",\"age\":46},{\"name\":\"John\",\"age\":42}]\n}";
        assert_eq!(expected, result);
    }

    #[test]
    fn filter() {
        let mut data_model = DataModel::new();
        data_model
            .update(
                "
            ns{
                Person {
                    name : String ,
                    age : Integer,
                    weight : Float,
                    is_human : Boolean,
                }
            }
        ",
            )
            .unwrap();

        let mutation = MutationParser::parse(
            r#"
            mutate {
                ns.Person {
                    name : "John"
                    age: 23
                    weight: 10
                    is_human : true
                }
                P1: ns.Person {
                    name : "Doe"
                    age: 32
                    weight: 12
                    is_human : true
                }
                P2: ns.Person {
                    name : "Jean"
                    age: 53
                    weight: 100
                    is_human : false
                }
            } "#,
            &data_model,
        )
        .unwrap();
        let conn = Connection::open_in_memory().unwrap();
        prepare_connection(&conn).unwrap();

        let mut param = Parameters::new();
        let mutation = Arc::new(mutation);
        let mut mutation_query = MutationQuery::execute(&mut param, mutation, &conn).unwrap();
        mutation_query.write(&conn).unwrap();

        let query_parser = QueryParser::parse(
            r#"
            query sample{
                ns.Person (name = "Jean", age < 100, weight >=100, is_human = false){
                    name
                    age
                    weight
                    is_human
                }
            }
        "#,
            &data_model,
        )
        .unwrap();

        let query = PreparedQueries::build(&query_parser).unwrap();
        let param = Parameters::new();
        let mut sql = Query {
            parameters: param,
            parser: Arc::new(query_parser),
            sql_queries: Arc::new(query),
        };
        let result = sql.read(&conn).unwrap();

        let expected =
            "{\n\"ns.Person\":[{\"name\":\"Jean\",\"age\":53,\"weight\":100.0,\"is_human\":false}]\n}";
        assert_eq!(expected, result);

        let query_parser = QueryParser::parse(
            r#"
            query sample{
                ns.Person (name = $name, age < $age, weight >= $we, is_human = $hum){
                    name
                    age
                    weight
                    is_human
                }
            }
        "#,
            &data_model,
        )
        .unwrap();

        let query = PreparedQueries::build(&query_parser).unwrap();
        let mut param = Parameters::new();
        param.add("name", "Jean".to_string()).unwrap();
        param.add("age", 100).unwrap();
        param.add("we", 100.0).unwrap();
        param.add("hum", false).unwrap();

        let mut sql = Query {
            parameters: param,
            parser: Arc::new(query_parser),
            sql_queries: Arc::new(query),
        };
        let result = sql.read(&conn).unwrap();

        let expected =
            "{\n\"ns.Person\":[{\"name\":\"Jean\",\"age\":53,\"weight\":100.0,\"is_human\":false}]\n}";
        assert_eq!(expected, result);
    }

    #[test]
    //test variable name reuse and internalised string
    fn positional_param() {
        let mut data_model = DataModel::new();
        data_model
            .update(
                "
            ns {
                Person {
                    name : String ,
                    surname : String,
                    pseudo : String,
                    is_human : Boolean,
                }
            }
        ",
            )
            .unwrap();

        let mutation = MutationParser::parse(
            r#"
            mutate {
                ns.Person {
                    name : "John"
                    surname : "John"
                    pseudo : "John"
                    is_human : true
                }
            } "#,
            &data_model,
        )
        .unwrap();
        let conn = Connection::open_in_memory().unwrap();
        prepare_connection(&conn).unwrap();

        let mut param = Parameters::new();
        let mutation = Arc::new(mutation);
        let mut mutation_query = MutationQuery::execute(&mut param, mutation, &conn).unwrap();
        mutation_query.write(&conn).unwrap();

        let query_parser = QueryParser::parse(
            r#"
            query sample{
                ns.Person (name = $name, surname = "John", surname = $name, is_human = true){
                    name
                    surname
                    pseudo
                    is_human
                }
            }
        "#,
            &data_model,
        )
        .unwrap();

        let query = PreparedQueries::build(&query_parser).unwrap();
        let mut param = Parameters::new();
        param.add("name", "John".to_string()).unwrap();
        let mut sql = Query {
            parameters: param,
            parser: Arc::new(query_parser),
            sql_queries: Arc::new(query),
        };

        let result = sql.read(&conn).unwrap();

        let expected =
             "{\n\"ns.Person\":[{\"name\":\"John\",\"surname\":\"John\",\"pseudo\":\"John\",\"is_human\":true}]\n}";
        assert_eq!(expected, result);
    }

    #[test]
    fn aggregate() {
        let mut data_model = DataModel::new();
        data_model
            .update(
                "
        ns{
            Person {
                age : Integer,
                weight : Float,
                nat: String,
            }
        }
        ",
            )
            .unwrap();

        let mutation = MutationParser::parse(
            r#"
           mutate {
                P1: ns.Person { age:24 weight:45 nat:"us" }
                P2: ns.Person { age:12 weight:23 nat:"us" }
                P3: ns.Person { age:45 weight:86 nat:"fr" }
                P4: ns.Person { age:34 weight:43 nat:"fr" }
                P5: ns.Person { age:54 weight:70 nat:"sa" }
                P6: ns.Person { age:67 weight:85 nat:"sa" }
                P7: ns.Person { age:72 weight:65 nat:"sa" }
                P8: ns.Person { age:24 weight:95 nat:"en" }
                P9: ns.Person { age:1 weight:52 nat:"en" }
                P10: ns.Person { age:45 weight:65 nat:"en" }
                P11: ns.Person { age:24 weight:75 nat:"en" }
            } "#,
            &data_model,
        )
        .unwrap();
        let conn = Connection::open_in_memory().unwrap();
        prepare_connection(&conn).unwrap();

        let mut param = Parameters::new();
        let mutation = Arc::new(mutation);
        let mut mutation_query = MutationQuery::execute(&mut param, mutation, &conn).unwrap();
        mutation_query.write(&conn).unwrap();

        let query_parser = QueryParser::parse(
            r#"
            query sample{
                ns.Person (order_by(avg asc, count asc, max asc,min asc,sum asc)) {
                    nat
                    avg: avg(weight)
                    count: count()
                    max: max(weight)
                    min: min(weight)
                    sum: sum(weight)
                }
            }
        "#,
            &data_model,
        )
        .unwrap();

        let query = PreparedQueries::build(&query_parser).unwrap();
        let param = Parameters::new();
        let mut sql = Query {
            parameters: param,
            parser: Arc::new(query_parser),
            sql_queries: Arc::new(query),
        };
        let result = sql.read(&conn).unwrap();

        let expected =
        "{\n\"ns.Person\":[{\"nat\":\"us\",\"avg\":34.0,\"count\":2,\"max\":45.0,\"min\":23.0,\"sum\":68.0},{\"nat\":\"fr\",\"avg\":64.5,\"count\":2,\"max\":86.0,\"min\":43.0,\"sum\":129.0},{\"nat\":\"en\",\"avg\":71.75,\"count\":4,\"max\":95.0,\"min\":52.0,\"sum\":287.0},{\"nat\":\"sa\",\"avg\":73.3333333333333,\"count\":3,\"max\":85.0,\"min\":65.0,\"sum\":220.0}]\n}";
        assert_eq!(expected, result);

        let query_parser = QueryParser::parse(
            r#"
            query sample{
                ns.Person (order_by(avg asc, count asc, max asc,min asc,sum asc)) {
                    nat
                    avg: avg(mdate)
                    count: count()
                    max: max(cdate)
                    min: min(cdate)
                    sum: sum(cdate)
                }
            }
        "#,
            &data_model,
        )
        .unwrap();

        let query = PreparedQueries::build(&query_parser).unwrap();
        let param = Parameters::new();
        let mut sql = Query {
            parameters: param,
            parser: Arc::new(query_parser),
            sql_queries: Arc::new(query),
        };
        let _result = sql.read(&conn).unwrap();

        let query_parser = QueryParser::parse(
            r#"
            query {
                ns.Person (
                    order_by(nat asc, count desc),
                    count > 2,
                    after("en", 3)
            ) {
                    nat
                    avg: avg(weight)
                    count: count()
                    max: max(weight)
                    min: min(weight)
                    sum: sum(weight)
                }
            }
        "#,
            &data_model,
        )
        .unwrap();

        let query = PreparedQueries::build(&query_parser).unwrap();
        let param = Parameters::new();
        let mut sql = Query {
            parameters: param,
            parser: Arc::new(query_parser),
            sql_queries: Arc::new(query),
        };

        let result = sql.read(&conn).unwrap();

        let expected ="{\n\"ns.Person\":[{\"nat\":\"sa\",\"avg\":73.3333333333333,\"count\":3,\"max\":85.0,\"min\":65.0,\"sum\":220.0}]\n}";
        assert_eq!(expected, result);
    }

    #[test]
    fn search() {
        let mut data_model = DataModel::new();
        data_model
            .update(
                "
            ns {
                Person {
                    name : String,
                    comment : String,
                }
            }
        ",
            )
            .unwrap();

        let mutation = MutationParser::parse(
            r#"
            mutate {
                P1: ns.Person { name:"John" comment:"Lorem ipsum sit doler et ames" }
                P2: ns.Person { name:"Alice" comment:"Lorem lorem ipsum " }
                P3: ns.Person { name:"Bob" comment:"A completely different comment" }
            } "#,
            &data_model,
        )
        .unwrap();
        let conn = Connection::open_in_memory().unwrap();
        prepare_connection(&conn).unwrap();

        let mut param = Parameters::new();
        let mutation = Arc::new(mutation);
        let mut mutation_query = MutationQuery::execute(&mut param, mutation, &conn).unwrap();
        mutation_query.write(&conn).unwrap();

        let query_parser = QueryParser::parse(
            r#"
            query sample{
                ns.Person(search("ames")) {
                    name
                    comment
                }
            }
        "#,
            &data_model,
        )
        .unwrap();

        let query = PreparedQueries::build(&query_parser).unwrap();
        let param = Parameters::new();
        let mut sql = Query {
            parameters: param,
            parser: Arc::new(query_parser),
            sql_queries: Arc::new(query),
        };

        let result = sql.read(&conn).unwrap();

        let expected =
            "{\n\"ns.Person\":[{\"name\":\"John\",\"comment\":\"Lorem ipsum sit doler et ames\"}]\n}";
        assert_eq!(expected, result);
    }

    #[test]
    fn disable_search() {
        let mut data_model = DataModel::new();
        data_model
            .update(
                "
            ns {
                Person (no_full_text_index){
                    name : String,
                    comment : String,
                }
            }
        ",
            )
            .unwrap();

        let mutation = MutationParser::parse(
            r#"
            mutate {
                P1: ns.Person { name:"John" comment:"Lorem ipsum sit doler et ames" }
                P2: ns.Person { name:"Alice" comment:"Lorem lorem ipsum " }
                P3: ns.Person { name:"Bob" comment:"A completely different comment" }
            } "#,
            &data_model,
        )
        .unwrap();
        let conn = Connection::open_in_memory().unwrap();
        prepare_connection(&conn).unwrap();

        let mut param = Parameters::new();
        let mutation = Arc::new(mutation);
        let mut mutation_query = MutationQuery::execute(&mut param, mutation, &conn).unwrap();
        mutation_query.write(&conn).unwrap();

        let query_parser = QueryParser::parse(
            r#"
            query sample{
                ns.Person(search("ames")) {
                    name
                    comment
                }
            }
        "#,
            &data_model,
        )
        .unwrap();

        let query = PreparedQueries::build(&query_parser).unwrap();
        let param = Parameters::new();
        let mut sql = Query {
            parameters: param,
            parser: Arc::new(query_parser),
            sql_queries: Arc::new(query),
        };

        let result = sql.read(&conn).unwrap();

        let expected = "{\n\"ns.Person\":[]\n}";
        assert_eq!(expected, result);
    }

    #[test]
    fn default_value() {
        let mut data_model = DataModel::new();

        data_model
            .update(
                r#"
            ns {
                Person {
                    name : String,
                    def : String default "Lorem ipsum",
                }
            }
        "#,
            )
            .unwrap();

        let mutation = MutationParser::parse(
            r#"
            mutate {
                P2: ns.Person { name:"Alice"  }
                P3: ns.Person { name:"Bob" def:"A completely different" }
            } "#,
            &data_model,
        )
        .unwrap();
        let conn = Connection::open_in_memory().unwrap();
        prepare_connection(&conn).unwrap();

        let mut param = Parameters::new();
        let mutation = Arc::new(mutation);
        let mut mutation_query = MutationQuery::execute(&mut param, mutation, &conn).unwrap();
        mutation_query.write(&conn).unwrap();

        let query_parser = QueryParser::parse(
            r#"
            query sample{
                ns.Person(order_by(name Asc)) {
                    name
                    def
                }
            }
        "#,
            &data_model,
        )
        .unwrap();

        let query = PreparedQueries::build(&query_parser).unwrap();
        let param = Parameters::new();
        let mut sql = Query {
            parameters: param,
            parser: Arc::new(query_parser),
            sql_queries: Arc::new(query),
        };
        let result = sql.read(&conn).unwrap();

        let expected =
            "{\n\"ns.Person\":[{\"name\":\"Alice\",\"def\":\"Lorem ipsum\"},{\"name\":\"Bob\",\"def\":\"A completely different\"}]\n}";
        assert_eq!(expected, result);

        data_model
            .update(
                r#"
            ns {
                Person {
                    name : String,
                    def : String default "Lorem ipsum",
                    newdef : String default "sit met",
                }
            }
        "#,
            )
            .unwrap();

        //old rows  will return the default value of the 'newdef' field
        let query_parser = QueryParser::parse(
            r#"
                query sample{
                    ns.Person(order_by(name asc)) {
                        name
                        def
                        newdef
                    }
                }
            "#,
            &data_model,
        )
        .unwrap();

        let query = PreparedQueries::build(&query_parser).unwrap();
        let param = Parameters::new();
        let mut sql = Query {
            parameters: param,
            parser: Arc::new(query_parser),
            sql_queries: Arc::new(query),
        };
        let result = sql.read(&conn).unwrap();
        let expected =
        "{\n\"ns.Person\":[{\"name\":\"Alice\",\"def\":\"Lorem ipsum\",\"newdef\":\"sit met\"},{\"name\":\"Bob\",\"def\":\"A completely different\",\"newdef\":\"sit met\"}]\n}";
        assert_eq!(expected, result);
    }

    #[test]
    fn json() {
        let mut data_model = DataModel::new();

        data_model
            .update(
                r#"
            ns{
                Person {
                    name : String,
                    data : Json,
                }
            }"#,
            )
            .unwrap();

        let mutation = MutationParser::parse(
            r#"
            mutate {
                P2: ns.Person { name:"Alice" data:"{\"val\":\"hello json\"}" }
                P3: ns.Person { name:"Bob" data:"[1,2,3,4]" }
            } "#,
            &data_model,
        )
        .unwrap();

        let mut param = Parameters::new();
        param
            .add("data", String::from(r#"{"val":"hello json"}"#))
            .unwrap();

        let conn = Connection::open_in_memory().unwrap();
        prepare_connection(&conn).unwrap();
        let mutation = Arc::new(mutation);
        let mut mutation_query = MutationQuery::execute(&mut param, mutation, &conn).unwrap();
        mutation_query.write(&conn).unwrap();

        let query_parser = QueryParser::parse(
            "
            query sample{
                ns.Person (order_by(name asc)){
                    name
                    data
                    array: data->$.val
                }
            }
        ",
            &data_model,
        )
        .unwrap();

        let query = PreparedQueries::build(&query_parser).unwrap();
        let param = Parameters::new();
        let mut sql = Query {
            parameters: param,
            parser: Arc::new(query_parser),
            sql_queries: Arc::new(query),
        };
        let result = sql.read(&conn).unwrap();
        let expected =
        "{\n\"ns.Person\":[{\"name\":\"Alice\",\"data\":{\"val\":\"hello json\"},\"array\":\"hello json\"},{\"name\":\"Bob\",\"data\":[1,2,3,4],\"array\":null}]\n}";
        assert_eq!(expected, result);

        let query_parser = QueryParser::parse(
            "
            query sample{
                ns.Person(order_by(name asc)) {
                    name
                    data
                    array: data->1
                }
            }
        ",
            &data_model,
        )
        .unwrap();

        let query = PreparedQueries::build(&query_parser).unwrap();
        let param = Parameters::new();
        let mut sql = Query {
            parameters: param,
            parser: Arc::new(query_parser),
            sql_queries: Arc::new(query),
        };
        let result = sql.read(&conn).unwrap();

        let expected =
        "{\n\"ns.Person\":[{\"name\":\"Alice\",\"data\":{\"val\":\"hello json\"},\"array\":null},{\"name\":\"Bob\",\"data\":[1,2,3,4],\"array\":2}]\n}";
        assert_eq!(expected, result);

        let query_parser = QueryParser::parse(
            "
            query sample{
                ns.Person (data->1 = 2, order_by(array asc)) {
                    name
                    data
                    array: data->1
                }
            }
        ",
            &data_model,
        )
        .unwrap();

        let query = PreparedQueries::build(&query_parser).unwrap();
        let param = Parameters::new();
        let mut sql = Query {
            parameters: param,
            parser: Arc::new(query_parser),
            sql_queries: Arc::new(query),
        };
        let result = sql.read(&conn).unwrap();

        let expected = "{\n\"ns.Person\":[{\"name\":\"Bob\",\"data\":[1,2,3,4],\"array\":2}]\n}";
        assert_eq!(expected, result);

        let query_parser = QueryParser::parse(
            r#"
            query sample{
                ns.Person (data->$.val = "hello json", order_by(array asc)) {
                    name
                    data
                    array: data->$.val
                }
            }
        "#,
            &data_model,
        )
        .unwrap();

        let query = PreparedQueries::build(&query_parser).unwrap();
        let param = Parameters::new();
        let mut sql = Query {
            parameters: param,
            parser: Arc::new(query_parser),
            sql_queries: Arc::new(query),
        };

        let result = sql.read(&conn).unwrap();

        let expected =
        "{\n\"ns.Person\":[{\"name\":\"Alice\",\"data\":{\"val\":\"hello json\"},\"array\":\"hello json\"}]\n}";
        assert_eq!(expected, result);
    }

    #[test]
    fn entity_not_null_selection() {
        let mut data_model = DataModel::new();
        data_model
            .update(
                "
            ns {
                Person {
                    name : String ,
                    parents : [ns.Person] ,
                    pet: ns.Pet ,
                }

                Pet {
                    name : String
                }
            }
        ",
            )
            .unwrap();

        let mutation = MutationParser::parse(
            r#"
            mutate {
                P1: ns.Person {
                    name : "John"
                    parents:  [ {name : "John Mother"} ,{ name:"John Father" pet:{ name:"Kiki" }}]
                    pet: { name:"Truffle"}
                }
                P2: ns.Person {
                    name : "Ada"
                    parents:  [ {name : "Ada Mother" pet:{ name:"Lulu" }} ,{ name:"Ada Father" pet:{ name:"Waf" }}]
                }

            } "#,
            &data_model,
        )
        .unwrap();

        let mut param = Parameters::new();

        let conn = Connection::open_in_memory().unwrap();
        prepare_connection(&conn).unwrap();

        let mutation = Arc::new(mutation);
        let mut mutation_query = MutationQuery::execute(&mut param, mutation, &conn).unwrap();
        mutation_query.write(&conn).unwrap();

        let query_parser = QueryParser::parse(
            r#"
            query sample{
                ns.Person (order_by(name asc)) {
                    name
                    parents (order_by(name asc)){
                        name
                    }
                    pet {name}
                    parents_pets : parents (order_by(name asc)) {
                        name
                        pet {name}
                    }
                }
            }
        "#,
            &data_model,
        )
        .unwrap();

        let query = PreparedQueries::build(&query_parser).unwrap();
        let param = Parameters::new();
        let mut sql = Query {
            parameters: param,
            parser: Arc::new(query_parser),
            sql_queries: Arc::new(query),
        };
        let result = sql.read(&conn).unwrap();
        let expected = "{\n\"ns.Person\":[{\"name\":\"John\",\"parents\":[{\"name\":\"John Father\"},{\"name\":\"John Mother\"}],\"pet\":{\"name\":\"Truffle\"},\"parents_pets\":[{\"name\":\"John Father\",\"pet\":{\"name\":\"Kiki\"}}]}]\n}";
        assert_eq!(expected, result);

        let query_parser = QueryParser::parse(
            r#"
            query sample{
                ns.Person (order_by(name asc)) {
                    name
                    parents (order_by(name asc)){
                        name
                    }

                    parents_pets : parents (order_by(name asc)) {
                        name
                        pet {name}
                    }
                }
            }
        "#,
            &data_model,
        )
        .unwrap();

        let query = PreparedQueries::build(&query_parser).unwrap();
        let param = Parameters::new();
        let mut sql = Query {
            parameters: param,
            parser: Arc::new(query_parser),
            sql_queries: Arc::new(query),
        };

        let result = sql.read(&conn).unwrap();
        let expected = "{\n\"ns.Person\":[{\"name\":\"Ada\",\"parents\":[{\"name\":\"Ada Father\"},{\"name\":\"Ada Mother\"}],\"parents_pets\":[{\"name\":\"Ada Father\",\"pet\":{\"name\":\"Waf\"}},{\"name\":\"Ada Mother\",\"pet\":{\"name\":\"Lulu\"}}]},{\"name\":\"John\",\"parents\":[{\"name\":\"John Father\"},{\"name\":\"John Mother\"}],\"parents_pets\":[{\"name\":\"John Father\",\"pet\":{\"name\":\"Kiki\"}}]}]\n}";
        assert_eq!(expected, result);
    }

    #[test]
    fn entity_nullable_selection() {
        let mut data_model = DataModel::new();
        data_model
            .update(
                "
            ns {
                Person {
                    name : String ,
                    parents : [ns.Person] nullable,
                    pet: ns.Pet ,
                }

                Pet {
                    name : String
                }
            }",
            )
            .unwrap();

        let mutation = MutationParser::parse(
            r#"
            mutate {
                P1: ns.Person {
                    name : "John"
                    parents:  [ {name : "John Mother"} ,{ name:"John Father" pet:{ name:"Kiki" }}]
                    pet: { name:"Truffle"}
                }
                P2: ns.Person {
                    name : "Ada"
                    parents:  [ {name : "Ada Mother" pet:{ name:"Lulu" }} ,{ name:"Ada Father" pet:{ name:"Waf" }}]
                }

            } "#,
            &data_model,
        )
        .unwrap();

        let mut param = Parameters::new();
        let conn = Connection::open_in_memory().unwrap();
        prepare_connection(&conn).unwrap();

        let mutation = Arc::new(mutation);
        let mut mutation_query = MutationQuery::execute(&mut param, mutation, &conn).unwrap();
        mutation_query.write(&conn).unwrap();

        let query_parser = QueryParser::parse(
            r#"
            query sample{
                ns.Person (order_by(name asc)) {
                    name
                    parents (order_by(name asc)) {name}
                }
            }
        "#,
            &data_model,
        )
        .unwrap();

        let query = PreparedQueries::build(&query_parser).unwrap();
        let param = Parameters::new();
        let mut sql = Query {
            parameters: param,
            parser: Arc::new(query_parser),
            sql_queries: Arc::new(query),
        };
        let result = sql.read(&conn).unwrap();
        let expected = "{\n\"ns.Person\":[{\"name\":\"Ada\",\"parents\":[{\"name\":\"Ada Father\"},{\"name\":\"Ada Mother\"}]},{\"name\":\"Ada Father\",\"parents\":[]},{\"name\":\"Ada Mother\",\"parents\":[]},{\"name\":\"John\",\"parents\":[{\"name\":\"John Father\"},{\"name\":\"John Mother\"}]},{\"name\":\"John Father\",\"parents\":[]},{\"name\":\"John Mother\",\"parents\":[]}]\n}";
        assert_eq!(expected, result);

        let query_parser = QueryParser::parse(
            r#"
            query {
                ns.Person (order_by(name asc), nullable(has_pet) ) {
                    name
                    has_pet: pet {name}
                }
            }
        "#,
            &data_model,
        )
        .unwrap();

        let query = PreparedQueries::build(&query_parser).unwrap();
        let param = Parameters::new();
        let mut sql = Query {
            parameters: param,
            parser: Arc::new(query_parser),
            sql_queries: Arc::new(query),
        };
        let result = sql.read(&conn).unwrap();
        let expected = "{\n\"ns.Person\":[{\"name\":\"Ada\",\"has_pet\":null},{\"name\":\"Ada Father\",\"has_pet\":{\"name\":\"Waf\"}},{\"name\":\"Ada Mother\",\"has_pet\":{\"name\":\"Lulu\"}},{\"name\":\"John\",\"has_pet\":{\"name\":\"Truffle\"}},{\"name\":\"John Father\",\"has_pet\":{\"name\":\"Kiki\"}},{\"name\":\"John Mother\",\"has_pet\":null}]\n}";
        assert_eq!(expected, result);
    }

    #[test]
    fn author_virtual_field() {
        let mut data_model = DataModel::new();
        data_model.update_system(SYSTEM_DATA_MODEL).unwrap();
        data_model
            .update(
                "
            ns {
                Person {
                    name : String ,
                    parents : [ns.Person] ,
                    pet: ns.Pet ,
                }

                Pet {
                    name : String
                }
            }",
            )
            .unwrap();

        let mutation = MutationParser::parse(
            r#"
            mutate {
                auth: sys.Peer {
                    pub_key: "TWFueSBoYW5kcyBtYWtlIGxpZ2h0IHdvcmsu"
                }

                P1: ns.Person {
                    name : "John"
                    parents:  [ {name : "John Mother"} ,{ name:"John Father" pet:{ name:"Kiki" }}]
                    pet: { name:"Truffle"}
                }
                P2: ns.Person {
                    name : "Ada"
                    parents:  [ {name : "Ada Mother" pet:{ name:"Lulu" }} ,{ name:"Ada Father" pet:{ name:"Waf" }}]
                }

            } "#,
            &data_model,
        )
        .unwrap();

        let mut param = Parameters::new();
        let conn = Connection::open_in_memory().unwrap();
        prepare_connection(&conn).unwrap();

        let mutation = Arc::new(mutation);
        let mut mutation_query = MutationQuery::execute(&mut param, mutation, &conn).unwrap();
        mutation_query.write(&conn).unwrap();

        let query_parser = QueryParser::parse(
            r#"
            query sample{
                ns.Person (order_by(name asc)) {
                    name
                    sys_peer{
                        pub_key
                    }
                    parents (order_by(name asc)) {
                        name
                        sys_peer{
                            pub_key
                        }
                    }
                }
            }
        "#,
            &data_model,
        )
        .unwrap();

        let query = PreparedQueries::build(&query_parser).unwrap();

        let param = Parameters::new();
        let mut sql = Query {
            parameters: param,
            parser: Arc::new(query_parser),
            sql_queries: Arc::new(query),
        };
        let result = sql.read(&conn).unwrap();

        let expected = "{\n\"ns.Person\":[{\"name\":\"Ada\",\"sys_peer\":{\"pub_key\":\"TWFueSBoYW5kcyBtYWtlIGxpZ2h0IHdvcmsu\"},\"parents\":[{\"name\":\"Ada Father\",\"sys_peer\":{\"pub_key\":\"TWFueSBoYW5kcyBtYWtlIGxpZ2h0IHdvcmsu\"}},{\"name\":\"Ada Mother\",\"sys_peer\":{\"pub_key\":\"TWFueSBoYW5kcyBtYWtlIGxpZ2h0IHdvcmsu\"}}]},{\"name\":\"John\",\"sys_peer\":{\"pub_key\":\"TWFueSBoYW5kcyBtYWtlIGxpZ2h0IHdvcmsu\"},\"parents\":[{\"name\":\"John Father\",\"sys_peer\":{\"pub_key\":\"TWFueSBoYW5kcyBtYWtlIGxpZ2h0IHdvcmsu\"}},{\"name\":\"John Mother\",\"sys_peer\":{\"pub_key\":\"TWFueSBoYW5kcyBtYWtlIGxpZ2h0IHdvcmsu\"}}]}]\n}";
        assert_eq!(expected, result);

        let query_parser = QueryParser::parse(
            r#"
            query sample{
                ns.Person (order_by(name asc),  nullable(sys_peer)) {
                    name
                    sys_peer (pub_key="cXNkcXNkcXM",){
                        pub_key
                    }
                    parents (order_by(name asc)) {
                        name
                        sys_peer{
                            pub_key
                        }
                    }
                }
            }
        "#,
            &data_model,
        )
        .unwrap();

        let query = PreparedQueries::build(&query_parser).unwrap();

        let param = Parameters::new();
        let mut sql = Query {
            parameters: param,
            parser: Arc::new(query_parser),
            sql_queries: Arc::new(query),
        };
        let result = sql.read(&conn).unwrap();
        let expected = "{\n\"ns.Person\":[{\"name\":\"Ada\",\"sys_peer\":null,\"parents\":[{\"name\":\"Ada Father\",\"sys_peer\":{\"pub_key\":\"TWFueSBoYW5kcyBtYWtlIGxpZ2h0IHdvcmsu\"}},{\"name\":\"Ada Mother\",\"sys_peer\":{\"pub_key\":\"TWFueSBoYW5kcyBtYWtlIGxpZ2h0IHdvcmsu\"}}]},{\"name\":\"John\",\"sys_peer\":null,\"parents\":[{\"name\":\"John Father\",\"sys_peer\":{\"pub_key\":\"TWFueSBoYW5kcyBtYWtlIGxpZ2h0IHdvcmsu\"}},{\"name\":\"John Mother\",\"sys_peer\":{\"pub_key\":\"TWFueSBoYW5kcyBtYWtlIGxpZ2h0IHdvcmsu\"}}]}]\n}";
        assert_eq!(expected, result);
    }

    #[test]
    fn room_virtual_field() {
        let mut data_model = DataModel::new();
        data_model.update_system(SYSTEM_DATA_MODEL).unwrap();
        data_model
            .update(
                "
            ns {
                Person {
                    name : String ,
                    parents : [ns.Person] ,
                    pet: ns.Pet ,
                }

                Pet {
                    name : String
                }
            }",
            )
            .unwrap();

        let conn: Connection = Connection::open_in_memory().unwrap();
        prepare_connection(&conn).unwrap();

        let mutation = MutationParser::parse(
            r#"
            mutate {
                auth: sys.Peer {
                    pub_key: "TWFueSBoYW5kcyBtYWtlIGxpZ2h0IHdvcmsu"
                }
            } "#,
            &data_model,
        )
        .unwrap();

        let mut param = Parameters::new();
        let mutation = Arc::new(mutation);
        let mut mutation_query = MutationQuery::execute(&mut param, mutation, &conn).unwrap();
        mutation_query.write(&conn).unwrap();

        let mutation = MutationParser::parse(
            r#"
            mutate {
                auth: sys.Room {
                    authorisations: [{
                        name:"admin"
                    }]
                }
            } "#,
            &data_model,
        )
        .unwrap();
        let mut param = Parameters::new();
        let mutation = Arc::new(mutation);
        let mut mutation_query = MutationQuery::execute(&mut param, mutation, &conn).unwrap();
        mutation_query.write(&conn).unwrap();
        let q = &mutation_query.mutate_entities[0];
        let id = q.node_to_mutate.id;

        let mutation = MutationParser::parse(
            r#"
            mutate {
                P1: ns.Person {
                    room_id : $room_id
                    name : "John"
                    parents:  [ {name : "John Mother"} ,{ name:"John Father" pet:{ name:"Kiki" }}]
                    pet: { name:"Truffle"}
                }
                P2: ns.Person {
                    room_id : $room_id
                    name : "Ada"
                    parents:  [ {name : "Ada Mother" pet:{ name:"Lulu" }} ,{ name:"Ada Father" pet:{ name:"Waf" }}]
                }

            } "#,
            &data_model,
        )
        .unwrap();
        let mut param = Parameters::new();
        param.add("room_id", uid_encode(&id)).unwrap();
        let mutation = Arc::new(mutation);
        let mut mutation_query = MutationQuery::execute(&mut param, mutation, &conn).unwrap();
        mutation_query.write(&conn).unwrap();

        let query_parser = QueryParser::parse(
            r#"
            query sample{
                ns.Person (order_by(name asc)) {
                    sys_room {
                        authorisations{
                            name
                        }
                    }
                    name
                    parents (order_by(name asc)) {
                        sys_room {
                            authorisations{
                                name
                            }
                        }
                        name
                    }
                }
            }
        "#,
            &data_model,
        )
        .unwrap();

        let query = PreparedQueries::build(&query_parser).unwrap();

        let param = Parameters::new();
        let mut sql = Query {
            parameters: param,
            parser: Arc::new(query_parser),
            sql_queries: Arc::new(query),
        };
        let result = sql.read(&conn).unwrap();
        let expected = "{\n\"ns.Person\":[{\"sys_room\":{\"authorisations\":[{\"name\":\"admin\"}]},\"name\":\"Ada\",\"parents\":[{\"sys_room\":{\"authorisations\":[{\"name\":\"admin\"}]},\"name\":\"Ada Father\"},{\"sys_room\":{\"authorisations\":[{\"name\":\"admin\"}]},\"name\":\"Ada Mother\"}]},{\"sys_room\":{\"authorisations\":[{\"name\":\"admin\"}]},\"name\":\"John\",\"parents\":[{\"sys_room\":{\"authorisations\":[{\"name\":\"admin\"}]},\"name\":\"John Father\"},{\"sys_room\":{\"authorisations\":[{\"name\":\"admin\"}]},\"name\":\"John Mother\"}]}]\n}";
        assert_eq!(expected, result);

        let query_parser = QueryParser::parse(
            r#"
            query sample{
                ns.Person (order_by(name asc)) {
                    sys_room {
                        authorisations (name="not"){
                            name
                        }
                    }
                    name
                    parents (order_by(name asc)) {
                        sys_room {
                            authorisations{
                                name
                            }
                        }
                        name
                    }
                }
            }
        "#,
            &data_model,
        )
        .unwrap();

        let query = PreparedQueries::build(&query_parser).unwrap();

        let param = Parameters::new();
        let mut sql = Query {
            parameters: param,
            parser: Arc::new(query_parser),
            sql_queries: Arc::new(query),
        };
        let result = sql.read(&conn).unwrap();
        let expected = "{\n\"ns.Person\":[]\n}";
        assert_eq!(expected, result);
    }

    #[test]
    fn query_result() {
        let mut data_model = DataModel::new();
        data_model
            .update(
                "
            ns {
                Person {
                    name : String,
                    comment : String,
                }
            }
        ",
            )
            .unwrap();

        let mutation = MutationParser::parse(
            r#"
            mutate {
                P1: ns.Person { name:"John" comment:"Lorem ipsum sit doler et ames" }
                P2: ns.Person { name:"Alice" comment:"Lorem lorem ipsum " }
                P3: ns.Person { name:"Bob" comment:"A completely different comment" }
            } "#,
            &data_model,
        )
        .unwrap();
        let conn = Connection::open_in_memory().unwrap();
        prepare_connection(&conn).unwrap();

        let mut param = Parameters::new();
        let mutation = Arc::new(mutation);
        let mut mutation_query = MutationQuery::execute(&mut param, mutation, &conn).unwrap();
        mutation_query.write(&conn).unwrap();

        let query_parser = QueryParser::parse(
            r#"
            query sample{
                ns.Person(order_by(name ASC)) {
                    name
                    comment
                }
            }
        "#,
            &data_model,
        )
        .unwrap();

        let query = PreparedQueries::build(&query_parser).unwrap();
        let param = Parameters::new();
        let mut sql = Query {
            parameters: param,
            parser: Arc::new(query_parser),
            sql_queries: Arc::new(query),
        };
        let result = sql.read(&conn).unwrap();

        #[derive(Deserialize)]
        struct Person {
            pub name: String,
            //  pub comment: String,
        }

        let mut query_result = ResultParser::new(&result).unwrap();
        let persons: Vec<Person> = query_result.take_array("ns.Person").unwrap();

        assert_eq!(3, persons.len());
        assert_eq!("Alice", persons[0].name);
        assert_eq!("Bob", persons[1].name);
        assert_eq!("John", persons[2].name);
    }

    #[test]
    fn query_with_null_default() {
        let mut data_model = DataModel::new();
        data_model
            .update(
                "
            ns {
                Person {
                    name : String nullable
                }
            }
        ",
            )
            .unwrap();

        let mutation = MutationParser::parse(
            r#"
            mutate {
                P3: ns.Person { name:"Bob"  }
                P1: ns.Person { }
                P2: ns.Person { name:"Alice"}
            } "#,
            &data_model,
        )
        .unwrap();
        let conn = Connection::open_in_memory().unwrap();
        prepare_connection(&conn).unwrap();

        let mut param = Parameters::new();
        let mutation = Arc::new(mutation);
        let mut mutation_query = MutationQuery::execute(&mut param, mutation, &conn).unwrap();
        mutation_query.write(&conn).unwrap();

        let query_parser = QueryParser::parse(
            r#"
            query sample{
                ns.Person(order_by(name ASC)) {
                    name
                }
            }
        "#,
            &data_model,
        )
        .unwrap();

        let query = PreparedQueries::build(&query_parser).unwrap();
        let param = Parameters::new();
        let mut sql = Query {
            parameters: param,
            parser: Arc::new(query_parser),
            sql_queries: Arc::new(query),
        };
        let result = sql.read(&conn).unwrap();

        #[derive(Deserialize)]
        struct Person {
            pub name: Option<String>,
        }

        let mut query_result = ResultParser::new(&result).unwrap();
        let persons: Vec<Person> = query_result.take_array("ns.Person").unwrap();

        assert_eq!(3, persons.len());
        assert_eq!(None, persons[0].name);
        assert_eq!("Alice", persons[1].name.as_ref().unwrap());
        assert_eq!("Bob", persons[2].name.as_ref().unwrap());

        data_model
            .update(
                r#"
            ns {
                Person {
                    name : String default "anonymous",
                    age : Integer default 10,
                    weight : Float default 12.0,
                    is_nice : Boolean default true
                }
            }
        "#,
            )
            .unwrap();

        let query_parser = QueryParser::parse(
            r#"
            query sample{
                ns.Person(age >= 10, is_nice=true, weight > 2, name="anonymous") {
                    name
                    age
                    weight
                    is_nice
                }
            }
        "#,
            &data_model,
        )
        .unwrap();

        let query = PreparedQueries::build(&query_parser).unwrap();

        let param = Parameters::new();
        let mut sql = Query {
            parameters: param,
            parser: Arc::new(query_parser),
            sql_queries: Arc::new(query),
        };
        let result = sql.read(&conn).unwrap();

        #[derive(Deserialize)]
        struct Person2 {
            pub name: String,
            pub age: i64,
            pub weight: f64,
            pub is_nice: i32,
        }

        let mut query_result = ResultParser::new(&result).unwrap();
        let persons: Vec<Person2> = query_result.take_array("ns.Person").unwrap();

        assert_eq!(1, persons.len());
        assert_eq!("anonymous", persons[0].name);
        assert_eq!(10, persons[0].age);
        assert_eq!(12.0, persons[0].weight);
        assert_eq!(1, persons[0].is_nice);
    }

    #[test]
    fn query_documentation_examples() {
        let mut data_model = DataModel::new();
        data_model
            .update(
                "
           {
                Person {
                    name: String,
                    surname: String nullable,
                    parents:[Person],
                    pet: Pet,
                }

                Pet{
                    name: String
                }
            }
        ",
            )
            .unwrap();

        let mutation = MutationParser::parse(
            r#"
            mutate {
                Person {
                    name : "Doe"
                    surname: "John"
                    parents:  [
                        {
                            name : "Coop"
                            surname: "Alice"
                        }
                        ,{
                            name: "Doe"
                            pet:{ name:"Kiki" }
                        }
                    ]
                    pet: {name:"Truffle"}

                }
            } "#,
            &data_model,
        )
        .unwrap();

        let mut param = Parameters::new();
        let conn = Connection::open_in_memory().unwrap();
        prepare_connection(&conn).unwrap();

        let mutation = Arc::new(mutation);
        let mut mutation_query = MutationQuery::execute(&mut param, mutation, &conn).unwrap();
        mutation_query.write(&conn).unwrap();

        let query_parser = QueryParser::parse(
            r#"
            query {
                result: Person {
                    name
                    surname
                }
            }
        "#,
            &data_model,
        )
        .unwrap();
        let query = PreparedQueries::build(&query_parser).unwrap();

        let param = Parameters::new();
        let mut sql = Query {
            parameters: param,
            parser: Arc::new(query_parser),
            sql_queries: Arc::new(query),
        };
        let _ = sql.read(&conn).unwrap();

        let query_parser = QueryParser::parse(
            r#"
            query {
                persons: Person {
                    name
                    surname
                }

                pets: Pet{
                    name
                }
            }
        "#,
            &data_model,
        )
        .unwrap();
        let query = PreparedQueries::build(&query_parser).unwrap();

        let param = Parameters::new();
        let mut sql = Query {
            parameters: param,
            parser: Arc::new(query_parser),
            sql_queries: Arc::new(query),
        };
        let _ = sql.read(&conn).unwrap();

        let query_parser = QueryParser::parse(
            r#"
            query {
                Person (
                    name="Doe"
                    ) {
                    name
                    surname
                }
            }
        "#,
            &data_model,
        )
        .unwrap();
        let query = PreparedQueries::build(&query_parser).unwrap();

        let param = Parameters::new();
        let mut sql = Query {
            parameters: param,
            parser: Arc::new(query_parser),
            sql_queries: Arc::new(query),
        };
        let _ = sql.read(&conn).unwrap();

        let query_parser = QueryParser::parse(
            r#"
            query {
                Person (
                    surname="John",
                    name="Doe"
                    ) {
                    name
                    surname
                }
            }
        "#,
            &data_model,
        )
        .unwrap();
        let query = PreparedQueries::build(&query_parser).unwrap();

        let param = Parameters::new();
        let mut sql = Query {
            parameters: param,
            parser: Arc::new(query_parser),
            sql_queries: Arc::new(query),
        };
        let _ = sql.read(&conn).unwrap();

        let query_parser = QueryParser::parse(
            r#"
            query {
                Person (
                    surname != null,
                    name="Doe"
                    ) {
                    name
                    surname
                }
            }
        "#,
            &data_model,
        )
        .unwrap();
        let query = PreparedQueries::build(&query_parser).unwrap();

        let param = Parameters::new();
        let mut sql = Query {
            parameters: param,
            parser: Arc::new(query_parser),
            sql_queries: Arc::new(query),
        };
        let _ = sql.read(&conn).unwrap();

        let query_parser = QueryParser::parse(
            r#"
            query {
                result: Person {
                    name
                    surname
                    pet {
                        name
                    }
                }
            }
        "#,
            &data_model,
        )
        .unwrap();
        let query = PreparedQueries::build(&query_parser).unwrap();

        let param = Parameters::new();
        let mut sql = Query {
            parameters: param,
            parser: Arc::new(query_parser),
            sql_queries: Arc::new(query),
        };
        let _ = sql.read(&conn).unwrap();

        let query_parser = QueryParser::parse(
            r#"
            query {
                Person {
                    name
                    surname
                    parents (surname = null) {
                        name
                        pet (name = "Kiki"){
                            name
                        }
                    }
                    pet {
                        name
                    }
                }
            }
        "#,
            &data_model,
        )
        .unwrap();
        let query = PreparedQueries::build(&query_parser).unwrap();

        let param = Parameters::new();
        let mut sql = Query {
            parameters: param,
            parser: Arc::new(query_parser),
            sql_queries: Arc::new(query),
        };
        let _ = sql.read(&conn).unwrap();

        let query_parser = QueryParser::parse(
            r#"
            query {
                Person(
                    nullable (pet)
                ) {
                    name
                    surname
                    pet {
                        name
                    }
                }
            }
        "#,
            &data_model,
        )
        .unwrap();
        let query = PreparedQueries::build(&query_parser).unwrap();

        let param = Parameters::new();
        let mut sql = Query {
            parameters: param,
            parser: Arc::new(query_parser),
            sql_queries: Arc::new(query),
        };
        let _ = sql.read(&conn).unwrap();

        let query_parser = QueryParser::parse(
            r#"
            query {
                Person(
                    nullable (pet),
                    pet = null
                ) {
                    name
                    surname
                    pet {
                        name
                    }
                }
            }
        "#,
            &data_model,
        )
        .unwrap();
        let query = PreparedQueries::build(&query_parser).unwrap();

        let param = Parameters::new();
        let mut sql = Query {
            parameters: param,
            parser: Arc::new(query_parser),
            sql_queries: Arc::new(query),
        };
        let _ = sql.read(&conn).unwrap();

        let query_parser = QueryParser::parse(
            r#"
            query {
                Person(
                    order_by(name desc, surname asc)
                ) {
                    name
                    surname
                }
            }
        "#,
            &data_model,
        )
        .unwrap();
        let query = PreparedQueries::build(&query_parser).unwrap();

        let param = Parameters::new();
        let mut sql = Query {
            parameters: param,
            parser: Arc::new(query_parser),
            sql_queries: Arc::new(query),
        };
        let _ = sql.read(&conn).unwrap();

        let query_parser = QueryParser::parse(
            r#"
            query {
                Person(
                    order_by(name desc, surname asc),
                    first 2
                ) {
                    name
                    surname
                }
            }
        "#,
            &data_model,
        )
        .unwrap();
        let query = PreparedQueries::build(&query_parser).unwrap();

        let param = Parameters::new();
        let mut sql = Query {
            parameters: param,
            parser: Arc::new(query_parser),
            sql_queries: Arc::new(query),
        };
        let _ = sql.read(&conn).unwrap();

        let query_parser = QueryParser::parse(
            r#"
            query {
                Person(
                    order_by(name desc, surname asc),
                    skip 1,
                    first 2
                ) {
                    name
                    surname
                }
            }
        "#,
            &data_model,
        )
        .unwrap();
        let query = PreparedQueries::build(&query_parser).unwrap();

        let param = Parameters::new();
        let mut sql = Query {
            parameters: param,
            parser: Arc::new(query_parser),
            sql_queries: Arc::new(query),
        };
        let _ = sql.read(&conn).unwrap();

        let query_parser = QueryParser::parse(
            r#"
                query {
                    Person(
                        search("lic")
                    ) {
                        name
                        surname
                    }
                }
            "#,
            &data_model,
        )
        .unwrap();
        let query = PreparedQueries::build(&query_parser).unwrap();

        let param = Parameters::new();
        let mut sql = Query {
            parameters: param,
            parser: Arc::new(query_parser),
            sql_queries: Arc::new(query),
        };
        let _ = sql.read(&conn).unwrap();

        let query_parser = QueryParser::parse(
            r#"
                query {
                    Person (
                        nullable(parents)
                    )
                    {
                        name
                        parent_count: parents {
                            total: count()
                        }
                        parents {
                            name
                        }
                    }
                }
            "#,
            &data_model,
        )
        .unwrap();
        let query = PreparedQueries::build(&query_parser).unwrap();

        let param = Parameters::new();
        let mut sql = Query {
            parameters: param,
            parser: Arc::new(query_parser),
            sql_queries: Arc::new(query),
        };
        let result = sql.read(&conn).unwrap();

        println!("{}", result);
    }

    #[test]
    fn query_documentation_json_examples() {
        let mut data_model = DataModel::new();
        data_model
            .update(
                "
                {
                    Article {
                        content: json
                    }
                }
            ",
            )
            .unwrap();

        let mutation = MutationParser::parse(
            r#"
            mutate {
                Article {
                    content : "{
                        \"title\": \"lorem ipsum\",
                        \"content\": \"Rerum earum culpa quis. Corporis unde aliquid.\"
                    }"
                }
            } "#,
            &data_model,
        )
        .unwrap();

        let mut param = Parameters::new();
        let conn = Connection::open_in_memory().unwrap();
        prepare_connection(&conn).unwrap();

        let mutation = Arc::new(mutation);
        let mut mutation_query = MutationQuery::execute(&mut param, mutation, &conn).unwrap();
        mutation_query.write(&conn).unwrap();

        let query_parser = QueryParser::parse(
            "
            query sample{
                Article{
                    title: content->$.title
                }
            }
        ",
            &data_model,
        )
        .unwrap();

        let query = PreparedQueries::build(&query_parser).unwrap();
        let param = Parameters::new();
        let mut sql = Query {
            parameters: param,
            parser: Arc::new(query_parser),
            sql_queries: Arc::new(query),
        };
        let result = sql.read(&conn).unwrap();

        println!("{}", result);
    }
}
