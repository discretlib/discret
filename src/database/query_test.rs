#[cfg(test)]
mod tests {

    use rusqlite::Connection;

    use std::sync::Arc;

    use crate::database::graph_database::Writeable;
    use crate::database::mutation_query::MutationQuery;
    use crate::database::query_language::parameter::ParametersAdd;
    use crate::{
        database::{
            graph_database::prepare_connection,
            query::{Queries, Query},
            query_language::{
                data_model::DataModel, mutation_parser::MutationParser, parameter::Parameters,
                query_parser::QueryParser,
            },
        },
        Ed25519SigningKey, SigningKey,
    };

    #[test]
    fn simple_scalar() {
        let mut data_model = DataModel::new();
        data_model
            .update(
                "
            Person {
                name : String ,
                age : Integer,
                weight : Float,
                is_human : Boolean, 
                some_nullable : String nullable,
            }
        ",
            )
            .unwrap();

        let mutation = MutationParser::parse(
            r#"
            mutation mutmut {
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
        let mutation_query = MutationQuery::build(&param, mutation, &conn).unwrap();

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

        let query = Queries::build(&query_parser).unwrap();
        let param = Parameters::new();
        let sql = Query {
            parameters: param,
            parser: Arc::new(query_parser),
            sql_queries: query,
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

        let query = Queries::build(&query_parser).unwrap();
        let param = Parameters::new();
        let sql = Query {
            parameters: param,
            parser: Arc::new(query_parser),
            sql_queries: query,
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
                "
            Person {
                name : String
            }
        ",
            )
            .unwrap();

        let mutation = MutationParser::parse(
            r#"
            mutation mutmut {
                Person {
                    name : "hello"
                }
            } "#,
            &data_model,
        )
        .unwrap();

        let param = Parameters::new();
        let conn = Connection::open_in_memory().unwrap();
        prepare_connection(&conn).unwrap();

        let mutation = Arc::new(mutation);
        let mut mutation_query = MutationQuery::build(&param, mutation, &conn).unwrap();

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
                    _pub_key
                    _signature
                }
                
            }
        ",
            &data_model,
        )
        .unwrap();

        let query = Queries::build(&query_parser).unwrap();
        let param = Parameters::new();
        let sql = Query {
            parameters: param,
            parser: Arc::new(query_parser),
            sql_queries: query,
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
                _pub_key <="ZXRzZXRzNDMx",
                _pub_key >= "ZXRzZXRzNDMx",
            ){
                    id
                    cdate
                    mdate
                    _entity
                    _json
                    _binary
                    _pub_key
                    _signature
                }
                
            }
        "#,
            &data_model,
        )
        .unwrap();

        let query = Queries::build(&query_parser).unwrap();
        let param = Parameters::new();
        let sql = Query {
            parameters: param,
            parser: Arc::new(query_parser),
            sql_queries: query,
        };

        let _ = sql
            .read(&conn)
            .expect("result changes everytime, just test that it creates a valid query");
    }

    #[test]
    fn entity() {
        let mut data_model = DataModel::new();
        data_model
            .update(
                "
            Person {
                name : String ,
                parents : [Person] nullable,
                pet: Pet nullable,
                siblings : [Person] nullable,
            }

            Pet {
                name : String
            }
        ",
            )
            .unwrap();

        let mutation = MutationParser::parse(
            r#"
            mutation mutmut {
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
        let mutation_query = MutationQuery::build(&param, mutation, &conn).unwrap();

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

        let query = Queries::build(&query_parser).unwrap();
        let param = Parameters::new();
        let sql = Query {
            parameters: param,
            parser: Arc::new(query_parser),
            sql_queries: query,
        };
        println!("{}", sql.sql_queries.sql_queries[0].sql_query);

        let result = sql.read(&conn).unwrap();
        let expected = "{\n\"Person\":[{\"name\":\"John\",\"parents\":[{\"name\":\"World\"}],\"pet\":{\"name\":\"Truffle\"},\"remps_pets\":[{\"name\":\"World\",\"pet\":{\"name\":\"kiki\"}}]}]\n}";
        assert_eq!(expected, result);
    }

    #[test]
    fn order_by_first_next_paging() {
        let conn = Connection::open_in_memory().unwrap();
        prepare_connection(&conn).unwrap();

        let mut data_model = DataModel::new();
        data_model
            .update(
                "
            Person {
                name : String,
                age : Integer,
            }
        ",
            )
            .unwrap();

        let mutation = MutationParser::parse(
            r#"
            mutation mutmut {
                Person {
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

        let mutation_query = MutationQuery::build(&param, mutation.clone(), &conn).unwrap();

        mutation_query.write(&conn).unwrap();

        let mut param = Parameters::new();
        param.add("name", "Silvie".to_string()).unwrap();
        param.add("age", 46).unwrap();

        let mutation_query = MutationQuery::build(&param, mutation.clone(), &conn).unwrap();

        mutation_query.write(&conn).unwrap();

        let mut param = Parameters::new();
        param.add("name", "Kevin".to_string()).unwrap();
        param.add("age", 22).unwrap();

        let mutation_query = MutationQuery::build(&param, mutation.clone(), &conn).unwrap();
        mutation_query.write(&conn).unwrap();

        let mut param = Parameters::new();
        param.add("name", "Sarah".to_string()).unwrap();
        param.add("age", 12).unwrap();

        let mutation_query = MutationQuery::build(&param, mutation.clone(), &conn).unwrap();
        mutation_query.write(&conn).unwrap();

        let mut param = Parameters::new();
        param.add("name", "Leonore".to_string()).unwrap();
        param.add("age", 22).unwrap();

        let mutation_query = MutationQuery::build(&param, mutation.clone(), &conn).unwrap();
        mutation_query.write(&conn).unwrap();

        let query_parser = QueryParser::parse(
            r#"
            query sample{
                Person (
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
        let query = Queries::build(&query_parser).unwrap();

        let sql = Query {
            parameters: Parameters::new(),
            parser: Arc::new(query_parser),
            sql_queries: query,
        };

        let result = sql.read(&conn).unwrap();
        let expected = "{\n\"Person\":[{\"name\":\"John\",\"age\":42},{\"name\":\"Kevin\",\"age\":22},{\"name\":\"Leonore\",\"age\":22}]\n}";
        assert_eq!(expected, result);

        let query_parser = QueryParser::parse(
            r#"
            query sample{
                Person (
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
        let query = Queries::build(&query_parser).unwrap();

        let sql = Query {
            parameters: Parameters::new(),
            parser: Arc::new(query_parser),
            sql_queries: query,
        };
        println!("{}", sql.sql_queries.sql_queries[0].sql_query);
        let result = sql.read(&conn).unwrap();
        let expected = "{\n\"Person\":[{\"name\":\"Sarah\",\"age\":12}]\n}";
        assert_eq!(expected, result);

        let query_parser = QueryParser::parse(
            r#"
            query sample{
                Person (
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
        let query = Queries::build(&query_parser).unwrap();

        let sql = Query {
            parameters: Parameters::new(),
            parser: Arc::new(query_parser),
            sql_queries: query,
        };

        let result = sql.read(&conn).unwrap();
        let expected =
            "{\n\"Person\":[{\"name\":\"Leonore\",\"age\":22},{\"name\":\"Sarah\",\"age\":12}]\n}";
        assert_eq!(expected, result);

        let query_parser = QueryParser::parse(
            r#"
            query sample{
                Person (
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
        let query = Queries::build(&query_parser).unwrap();

        let sql = Query {
            parameters: Parameters::new(),
            parser: Arc::new(query_parser),
            sql_queries: query,
        };
        let result = sql.read(&conn).unwrap();
        let expected =
            "{\n\"Person\":[{\"name\":\"Kevin\",\"age\":22},{\"name\":\"Sarah\",\"age\":12}]\n}";
        assert_eq!(expected, result);

        let query_parser = QueryParser::parse(
            r#"
            query sample{
                Person (
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
        let query = Queries::build(&query_parser).unwrap();

        println!("{}", &query.sql_queries[0].sql_query);

        let sql = Query {
            parameters: Parameters::new(),
            parser: Arc::new(query_parser),
            sql_queries: query,
        };
        let result = sql.read(&conn).unwrap();
        let expected =
            "{\n\"Person\":[{\"name\":\"Silvie\",\"age\":46},{\"name\":\"John\",\"age\":42}]\n}";
        assert_eq!(expected, result);

        //println!("{:#?}", result.as_str().unwrap());
        // println!("{}", result.as_str().unwrap());
    }

    #[test]
    fn filter() {
        let mut data_model = DataModel::new();
        data_model
            .update(
                "
            Person {
                name : String ,
                age : Integer,
                weight : Float,
                is_human : Boolean, 
            }
        ",
            )
            .unwrap();

        let mutation = MutationParser::parse(
            r#"
            mutation mutmut {
                Person {
                    name : "John"
                    age: 23
                    weight: 10
                    is_human : true
                }
                P1: Person {
                    name : "Doe"
                    age: 32
                    weight: 12
                    is_human : true
                }
                P2: Person {
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

        let param = Parameters::new();
        let mutation = Arc::new(mutation);
        let mutation_query = MutationQuery::build(&param, mutation, &conn).unwrap();

        mutation_query.write(&conn).unwrap();

        let query_parser = QueryParser::parse(
            r#"
            query sample{
                Person (name = "Jean", age < 100, weight >=100, is_human = false){
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

        let query = Queries::build(&query_parser).unwrap();
        let param = Parameters::new();
        let sql = Query {
            parameters: param,
            parser: Arc::new(query_parser),
            sql_queries: query,
        };
        let result = sql.read(&conn).unwrap();

        let expected =
            "{\n\"Person\":[{\"name\":\"Jean\",\"age\":53,\"weight\":100.0,\"is_human\":false}]\n}";
        assert_eq!(expected, result);

        let query_parser = QueryParser::parse(
            r#"
            query sample{
                Person (name = $name, age < $age, weight >= $we, is_human = $hum){
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

        let query = Queries::build(&query_parser).unwrap();
        let mut param = Parameters::new();
        param.add("name", "Jean".to_string()).unwrap();
        param.add("age", 100).unwrap();
        param.add("we", 100.0).unwrap();
        param.add("hum", false).unwrap();

        let sql = Query {
            parameters: param,
            parser: Arc::new(query_parser),
            sql_queries: query,
        };
        let result = sql.read(&conn).unwrap();

        let expected =
            "{\n\"Person\":[{\"name\":\"Jean\",\"age\":53,\"weight\":100.0,\"is_human\":false}]\n}";
        assert_eq!(expected, result);
        println!("{:#?}", result);
    }

    #[test]
    //test variable name reuse and internalised string
    fn positional_param() {
        let mut data_model = DataModel::new();
        data_model
            .update(
                "
            Person {
                name : String ,
                surname : String,
                pseudo : String,
                is_human : Boolean, 
            }
        ",
            )
            .unwrap();

        let mutation = MutationParser::parse(
            r#"
            mutation mutmut {
                Person {
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

        let param = Parameters::new();
        let mutation = Arc::new(mutation);
        let mutation_query = MutationQuery::build(&param, mutation, &conn).unwrap();
        mutation_query.write(&conn).unwrap();

        let query_parser = QueryParser::parse(
            r#"
            query sample{
                Person (name = $name, surname = "John", surname = $name, is_human = true){
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

        let query = Queries::build(&query_parser).unwrap();
        let mut param = Parameters::new();
        param.add("name", "John".to_string()).unwrap();
        let sql = Query {
            parameters: param,
            parser: Arc::new(query_parser),
            sql_queries: query,
        };
        //println!("{}", sql.sql_queries.sql_queries[0].sql_query);
        let result = sql.read(&conn).unwrap();

        let expected =
             "{\n\"Person\":[{\"name\":\"John\",\"surname\":\"John\",\"pseudo\":\"John\",\"is_human\":true}]\n}";
        assert_eq!(expected, result);

        //println!("{:#?}", result.as_str().unwrap());
    }

    #[test]
    fn aggregate() {
        let mut data_model = DataModel::new();
        data_model
            .update(
                "
            Person {
                age : Integer,
                weight : Float,
                nat: String, 
            }
        ",
            )
            .unwrap();

        let mutation = MutationParser::parse(
            r#"
            mutation mutmut {
                P1: Person { age:24 weight:45 nat:"us" }
                P2: Person { age:12 weight:23 nat:"us" }
                P3: Person { age:45 weight:86 nat:"fr" }
                P4: Person { age:34 weight:43 nat:"fr" }
                P5: Person { age:54 weight:70 nat:"sa" }
                P6: Person { age:67 weight:85 nat:"sa" }
                P7: Person { age:72 weight:65 nat:"sa" }
                P8: Person { age:24 weight:95 nat:"en" }
                P9: Person { age:1 weight:52 nat:"en" }
                P10: Person { age:45 weight:65 nat:"en" }
                P11: Person { age:24 weight:75 nat:"en" }
            } "#,
            &data_model,
        )
        .unwrap();
        let conn = Connection::open_in_memory().unwrap();
        prepare_connection(&conn).unwrap();

        let param = Parameters::new();
        let mutation = Arc::new(mutation);
        let mutation_query = MutationQuery::build(&param, mutation, &conn).unwrap();
        mutation_query.write(&conn).unwrap();

        let query_parser = QueryParser::parse(
            r#"
            query sample{
                Person (order_by(avg asc, count asc, max asc,min asc,sum asc)) {
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

        let query = Queries::build(&query_parser).unwrap();
        let param = Parameters::new();
        let sql = Query {
            parameters: param,
            parser: Arc::new(query_parser),
            sql_queries: query,
        };
        let result = sql.read(&conn).unwrap();

        let expected =
        "{\n\"Person\":[{\"nat\":\"us\",\"avg\":34.0,\"count\":2,\"max\":45.0,\"min\":23.0,\"sum\":68.0},{\"nat\":\"fr\",\"avg\":64.5,\"count\":2,\"max\":86.0,\"min\":43.0,\"sum\":129.0},{\"nat\":\"en\",\"avg\":71.75,\"count\":4,\"max\":95.0,\"min\":52.0,\"sum\":287.0},{\"nat\":\"sa\",\"avg\":73.3333333333333,\"count\":3,\"max\":85.0,\"min\":65.0,\"sum\":220.0}]\n}";
        assert_eq!(expected, result);

        let query_parser = QueryParser::parse(
            r#"
            query sample{
                Person (order_by(avg asc, count asc, max asc,min asc,sum asc)) {
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

        let query = Queries::build(&query_parser).unwrap();
        let param = Parameters::new();
        let sql = Query {
            parameters: param,
            parser: Arc::new(query_parser),
            sql_queries: query,
        };
        let _result = sql.read(&conn).unwrap();

        let query_parser = QueryParser::parse(
            r#"
            query sample{
                Person (
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

        let query = Queries::build(&query_parser).unwrap();
        let param = Parameters::new();
        let sql = Query {
            parameters: param,
            parser: Arc::new(query_parser),
            sql_queries: query,
        };
        //println!("{}", sql.sql_queries.sql_queries[0].sql_query);
        let result = sql.read(&conn).unwrap();

        let expected ="{\n\"Person\":[{\"nat\":\"sa\",\"avg\":73.3333333333333,\"count\":3,\"max\":85.0,\"min\":65.0,\"sum\":220.0}]\n}";
        assert_eq!(expected, result);
        // println!("{:#?}", _result.as_str().unwrap());
        //println!("{}", _result.as_str().unwrap());
    }

    #[test]
    fn search() {
        let mut data_model = DataModel::new();
        data_model
            .update(
                "
            Person {
                name : String,
                comment : String,
            }
        ",
            )
            .unwrap();

        let mutation = MutationParser::parse(
            r#"
            mutation mutmut {
                P1: Person { name:"John" comment:"Lorem ipsum sit doler et ames" }
                P2: Person { name:"Alice" comment:"Lorem lorem ipsum " }
                P3: Person { name:"Bob" comment:"A completely different comment" }
            } "#,
            &data_model,
        )
        .unwrap();
        let conn = Connection::open_in_memory().unwrap();
        prepare_connection(&conn).unwrap();

        let param = Parameters::new();
        let mutation = Arc::new(mutation);
        let mutation_query = MutationQuery::build(&param, mutation, &conn).unwrap();
        mutation_query.write(&conn).unwrap();

        let query_parser = QueryParser::parse(
            r#"
            query sample{
                Person(search("ames")) {
                    name
                    comment
                }
            }
        "#,
            &data_model,
        )
        .unwrap();

        let query = Queries::build(&query_parser).unwrap();
        let param = Parameters::new();
        let sql = Query {
            parameters: param,
            parser: Arc::new(query_parser),
            sql_queries: query,
        };
        //println!("{}", sql.sql_queries.sql_queries[0].sql_query);
        let result = sql.read(&conn).unwrap();

        let expected =
            "{\n\"Person\":[{\"name\":\"John\",\"comment\":\"Lorem ipsum sit doler et ames\"}]\n}";
        assert_eq!(expected, result);
        // println!("{:#?}", result.as_str().unwrap());
        //println!("{}", result.as_str().unwrap());
    }

    #[test]
    fn default_value() {
        let mut data_model = DataModel::new();

        data_model
            .update(
                r#"
            Person {
                name : String,
                def : String default "Lorem ipsum", 
            }
        "#,
            )
            .unwrap();

        let mutation = MutationParser::parse(
            r#"
            mutation mutmut {
                P2: Person { name:"Alice"  }
                P3: Person { name:"Bob" def:"A completely different" }
            } "#,
            &data_model,
        )
        .unwrap();
        let conn = Connection::open_in_memory().unwrap();
        prepare_connection(&conn).unwrap();

        let param = Parameters::new();
        let mutation = Arc::new(mutation);
        let mutation_query = MutationQuery::build(&param, mutation, &conn).unwrap();
        mutation_query.write(&conn).unwrap();

        let query_parser = QueryParser::parse(
            r#"
            query sample{
                Person() {
                    name
                    def
                }
            }
        "#,
            &data_model,
        )
        .unwrap();

        let query = Queries::build(&query_parser).unwrap();
        let param = Parameters::new();
        let sql = Query {
            parameters: param,
            parser: Arc::new(query_parser),
            sql_queries: query,
        };
        let result = sql.read(&conn).unwrap();

        let expected =
            "{\n\"Person\":[{\"name\":\"Alice\",\"def\":\"Lorem ipsum\"},{\"name\":\"Bob\",\"def\":\"A completely different\"}]\n}";
        assert_eq!(expected, result);

        data_model
            .update(
                r#"
            Person {
                name : String,
                def : String default "Lorem ipsum", 
                newdef : String default "sit met", 
            }
        "#,
            )
            .unwrap();

        //old rows  will return the default value of the 'newdef' field
        let query_parser = QueryParser::parse(
            r#"
                query sample{
                    Person() {
                        name
                        def
                        newdef
                    }
                }
            "#,
            &data_model,
        )
        .unwrap();

        let query = Queries::build(&query_parser).unwrap();
        let param = Parameters::new();
        let sql = Query {
            parameters: param,
            parser: Arc::new(query_parser),
            sql_queries: query,
        };
        let result = sql.read(&conn).unwrap();
        let expected =
        "{\n\"Person\":[{\"name\":\"Alice\",\"def\":\"Lorem ipsum\",\"newdef\":\"sit met\"},{\"name\":\"Bob\",\"def\":\"A completely different\",\"newdef\":\"sit met\"}]\n}";
        assert_eq!(expected, result);
    }

    #[test]
    fn json() {
        let mut data_model = DataModel::new();

        data_model
            .update(
                r#"
            Person {
                name : String,
                data : Json, 
            }
        "#,
            )
            .unwrap();

        let mutation = MutationParser::parse(
            r#"
            mutation mutmut {
                P2: Person { name:"Alice" data:$data }
                P3: Person { name:"Bob" data:"[1,2,3,4]" }
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
        let mutation_query = MutationQuery::build(&param, mutation, &conn).unwrap();

        mutation_query.write(&conn).unwrap();

        let query_parser = QueryParser::parse(
            "
            query sample{
                Person {
                    name
                    data
                    array: data->$.val
                }
            }
        ",
            &data_model,
        )
        .unwrap();

        let query = Queries::build(&query_parser).unwrap();
        let param = Parameters::new();
        let sql = Query {
            parameters: param,
            parser: Arc::new(query_parser),
            sql_queries: query,
        };
        let result = sql.read(&conn).unwrap();
        let expected = 
        "{\n\"Person\":[{\"name\":\"Alice\",\"data\":{\"val\":\"hello json\"},\"array\":\"hello json\"},{\"name\":\"Bob\",\"data\":[1,2,3,4],\"array\":null}]\n}";
        assert_eq!(expected, result);
      
        let query_parser = QueryParser::parse(
            "
            query sample{
                Person {
                    name
                    data
                    array: data->1
                }
            }
        ",
            &data_model,
        )
        .unwrap();

        let query = Queries::build(&query_parser).unwrap();
        let param = Parameters::new();
        let sql = Query {
            parameters: param,
            parser: Arc::new(query_parser),
            sql_queries: query,
        };
        let result = sql.read(&conn).unwrap();

        let expected = 
        "{\n\"Person\":[{\"name\":\"Alice\",\"data\":{\"val\":\"hello json\"},\"array\":null},{\"name\":\"Bob\",\"data\":[1,2,3,4],\"array\":2}]\n}";
        assert_eq!(expected, result);
   

        let query_parser = QueryParser::parse(
            "
            query sample{
                Person (data->1 = 2, order_by(array asc)) {
                    name
                    data
                    array: data->1
                }
            }
        ",
            &data_model,
        )
        .unwrap();

        let query = Queries::build(&query_parser).unwrap();
        let param = Parameters::new();
        let sql = Query {
            parameters: param,
            parser: Arc::new(query_parser),
            sql_queries: query,
        };
        let result = sql.read(&conn).unwrap();

        let expected = 
        "{\n\"Person\":[{\"name\":\"Bob\",\"data\":[1,2,3,4],\"array\":2}]\n}";
        assert_eq!(expected, result);

        let query_parser = QueryParser::parse(
            r#"
            query sample{
                Person (data->$.val = "hello json", order_by(array asc)) {
                    name
                    data
                    array: data->$.val
                }
            }
        "#,
            &data_model,
        )
        .unwrap();

        let query = Queries::build(&query_parser).unwrap();
        let param = Parameters::new();
        let sql = Query {
            parameters: param,
            parser: Arc::new(query_parser),
            sql_queries: query,
        };
        //println!("{}", sql.sql_queries.sql_queries[0].sql_query);
        let result = sql.read(&conn).unwrap();

        let expected = 
        "{\n\"Person\":[{\"name\":\"Alice\",\"data\":{\"val\":\"hello json\"},\"array\":\"hello json\"}]\n}";
        assert_eq!(expected, result);
        // println!("{}", result);
        // println!("{:#?}", result);

    }
}
