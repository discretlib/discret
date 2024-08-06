#[cfg(test)]
mod tests {

    use std::{fs, path::PathBuf};

    use serde::Deserialize;

    use crate::{
        configuration::Configuration,
        database::{
            graph_database::GraphDatabaseService,
            query_language::parameter::{Parameters, ParametersAdd},
        },
        date_utils::now,
        event_service::EventService,
        security::{base64_encode, random32, uid_decode},
        ResultParser,
    };

    const DATA_PATH: &str = "test_data/database/authorisation_service_test/";
    fn init_database_path() {
        let path: PathBuf = DATA_PATH.into();
        fs::create_dir_all(&path).unwrap();
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn room_creation() {
        init_database_path();
        let data_model = "{Person{ name:String }}";
        let secret = random32();
        let path: PathBuf = DATA_PATH.into();
        let (app, verifying_key, _) = GraphDatabaseService::start(
            "authorisation app",
            data_model,
            &secret,
            &random32(),
            path,
            &Configuration::default(),
            EventService::new(),
        )
        .await
        .unwrap();

        let user_id = base64_encode(&verifying_key);

        let mut param = Parameters::default();
        param.add("user_id", user_id).unwrap();

        let _room = app
            .mutate_raw(
                r#"mutate mut {
                    sys.Room{
                        admin: [{
                            verif_key:$user_id
                        }]

                        authorisations:[{
                            name:"what"
                            rights:[{
                                entity:"Person"
                                mutate_self:true
                                mutate_all:true
                            }]
                        }]
                    }
                }"#,
                Some(param),
            )
            .await
            .unwrap();

        let result = app
            .query(
                "query q{
                    sys.Room{
                        admin{
                            enabled
                        }
                        authorisations{
                            name 
                            rights{
                                entity
                                mutate_self
                                mutate_all
                            }
                        }
                    }
                }",
                None,
            )
            .await
            .unwrap();
        let expected = "{\n\"sys.Room\":[{\"admin\":[{\"enabled\":true}],\"authorisations\":[{\"name\":\"what\",\"rights\":[{\"entity\":\"Person\",\"mutate_self\":true,\"mutate_all\":true}]}]}]\n}";
        assert_eq!(result, expected);
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn mutate_with_room_propagation() {
        init_database_path();
        let data_model = "
        ns {
            Person{ 
                name:String, 
                pets:[ns.Pet]
            }   

            Pet{
                name:String,
            }
        }
        ";

        let secret = random32();
        let path: PathBuf = DATA_PATH.into();
        let (app, verifying_key, _) = GraphDatabaseService::start(
            "authorisation app",
            data_model,
            &secret,
            &random32(),
            path,
            &Configuration::default(),
            EventService::new(),
        )
        .await
        .unwrap();

        let user_id = base64_encode(&verifying_key);

        let mut param = Parameters::default();
        param.add("user_id", user_id.clone()).unwrap();

        let room = app
            .mutate_raw(
                r#"mutate mut {
                    sys.Room{
                        admin: [{
                            verif_key:$user_id
                        }]
                        authorisations:[{
                            name:"admin"
                            rights:[{
                                entity:"ns.Person"
                                mutate_self:true
                                mutate_all:true
                            }]
                        }]
                    }

                }"#,
                Some(param),
            )
            .await
            .unwrap();

        let room_insert = &room.mutate_entities[0];
        let room_id = base64_encode(&room_insert.node_to_mutate.id);

        let authorisation_insert = &room_insert.sub_nodes.get("authorisations").unwrap()[0];
        let _auth_id = base64_encode(&authorisation_insert.node_to_mutate.id);

        let mut param = Parameters::default();
        param.add("room_id", room_id.clone()).unwrap();

        app.mutate_raw(
            r#"mutate {
                ns.Person{
                    room_id: $room_id
                    name: "me"
                }
            }"#,
            Some(param),
        )
        .await
        .expect("Person has the necessary rights");

        let mut param = Parameters::default();
        param.add("room_id", room_id.clone()).unwrap();

        app.mutate_raw(
            r#"mutate mut {
                ns.Pet{
                    room_id: $room_id
                    name: "kiki"
                }
            }"#,
            Some(param),
        )
        .await
        .expect_err("there is no authorisation to insert pets");

        let mut param = Parameters::default();
        param.add("room_id", room_id.clone()).unwrap();
        app.mutate_raw(
            r#"mutate mut {
                ns.Person{
                    room_id: $room_id
                    name: "another me"
                    pets:[{name:"kiki"}]
                }
            }"#,
            Some(param),
        )
        .await
        .expect_err("Room check is propagated to sub entities");

        let mut param = Parameters::default();
        param.add("user_id", user_id.clone()).unwrap();
        let room = app
            .mutate_raw(
                r#"mutate {
                sys.Room{
                    admin: [{
                        verif_key:$user_id
                    }]
                    authorisations:[{
                        name:"admin"
                        rights:[{
                            entity:"ns.Pet"
                            mutate_self:true
                            mutate_all:true
                        }]
                    }]
                }

            }"#,
                Some(param),
            )
            .await
            .unwrap();

        let room_insert = &room.mutate_entities[0];
        let pet_room_id = base64_encode(&room_insert.node_to_mutate.id);

        let mut param = Parameters::default();
        param.add("pet_room_id", pet_room_id.clone()).unwrap();
        app.mutate_raw(
            r#"mutate mut {
                ns.Pet{
                    room_id: $pet_room_id
                    name: "kiki"
                }
            }"#,
            Some(param),
        )
        .await
        .expect("room_id2 can insert pets");

        let mut param = Parameters::default();
        param.add("room_id", room_id.clone()).unwrap();
        param.add("pet_room_id", pet_room_id.clone()).unwrap();
        app.mutate_raw(
            r#"mutate mut {
                ns.Person{
                    room_id: $room_id
                    name: "another me"
                    pets:[{
                        room_id: $pet_room_id
                        name:"kiki"
                    }]
                }
            }"#,
            Some(param),
        )
        .await
        .expect("sub entities also supports room");

        let result = app
            .query(
                "query q{
                    ns.Person(order_by(name asc)){
                        name
                        pets{
                            name
                        }
                    }
                }",
                None,
            )
            .await
            .unwrap();

        let expected =
            "{\n\"ns.Person\":[{\"name\":\"another me\",\"pets\":[{\"name\":\"kiki\"}]}]\n}";
        assert_eq!(result, expected);
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn authorisation_entities_error() {
        init_database_path();
        let data_model = "{Person{name:String,}}";
        let secret = random32();
        let path: PathBuf = DATA_PATH.into();
        let (app, verifying_key, _) = GraphDatabaseService::start(
            "authorisation app",
            data_model,
            &secret,
            &random32(),
            path,
            &Configuration::default(),
            EventService::new(),
        )
        .await
        .unwrap();

        let user_id = base64_encode(&verifying_key);

        let mut param = Parameters::default();
        param.add("user_id", user_id.clone()).unwrap();

        app.mutate_raw(
            r#"mutate mut {
                sys.Authorisation{
                    name:"admin" 
                    rights:[{
                        entity:"Person"
                        mutate_self:true
                        mutate_all:true
                    }]
                    users: [{
                        verif_key:$user_id
                    }]
                }
            }"#,
            Some(param),
        )
        .await
        .expect_err("sys.Authorisation cannot be mutated outside of a room context");

        app.mutate_raw(
            r#"mutate mut {
                sys.EntityRight {
                    entity:"Person"
                    mutate_self:true
                    mutate_all:true
                }
            }"#,
            None,
        )
        .await
        .expect_err("sys.EntityRight cannot be mutated outside of a room context");

        app.mutate_raw(
            r#"mutate mut {
                sys.UserAuth {
                    verifying_key:"cAH9ZO7FMgNhdaEpVLQbmQMb8gI-92d-b6wtTQbSLsw"
                }
            }"#,
            None,
        )
        .await
        .expect_err("sys.UserAuth cannot be mutated outside of a room context");
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn room_update_rights() {
        init_database_path();
        let data_model = "
        {
            Person{ 
                name:String, 
                pets:[Pet]
            }   

            Pet{
                name:String,
            }
        }
        ";

        let secret = random32();
        let path: PathBuf = DATA_PATH.into();
        let (app, verifying_key, _) = GraphDatabaseService::start(
            "authorisation app",
            data_model,
            &secret,
            &random32(),
            path,
            &Configuration::default(),
            EventService::new(),
        )
        .await
        .unwrap();

        let user_id = base64_encode(&verifying_key);

        let mut param = Parameters::default();
        param.add("user_id", user_id.clone()).unwrap();

        let room = app
            .mutate_raw(
                r#"mutate mut {
                    sys.Room{
                        admin: [{
                            verif_key:$user_id
                        }]
                        authorisations:[{
                            name:"admin"
                            rights:[{
                                entity:"Person"
                                mutate_self:true
                                mutate_all:true
                            }]
                        }]
                    }

                }"#,
                Some(param),
            )
            .await
            .unwrap();

        let room_insert = &room.mutate_entities[0];
        let room_id = base64_encode(&room_insert.node_to_mutate.id);

        let authorisation_insert = &room_insert.sub_nodes.get("authorisations").unwrap()[0];
        let auth_id = base64_encode(&authorisation_insert.node_to_mutate.id);

        let mut param = Parameters::default();
        param.add("room_id", room_id.clone()).unwrap();
        app.mutate_raw(
            r#"mutate mut {
                Person{
                    room_id: $room_id
                    name: "me"
                }
            }"#,
            Some(param),
        )
        .await
        .expect("can insert");

        let mut param = Parameters::default();
        param.add("room_id", room_id.clone()).unwrap();
        param.add("auth_id", auth_id.clone()).unwrap();
        app.mutate_raw(
            r#"mutate mut {
                sys.Room{
                    id:$room_id
                    authorisations:[{
                        id:$auth_id
                        rights:[{
                            entity:"Person"
                            mutate_self:false
                            mutate_all:false
                        }]
                    }]
                }
            }"#,
            Some(param),
        )
        .await
        .expect("remove all rights");

        let mut param = Parameters::default();
        param.add("room_id", room_id.clone()).unwrap();
        app.mutate_raw(
            r#"mutate mut {
                Person{
                    room_id: $room_id
                    name: "me"
                }
            }"#,
            Some(param),
        )
        .await
        .expect_err("authorisation to insert has been removed");

        let result = app
            .query(
                "query q{
                    sys.Room{
                        authorisations{
                            name  
                            rights (order_by(mdate desc)){
                                entity
                                mutate_self
                                mutate_all
                            }
                        }
                    }
                }",
                None,
            )
            .await
            .unwrap();
        let expected =  "{\n\"sys.Room\":[{\"authorisations\":[{\"name\":\"admin\",\"rights\":[{\"entity\":\"Person\",\"mutate_self\":false,\"mutate_all\":false},{\"entity\":\"Person\",\"mutate_self\":true,\"mutate_all\":true}]}]}]\n}";
        assert_eq!(result, expected);
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn room_update_user() {
        init_database_path();
        let data_model = "{Person{ name:String }} ";

        let secret = random32();
        let path: PathBuf = DATA_PATH.into();
        let (app, verifying_key, _) = GraphDatabaseService::start(
            "authorisation app",
            data_model,
            &secret,
            &random32(),
            path,
            &Configuration::default(),
            EventService::new(),
        )
        .await
        .unwrap();

        let user_id = base64_encode(&verifying_key);

        let mut param = Parameters::default();
        param.add("user_id", user_id.clone()).unwrap();

        let room = app
            .mutate_raw(
                r#"mutate mut {
                    sys.Room{
                        admin: [{
                            verif_key:$user_id
                        }]
                        authorisations:[{
                            name:"admin"
                        }]
                    }
                }"#,
                Some(param),
            )
            .await
            .unwrap();
        let room_insert = &room.mutate_entities[0];
        let room_id = base64_encode(&room_insert.node_to_mutate.id);

        let authorisation_insert = &room_insert.sub_nodes.get("authorisations").unwrap()[0];
        let auth_id = base64_encode(&authorisation_insert.node_to_mutate.id);

        let mut param = Parameters::default();
        param.add("room_id", room_id.clone()).unwrap();
        param.add("user_id", user_id.clone()).unwrap();
        app.mutate_raw(
            r#"mutate mut {
                sys.Room{
                    id:$room_id
                    admin: [{
                        verif_key:$user_id
                        enabled:false
                    }]
                }
            }"#,
            Some(param),
        )
        .await
        .expect_err("cannot disable itself from admin");

        let mut param = Parameters::default();
        param.add("room_id", room_id.clone()).unwrap();
        param.add("auth_id", auth_id.clone()).unwrap();
        param.add("user_id", user_id.clone()).unwrap();

        let mut param = Parameters::default();
        param.add("room_id", room_id.clone()).unwrap();
        param.add("auth_id", auth_id.clone()).unwrap();
        app.mutate_raw(
            r#"mutate mut {
                sys.Room{
                    id:$room_id
                    authorisations:[{
                        id:$auth_id
                        users: [{
                            verif_key:"cAH9ZO7FMgNhdaEpVLQbmQMb8gI-92d-b6wtTQbSLsw"
                        }]
                    }]
                }
            }"#,
            Some(param),
        )
        .await
        .expect("can add a new user");

        let mut param = Parameters::default();
        param.add("room_id", room_id.clone()).unwrap();
        param.add("auth_id", auth_id.clone()).unwrap();

        app.mutate_raw(
            r#"mutate mut {
                sys.Room{
                    id:$room_id
                    authorisations:[{
                        id:$auth_id
                        users: [{
                            verif_key:"cAH9ZO7FMgNhdaEpVLQbmQMb8gI-92d-b6wtTQbSLsw"
                            enabled:false
                        }]
                    }]
                }
            }"#,
            Some(param),
        )
        .await
        .expect("can disable another user");
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn room_load() {
        init_database_path();
        let data_model = "
        {
            Person{ name:String } 
            Pet{ name:String }
        }";

        let secret = random32();
        let path: PathBuf = DATA_PATH.into();

        //open a database, creates two rooms and close it
        let ids = {
            let (app, verifying_key, _) = GraphDatabaseService::start(
                "authorisation app",
                data_model,
                &secret,
                &random32(),
                path.clone(),
                &Configuration::default(),
                EventService::new(),
            )
            .await
            .unwrap();

            let user_id = base64_encode(&verifying_key);

            let mut param = Parameters::default();
            param.add("user_id", user_id.clone()).unwrap();
            let room = app
                .mutate_raw(
                    r#"
                mutate {
                    sys.Room{
                        admin: [{
                            verif_key:$user_id
                        }]
                        authorisations:[{
                            name:"admin"
                            rights:[{
                                entity:"Person"
                                mutate_self:true
                                mutate_all:true
                            }]
                        }]
                    }
                }"#,
                    Some(param),
                )
                .await
                .unwrap();

            let room_insert = &room.mutate_entities[0];
            let room_person_id = base64_encode(&room_insert.node_to_mutate.id);

            let mut param = Parameters::default();
            param.add("user_id", user_id.clone()).unwrap();
            let room = app
                .mutate_raw(
                    r#"
                mutate mut {
                    sys.Room{
                        admin: [{
                            verif_key:$user_id
                        }]
                        authorisations:[{
                            name:"admin"
                            rights:[{
                                entity:"Pet"
                                mutate_self:true
                                mutate_all:true
                            }]
                        }]
                    }
                }"#,
                    Some(param),
                )
                .await
                .unwrap();

            let room_insert = &room.mutate_entities[0];
            let room_pet_id = base64_encode(&room_insert.node_to_mutate.id);

            (room_person_id, room_pet_id)
        };

        let (app, _, _) = GraphDatabaseService::start(
            "authorisation app",
            data_model,
            &secret,
            &random32(),
            path,
            &&Configuration::default(),
            EventService::new(),
        )
        .await
        .unwrap();

        let mut param = Parameters::default();
        param.add("room_id", ids.0.clone()).unwrap();
        app.mutate_raw(
            r#"mutate mut {
                    Person{
                        room_id: $room_id
                        name: "me"
                    }

                }"#,
            Some(param),
        )
        .await
        .unwrap();

        let mut param = Parameters::default();
        param.add("room_id", ids.1.clone()).unwrap();
        app.mutate_raw(
            r#"mutate mut {
                Person{
                    room_id: $room_id
                    name: "me"
                }
            }"#,
            Some(param),
        )
        .await
        .expect_err("cannot insert a Person in the second room");

        let mut param = Parameters::default();
        param.add("room_id", ids.0.clone()).unwrap();
        app.mutate_raw(
            r#"mutate mut {
                Pet{
                    room_id: $room_id
                    name: "me"
                }
            }"#,
            Some(param),
        )
        .await
        .expect_err("cannot insert a Pet in the first room");

        let mut param = Parameters::default();
        param.add("room_id", ids.1.clone()).unwrap();
        app.mutate_raw(
            r#"mutate {
                Pet{
                    room_id: $room_id
                    name: "me"
                }
            }"#,
            Some(param),
        )
        .await
        .expect("can insert a Pet in the second room");
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn deletion_auth() {
        init_database_path();
        let data_model = "{
            Person{ 
                name:String, 
                parents:[Person]
            }   
        }";

        let secret = random32();
        let path: PathBuf = DATA_PATH.into();
        let (app, verifying_key, _) = GraphDatabaseService::start(
            "authorisation app",
            data_model,
            &secret,
            &random32(),
            path,
            &Configuration::default(),
            EventService::new(),
        )
        .await
        .unwrap();

        let user_id = base64_encode(&verifying_key);

        let mut param = Parameters::default();
        param.add("user_id", user_id.clone()).unwrap();

        let room = app
            .mutate_raw(
                r#"mutate mut {
                    sys.Room{
                        admin: [{
                            verif_key:$user_id
                        }]

                        authorisations:[{
                            name:"admin"
                            rights:[{
                                entity:"Person"
                                mutate_self:true
                                mutate_all:true
                            }]       
                        }]
                    }
                }"#,
                Some(param),
            )
            .await
            .unwrap();

        let room_insert = &room.mutate_entities[0];
        let room_id = base64_encode(&room_insert.node_to_mutate.id);

        let authorisation_insert = &room_insert.sub_nodes.get("authorisations").unwrap()[0];
        let auth_id = base64_encode(&authorisation_insert.node_to_mutate.id);

        let mut param = Parameters::default();
        param.add("room_id", room_id.clone()).unwrap();

        let mutat = app
            .mutate_raw(
                r#"mutate mut {
                P1: Person{
                    room_id: $room_id
                    name: "me"
                    parents:[{name:"father"},{name:"mother"}]
                }
                P2: Person{
                    room_id: $room_id
                    name: "another me"
                }
            }"#,
                Some(param),
            )
            .await
            .expect("can insert");

        let ent = &mutat.mutate_entities[0];
        assert_eq!("P1", ent.name);
        let id1 = base64_encode(&ent.node_to_mutate.id);
        let parents = ent.sub_nodes.get("parents").unwrap();

        let father_id = base64_encode(&parents[0].node_to_mutate.id);
        let mother_id = base64_encode(&parents[1].node_to_mutate.id);

        let ent = &mutat.mutate_entities[1];
        assert_eq!("P2", ent.name);
        let id2 = base64_encode(&ent.node_to_mutate.id);

        let mut param = Parameters::default();
        param.add("id", id2).unwrap();

        app.delete(
            "delete delete_person {
            Person { $id  }
        }",
            Some(param),
        )
        .await
        .unwrap();

        let result = app
            .query(
                "query q{
               Person(order_by(name asc)){
                    name
               }
            }",
                None,
            )
            .await
            .unwrap();
        let expected =
            "{\n\"Person\":[{\"name\":\"father\"},{\"name\":\"me\"},{\"name\":\"mother\"}]\n}";
        assert_eq!(result, expected);

        let mut param = Parameters::default();
        param.add("id", id1.clone()).unwrap();
        param.add("father_id", father_id).unwrap();
        app.delete(
            "delete delete_person {
            Person { 
                $id
                parents[$father_id]
            }
        }",
            Some(param),
        )
        .await
        .unwrap();

        let result = app
            .query(
                "query q{
           Person(order_by(name asc)){
                name
                parents{name}
           }
        }",
                None,
            )
            .await
            .unwrap();

        let expected = "{\n\"Person\":[{\"name\":\"me\",\"parents\":[{\"name\":\"mother\"}]}]\n}";
        assert_eq!(result, expected);

        let mut param = Parameters::default();
        param.add("id", room_id.clone()).unwrap();
        param.add("auth_id", auth_id).unwrap();
        app.mutate_raw(
            r#"mutate mut {
                sys.Room{
                    id:$id
                    authorisations:[{
                        id:$auth_id
                        rights:[{
                            entity:"Person"
                            mutate_self:false
                            mutate_all:false
                        }]
                    }]
                }
            }"#,
            Some(param),
        )
        .await
        .unwrap();

        let mut param = Parameters::default();
        param.add("id", id1.clone()).unwrap();
        param.add("mother_id", mother_id).unwrap();
        app.delete(
            "delete delete_person {
            Person { 
                $id
                parents[$mother_id]
            }
        }",
            Some(param),
        )
        .await
        .expect_err("cannot mutate anymore");

        let mut param = Parameters::default();
        param.add("id", id1.clone()).unwrap();

        app.delete(
            "delete delete_person {
            Person { 
                $id
            }
        }",
            Some(param),
        )
        .await
        .expect_err("cannot mutate anymore");

        let result = app
            .query(
                "query q{
           Person(order_by(name asc)){
                name
                parents{name}
           }
        }",
                None,
            )
            .await
            .unwrap();

        let expected = "{\n\"Person\":[{\"name\":\"me\",\"parents\":[{\"name\":\"mother\"}]}]\n}";
        assert_eq!(result, expected);
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn deletion_log() {
        init_database_path();
        let data_model = "
        {
            Person{ 
                name:String, 
                parents:[Person]
            }   
        }";

        let secret = random32();
        let path: PathBuf = DATA_PATH.into();
        let (app, verifying_key, _) = GraphDatabaseService::start(
            "authorisation app",
            data_model,
            &secret,
            &random32(),
            path,
            &Configuration::default(),
            EventService::new(),
        )
        .await
        .unwrap();

        let user_id = base64_encode(&verifying_key);

        let mut param = Parameters::default();
        param.add("user_id", user_id.clone()).unwrap();

        let room = app
            .mutate_raw(
                r#"mutate mut {
                    sys.Room{
                        admin: [{
                            verif_key:$user_id
                        }]
                        authorisations:[{
                            name:"admin"
                            rights:[{
                                entity:"Person"
                                mutate_self:true
                                mutate_all:true
                            }]
                        }]
                    }
                }"#,
                Some(param),
            )
            .await
            .unwrap();

        let room_insert = &room.mutate_entities[0];

        let room_id = base64_encode(&room_insert.node_to_mutate.id);

        let mut param = Parameters::default();
        param.add("room_id", room_id.clone()).unwrap();

        let mutat = app
            .mutate_raw(
                r#"mutate mut {
                P1: Person{
                    room_id: $room_id
                    name: "me"
                    parents:[{name:"father"},{name:"mother"}]
                }
                P2: Person{
                    room_id: $room_id
                    name: "another me"
                }
            }"#,
                Some(param),
            )
            .await
            .expect("can insert");

        let ent = &mutat.mutate_entities[0];
        assert_eq!("P1", ent.name);
        let id1 = base64_encode(&ent.node_to_mutate.id);
        let parents = ent.sub_nodes.get("parents").unwrap();

        let father_id = base64_encode(&parents[0].node_to_mutate.id);

        let ent = &mutat.mutate_entities[1];
        assert_eq!("P2", ent.name);
        let id2 = base64_encode(&ent.node_to_mutate.id);

        let mut param = Parameters::default();
        param.add("id", id2.clone()).unwrap();

        app.delete(
            "delete delete_person {
            Person { $id  }
        }",
            Some(param),
        )
        .await
        .unwrap();

        let mut del_log_recv = app
            .get_room_node_deletion_log(uid_decode(&room_id).unwrap(), "0".to_string(), now())
            .await;
        let del_log = del_log_recv.recv().await.unwrap().unwrap();
        assert_eq!(1, del_log.len());
        let deletion_entry = &del_log[0];
        deletion_entry.verify().unwrap();
        assert_eq!(id2, base64_encode(&deletion_entry.id));

        let mut param = Parameters::default();
        param.add("id", id1.clone()).unwrap();
        param.add("father_id", father_id.clone()).unwrap();
        app.delete(
            "delete delete_person {
            Person { 
                $id
                parents[$father_id]
            }
        }",
            Some(param),
        )
        .await
        .unwrap();

        let mut log_entries_recv = app
            .get_room_edge_deletion_log(uid_decode(&room_id).unwrap(), "0".to_string(), now())
            .await;
        let log_entries = log_entries_recv.recv().await.unwrap().unwrap();
        assert_eq!(1, log_entries.len());
        let deletion_entry = &log_entries[0];
        deletion_entry.verify().unwrap();
        assert_eq!(id1.clone(), base64_encode(&deletion_entry.src));
        assert_eq!(father_id.clone(), base64_encode(&deletion_entry.dest));

        let mut param = Parameters::default();
        param.add("id", id1.clone()).unwrap();

        app.mutate_raw(
            "mutate mut {
            Person{
                id:$id
                parents: null
            }
        }",
            Some(param),
        )
        .await
        .unwrap();
        let mut log_entries_recv = app
            .get_room_edge_deletion_log(uid_decode(&room_id).unwrap(), "0".to_string(), now())
            .await;
        let log_entries = log_entries_recv.recv().await.unwrap().unwrap();
        assert_eq!(2, log_entries.len());
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn room_documentation_blog_example() {
        init_database_path();
        let data_model = "
        blog {
            Article {
                title: String,
                content: String
            }

            Comment {
                article: blog.Article,
                comment: String
            }
        }";

        let secret = random32();
        let path: PathBuf = DATA_PATH.into();
        let (app, verifying_key, _) = GraphDatabaseService::start(
            "authorisation app",
            data_model,
            &secret,
            &random32(),
            path,
            &Configuration::default(),
            EventService::new(),
        )
        .await
        .unwrap();
        let user_id = base64_encode(&verifying_key);
        let mut param = Parameters::default();
        param.add("author", user_id.clone()).unwrap();

        let room = app
            .mutate_raw(
                r#"mutate {
                sys.Room{
                    admin: [{
                        verif_key:$author
                    }]

                    authorisations:[{
                        name:"authors"
                        rights:[{
                                entity:"blog.Article"
                                mutate_self:true
                                mutate_all:true
                            },{
                                entity:"Comment"
                                mutate_self:true
                                mutate_all:true
                            }
                        ]
                        users:[{
                            verif_key:$author
                        }]
                    },{
                        name:"readers"
                        rights:[ {
                                entity:"blog.Comment"
                                mutate_self:true
                                mutate_all:false
                        }]

                        users:[{
                            verif_key:$author
                        }]
                    }]
                }
            }
            "#,
                Some(param),
            )
            .await
            .unwrap();
        let room_insert = &room.mutate_entities[0];

        let room_id = base64_encode(&room_insert.node_to_mutate.id);
        let mut param = Parameters::default();
        param.add("room_id", room_id.clone()).unwrap();

        let res = app
            .mutate(
                r#"mutate {
           res: blog.Article{
                room_id: $room_id
                title: "hello"
                content: "world"
            }
        }"#,
                Some(param),
            )
            .await
            .unwrap();
        #[derive(Deserialize)]
        struct Id {
            id: String,
        }

        let mut parser = ResultParser::new(&res).unwrap();
        let ids: Id = parser.take_object("res").unwrap();

        let mut param = Parameters::default();
        param.add("room_id", room_id.clone()).unwrap();
        param.add("article", ids.id.clone()).unwrap();

        app.mutate(
            r#"mutate {
                    res:  blog.Comment {
                        room_id: $room_id
                        article: {id:$article}
                        comment: "a nice comment"
                    }
                }"#,
            Some(param),
        )
        .await
        .unwrap();

        let res = app
            .query(
                r#"query {
                    res:  blog.Comment {
                        room_id
                        comment
                        article {
                            title
                            content
                        }
                    }
                }"#,
                None,
            )
            .await
            .unwrap();
        println!("{}", res);
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn room_documentation_shared_calendar_example() {
        init_database_path();
        let data_model = "
        cal {
            Calendar {
                name: String,
                appointments: [cal.Appointment],
            }

            Appointment {
                start: Integer,
                end: Integer,
                detail: cal.AppointmentDetail
            }

            AppointmentDetail {
                title: String,
            }
        }";

        let secret = random32();
        let path: PathBuf = DATA_PATH.into();
        let (app, verifying_key, _) = GraphDatabaseService::start(
            "authorisation app",
            data_model,
            &secret,
            &random32(),
            path,
            &Configuration::default(),
            EventService::new(),
        )
        .await
        .unwrap();
        let user_id = base64_encode(&verifying_key);
        let mut param = Parameters::default();
        param.add("author", user_id.clone()).unwrap();

        let room = app
            .mutate_raw(
                r#"mutate {
                    sys.Room{
                        admin: [{
                            verif_key:$author
                        }]
                        authorisations:[{
                            name:"authors"
                            rights:[
                                {
                                    entity:"cal.Calendar"
                                    mutate_self:true
                                    mutate_all:true
                                },
                                {
                                    entity:"cal.Appointment"
                                    mutate_self:true
                                    mutate_all:true
                                }
                            ]
                            users:[{
                                verif_key:$author
                            }]
                        },{
                            name:"readers"
                            users:[{
                                verif_key:$author
                            }]
                        }]
                    }
                }
            "#,
                Some(param),
            )
            .await
            .unwrap();
        let room_insert = &room.mutate_entities[0];
        let room_calendar_id = base64_encode(&room_insert.node_to_mutate.id);

        let mut param = Parameters::default();
        param.add("author", user_id.clone()).unwrap();
        let room = app
            .mutate_raw(
                r#"mutate {
                sys.Room{
                    admin: [{
                        verif_key:$author
                    }]
                    authorisations:[{
                        name:"authors"
                        rights:[
                            {
                                entity:"cal.AppointmentDetail"
                                mutate_self:true
                                mutate_all:true
                            }
                        ]
                        users:[{
                            verif_key:$author
                        }]
                    },{
                        name:"readers"
                        users:[{
                            verif_key:$author
                        }]
                    }]
                }
            }
            "#,
                Some(param),
            )
            .await
            .unwrap();
        let room_insert = &room.mutate_entities[0];
        let room_cal_detail_id = base64_encode(&room_insert.node_to_mutate.id);

        let mut param = Parameters::default();
        param.add("room_id", room_calendar_id.clone()).unwrap();

        let res = app
            .mutate(
                r#"mutate {
                res: cal.Calendar{
                        room_id: $room_id
                        name: "my calendar"
                    }
                }"#,
                Some(param),
            )
            .await
            .unwrap();
        #[derive(Deserialize)]
        struct Id {
            id: String,
        }

        let mut parser = ResultParser::new(&res).unwrap();
        let ids: Id = parser.take_object("res").unwrap();

        let mut param = Parameters::default();
        param.add("calendar_id", ids.id.clone()).unwrap();
        param
            .add("room_calendar_id", room_calendar_id.clone())
            .unwrap();
        param
            .add("room_cal_detail_id", room_cal_detail_id.clone())
            .unwrap();
        param.add("start_date", 0).unwrap();
        param.add("end_date", 1675).unwrap();

        app.mutate(
            r#"mutate {
                cal.Calendar {
                    id:$calendar_id
                    appointments:[{
                        room_id: $room_calendar_id
                        start: $start_date
                        end:$end_date
                        detail:{
                            room_id: $room_cal_detail_id
                            title: "An important meeting"
                        }
                    }]
                }
            }"#,
            Some(param),
        )
        .await
        .unwrap();

        let res = app
            .query(
                r#"query {
                     cal.Calendar {
                        room_id
                        name
                        appointments(
                            nullable(detail)
                            ){
                            room_id
                            start
                            end
                            detail{
                                room_id
                                title
                            }
                        }
                    }
                }"#,
                None,
            )
            .await
            .unwrap();
        println!("{}", res);
    }
}
