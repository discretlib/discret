#[cfg(test)]
mod tests {

    use std::{fs, path::PathBuf};

    use crate::{
        cryptography::{base64_encode, now, random_secret},
        database::{
            authorisation::*,
            configuration::Configuration,
            edge::EdgeDeletionEntry,
            graph_database::GraphDatabaseService,
            node::NodeDeletionEntry,
            query_language::parameter::{Parameters, ParametersAdd},
        },
    };

    #[test]
    fn mutate_room() {
        let user1 = User {
            verifying_key: random_secret().to_vec(),
            date: 0,
            enabled: true,
        };

        let mut room = Room::default();
        let mut auth = Authorisation::default();

        auth.set_user(user1.clone()).unwrap();

        let mut cred1 = Credential::default();
        cred1.valid_from = 1000;
        cred1.mutate_room = true;
        cred1.mutate_room_users = true;

        auth.set_credential(cred1).unwrap();

        let mut cred2 = Credential::default();
        cred2.valid_from = 1000;

        auth.set_credential(cred2).expect_err(
            "Cannot insert a new credential with a from_date lower or equal to the last one",
        );

        let mut cred2 = Credential::default();
        cred2.valid_from = 2000;
        cred2.mutate_room = false;
        cred2.mutate_room_users = false;

        auth.set_credential(cred2).unwrap();

        assert!(!auth.can("", 10, &RightType::MutateRoom));
        assert!(!auth.can("", 10, &RightType::MutateRoomUsers));
        assert!(auth.can("", 1000, &RightType::MutateRoom));
        assert!(auth.can("", 1000, &RightType::MutateRoomUsers));
        assert!(auth.can("", 1500, &RightType::MutateRoom));
        assert!(auth.can("", 1500, &RightType::MutateRoomUsers));
        assert!(!auth.can("", 2000, &RightType::MutateRoom));
        assert!(!auth.can("", 2000, &RightType::MutateRoomUsers));
        assert!(!auth.can("", now(), &RightType::MutateRoom));
        assert!(!auth.can("", now(), &RightType::MutateRoomUsers));

        assert!(auth.is_user_valid_at(&user1.verifying_key, 1500));

        let mut user1_dis = user1.clone();
        user1_dis.date = 1500;
        user1_dis.enabled = false;
        auth.set_user(user1_dis.clone()).unwrap();

        user1_dis.date = 1000;
        auth.set_user(user1_dis.clone())
            .expect_err("cannot set a user validity date to a lower value than the current one");

        assert!(auth.is_user_valid_at(&user1.verifying_key, 1400));
        assert!(!auth.is_user_valid_at(&user1.verifying_key, 1501));

        let authorisation_id = random_secret().to_vec();
        room.add_auth(authorisation_id.clone(), auth).unwrap();
        room.add_auth(authorisation_id, Authorisation::default())
            .expect_err("cannot insert twice");

        assert!(!room.can(&user1.verifying_key, "", 10, &RightType::MutateRoom));
        assert!(room.can(&user1.verifying_key, "", 1400, &RightType::MutateRoom));
        assert!(!room.can(&user1.verifying_key, "", 1501, &RightType::MutateRoom));
    }

    #[test]
    fn entity_right() {
        let user1 = User {
            verifying_key: random_secret().to_vec(),
            date: 0,
            enabled: true,
        };

        //random_secret().to_vec();

        let mut room = Room::default();
        let mut auth = Authorisation::default();

        auth.set_user(user1.clone()).unwrap();
        let mut cred1 = Credential::default();
        cred1.valid_from = 1000;
        cred1
            .add_entity_rights(
                "Person",
                EntityRight {
                    entity: "Person".to_string(),
                    mutate_self: true,
                    delete_all: true,
                    mutate_all: true,
                },
            )
            .unwrap();
        cred1
            .add_entity_rights(
                "Pet",
                EntityRight {
                    entity: "Pet".to_string(),
                    mutate_self: false,
                    delete_all: false,
                    mutate_all: false,
                },
            )
            .unwrap();

        cred1
            .add_entity_rights(
                "Pet",
                EntityRight {
                    entity: "Pet".to_string(),
                    mutate_self: false,
                    delete_all: false,
                    mutate_all: false,
                },
            )
            .expect_err("cannot insert twice");

        auth.set_credential(cred1).unwrap();
        let authorisation_id = random_secret().to_vec();
        room.add_auth(authorisation_id, auth).unwrap();

        assert!(!room.can(&user1.verifying_key, "Person", 0, &RightType::DeleteAll));
        assert!(!room.can(&user1.verifying_key, "Person", 0, &RightType::MutateSelf));
        assert!(!room.can(&user1.verifying_key, "Person", 0, &RightType::MutateAll));

        assert!(room.can(&user1.verifying_key, "Person", 1000, &RightType::DeleteAll));
        assert!(room.can(&user1.verifying_key, "Person", 1000, &RightType::MutateSelf));
        assert!(room.can(&user1.verifying_key, "Person", 1000, &RightType::MutateAll));

        assert!(!room.can(&user1.verifying_key, "Pet", 1000, &RightType::DeleteAll));
        assert!(!room.can(&user1.verifying_key, "Pet", 1000, &RightType::MutateSelf));
        assert!(!room.can(&user1.verifying_key, "Pet", 1000, &RightType::MutateAll));

        let user2 = random_secret().to_vec();
        assert!(!room.can(&user2, "Person", 1000, &RightType::DeleteAll));
        assert!(!room.can(&user2, "Person", 1000, &RightType::MutateSelf));
        assert!(!room.can(&user2, "Person", 1000, &RightType::MutateAll));
    }

    const DATA_PATH: &str = "test/data/database/authorisation/";
    fn init_database_path() {
        let path: PathBuf = DATA_PATH.into();
        fs::create_dir_all(&path).unwrap();
        let paths = fs::read_dir(path).unwrap();

        for path in paths {
            let dir = path.unwrap().path();
            let paths = fs::read_dir(dir).unwrap();
            for file in paths {
                let files = file.unwrap().path();
                // println!("Name: {}", files.display());
                let _ = fs::remove_file(&files);
            }
        }
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn room_creation() {
        init_database_path();
        let data_model = "Person{ name:String }";
        let secret = random_secret();
        let path: PathBuf = DATA_PATH.into();
        let app = GraphDatabaseService::start(
            "authorisation app",
            data_model,
            &secret,
            path,
            Configuration::default(),
        )
        .await
        .unwrap();

        let user_id = base64_encode(app.verifying_key());

        let mut param = Parameters::default();
        param.add("user_id", user_id).unwrap();

        let _room = app
            .mutate(
                r#"mutation mut {
                    _Room{
                        type: "whatever"
                        authorisations:[{
                            name:"admin"
                            credentials: [{
                                mutate_room:true
                                mutate_room_users:true
                                rights:[{
                                    entity:"Person"
                                    mutate_self:true
                                    delete_all:true
                                    mutate_all:true
                                }]
                            }]
                            users: [{
                                verifying_key:$user_id
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
                    _Room{
                        type
                        authorisations{
                            name 
                            credentials{
                                mutate_room
                                mutate_room_users
                                rights{
                                    entity
                                    mutate_self
                                    delete_all
                                    mutate_all
                                }
                            } 
                            users{
                                enabled
                            }
                        }
                    }
                }",
                None,
            )
            .await
            .unwrap();

        let expected = "{\n\"_Room\":[{\"type\":\"whatever\",\"authorisations\":[{\"name\":\"admin\",\"credentials\":[{\"mutate_room\":true,\"mutate_room_users\":true,\"rights\":[{\"entity\":\"Person\",\"mutate_self\":true,\"delete_all\":true,\"mutate_all\":true}]}],\"users\":[{\"enabled\":true}]}]}]\n}";
        assert_eq!(result, expected);
        // println!("{:#?}", result);
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn mutate_with_room_propagation() {
        init_database_path();
        let data_model = "
        Person{ 
            name:String, 
            pets:[Pet]
        }   

        Pet{
            name:String,
        }
        ";

        let secret = random_secret();
        let path: PathBuf = DATA_PATH.into();
        let app = GraphDatabaseService::start(
            "authorisation app",
            data_model,
            &secret,
            path,
            Configuration::default(),
        )
        .await
        .unwrap();

        let user_id = base64_encode(app.verifying_key());

        let mut param = Parameters::default();
        param.add("user_id", user_id.clone()).unwrap();

        let room = app
            .mutate(
                r#"mutation mut {
                    _Room{
                        type: "whatever"
                        authorisations:[{
                            name:"admin"
                            credentials: [{
                                mutate_room:true
                                mutate_room_users:true
                                rights:[{
                                    entity:"Person"
                                    mutate_self:true
                                    delete_all:true
                                    mutate_all:true
                                }]
                            }]
                            users: [{
                                verifying_key:$user_id
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

        let credentials_insert = &authorisation_insert.sub_nodes.get("credentials").unwrap()[0];
        let _cred_id = base64_encode(&credentials_insert.node_to_mutate.id);

        let mut param = Parameters::default();
        param.add("room_id", room_id.clone()).unwrap();

        app.mutate(
            r#"mutation mut {
                    Person{
                        _rooms: [{id:$room_id}]
                        name: "me"
                    }

                }"#,
            Some(param),
        )
        .await
        .expect("Person has the necessary rights");

        let mut param = Parameters::default();
        param.add("room_id", room_id.clone()).unwrap();

        app.mutate(
            r#"mutation mut {
                    Pet{
                        _rooms: [{id:$room_id}]
                        name: "kiki"
                    }
                }"#,
            Some(param),
        )
        .await
        .expect_err("there is no authorisation to insert pets");

        let mut param = Parameters::default();
        param.add("room_id", room_id.clone()).unwrap();
        app.mutate(
            r#"mutation mut {
                    Person{
                        _rooms: [{id:$room_id}]
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
            .mutate(
                r#"mutation mut {
                _Room{
                    type: "whatever"
                    authorisations:[{
                        name:"admin"
                        credentials: [{
                            mutate_room:true
                            mutate_room_users:true
                            rights:[{
                                entity:"Pet"
                                mutate_self:true
                                delete_all:true
                                mutate_all:true
                            }]
                        }]
                        users: [{
                            verifying_key:$user_id
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
        app.mutate(
            r#"mutation mut {
                    Pet{
                        _rooms: [{id:$pet_room_id}]
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
        app.mutate(
            r#"mutation mut {
                    Person{
                        _rooms: [{id:$room_id}]
                        name: "another me"
                        pets:[{
                            _rooms: [{id:$pet_room_id}]
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
                    Person(order_by(name asc)){
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
            "{\n\"Person\":[{\"name\":\"another me\",\"pets\":[{\"name\":\"kiki\"}]}]\n}";
        assert_eq!(result, expected);
        //println!("{:#?}", result);
        //println!("{}", result);
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn authorisation_entities_error() {
        init_database_path();
        let data_model = "Person{name:String,}";
        let secret = random_secret();
        let path: PathBuf = DATA_PATH.into();
        let app = GraphDatabaseService::start(
            "authorisation app",
            data_model,
            &secret,
            path,
            Configuration::default(),
        )
        .await
        .unwrap();

        let user_id = base64_encode(app.verifying_key());

        let mut param = Parameters::default();
        param.add("user_id", user_id.clone()).unwrap();

        app.mutate(
            r#"mutation mut {
                    _Authorisation{
                        name:"admin"
                        credentials: [{
                            mutate_room:true
                            mutate_room_users:true
                            rights:[{
                                entity:"Person"
                                mutate_self:true
                                delete_all:true
                                mutate_all:true
                            }]
                        }]
                        users: [{
                            verifying_key:$user_id
                        }]
                    }
                }"#,
            Some(param),
        )
        .await
        .expect_err("_Authorisation cannot be mutated outside of a room context");

        app.mutate(
            r#"mutation mut {
                    _Credential{
                        mutate_room:true
                        mutate_room_users:true
                        rights:[{
                            entity:"Person"
                            mutate_self:true
                            delete_all:true
                            mutate_all:true
                        }]
                    }
                }"#,
            None,
        )
        .await
        .expect_err("_Credential cannot be mutated outside of a room context");

        app.mutate(
            r#"mutation mut {
                    _EntityRight {
                        entity:"Person"
                        mutate_self:true
                        delete_all:true
                        mutate_all:true
                    }
                }"#,
            None,
        )
        .await
        .expect_err("_EntityRight cannot be mutated outside of a room context");

        app.mutate(
            r#"mutation mut {
                    _UserAuth {
                        verifying_key:"cAH9ZO7FMgNhdaEpVLQbmQMb8gI-92d-b6wtTQbSLsw"
                    }
                }"#,
            None,
        )
        .await
        .expect_err("_UserAuth cannot be mutated outside of a room context");
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn room_update_credentials() {
        init_database_path();
        let data_model = "
        Person{ 
            name:String, 
            pets:[Pet]
        }   

        Pet{
            name:String,
        }
        ";

        let secret = random_secret();
        let path: PathBuf = DATA_PATH.into();
        let app = GraphDatabaseService::start(
            "authorisation app",
            data_model,
            &secret,
            path,
            Configuration::default(),
        )
        .await
        .unwrap();

        let user_id = base64_encode(app.verifying_key());

        let mut param = Parameters::default();
        param.add("user_id", user_id.clone()).unwrap();

        let room = app
            .mutate(
                r#"mutation mut {
                    _Room{
                        type: "whatever"
                        authorisations:[{
                            name:"admin"
                            credentials: [{
                                mutate_room:true
                                mutate_room_users:true
                                rights:[{
                                    entity:"Person"
                                    mutate_self:true
                                    delete_all:true
                                    mutate_all:true
                                }]
                            }]
                            users: [{
                                verifying_key:$user_id
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

        let credentials_insert = &authorisation_insert.sub_nodes.get("credentials").unwrap()[0];
        let cred_id = base64_encode(&credentials_insert.node_to_mutate.id);

        let mut param = Parameters::default();
        param.add("room_id", room_id.clone()).unwrap();
        app.mutate(
            r#"mutation mut {
                    Person{
                        _rooms: [{id:$room_id}]
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
        param.add("cred_id", cred_id.clone()).unwrap();

        app.mutate(
            r#"mutation mut {
                _Room{
                    id:$room_id
                    authorisations:[{
                        id:$auth_id
                        credentials: [{
                            id:$cred_id
                            rights:[{
                                entity:"Person"
                                mutate_self:true
                                delete_all:false
                                mutate_all:false
                            }]
                        }]
                    }]
                }

            }"#,
            Some(param),
        )
        .await
        .expect_err("Cannot update credentials");

        let mut param = Parameters::default();
        param.add("room_id", room_id.clone()).unwrap();
        param.add("auth_id", auth_id.clone()).unwrap();
        app.mutate(
            r#"mutation mut {
                _Room{
                    id:$room_id
                    authorisations:[{
                        id:$auth_id
                        credentials: [{
                            rights:[{
                                entity:"Person"
                                mutate_self:true
                                delete_all:false
                                mutate_all:false
                            }]
                        }]
                    }]
                }

            }"#,
            Some(param),
        )
        .await
        .expect_err("this removes the  mutate_room:true for the owner");

        let mut param = Parameters::default();
        param.add("room_id", room_id.clone()).unwrap();
        param.add("auth_id", auth_id.clone()).unwrap();
        app.mutate(
            r#"mutation mut {
                _Room{
                    id:$room_id
                    authorisations:[{
                        id:$auth_id
                        credentials: [{
                            mutate_room:true
                            mutate_room_users:true
                            rights:[{
                                entity:"Person"
                                mutate_self:false
                                delete_all:false
                                mutate_all:false
                            }]
                        }]
                    }]
                }

            }"#,
            Some(param),
        )
        .await
        .expect("ok a new version of the credential is created");

        let mut param = Parameters::default();
        param.add("room_id", room_id.clone()).unwrap();
        app.mutate(
            r#"mutation mut {
                    Person{
                        _rooms: [{id:$room_id}]
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
                    _Room(order_by(type asc)){
                        type
                        authorisations{
                            name
                            credentials(order_by(mdate desc)){
                                rights {
                                    entity
                                    mutate_self
                                    mutate_all
                                    delete_all
                                }
                            }
                        }

                    }
                }",
                None,
            )
            .await
            .unwrap();
        let expected = "{\n\"_Room\":[{\"type\":\"whatever\",\"authorisations\":[{\"name\":\"admin\",\"credentials\":[{\"rights\":[{\"entity\":\"Person\",\"mutate_self\":false,\"mutate_all\":false,\"delete_all\":false}]},{\"rights\":[{\"entity\":\"Person\",\"mutate_self\":true,\"mutate_all\":true,\"delete_all\":true}]}]}]}]\n}";
        assert_eq!(result, expected);
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn room_update_user() {
        init_database_path();
        let data_model = "Person{ name:String } ";

        let secret = random_secret();
        let path: PathBuf = DATA_PATH.into();
        let app = GraphDatabaseService::start(
            "authorisation app",
            data_model,
            &secret,
            path,
            Configuration::default(),
        )
        .await
        .unwrap();

        let user_id = base64_encode(app.verifying_key());

        let mut param = Parameters::default();
        param.add("user_id", user_id.clone()).unwrap();

        app.mutate(
            r#"mutation mut {
                    _Room{
                        type: "whatever"
                        authorisations:[{
                            name:"admin"
                            users: [{
                                verifying_key:$user_id
                            }]
                        }]
                    }

                }"#,
            Some(param),
        )
        .await
        .expect_err("no mutate_room_users:true credential");

        let mut param = Parameters::default();
        param.add("user_id", user_id.clone()).unwrap();
        let room = app
            .mutate(
                r#"mutation mut {
                    _Room{
                        type: "whatever"
                        authorisations:[{
                            name:"admin"
                            credentials: [{
                                mutate_room:true
                                mutate_room_users:true
                            }]
                            users: [{
                                verifying_key:$user_id
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

        let user_insert = &authorisation_insert.sub_nodes.get("users").unwrap()[0];
        let user_id = base64_encode(&user_insert.node_to_mutate.id);

        let mut param = Parameters::default();
        param.add("room_id", room_id.clone()).unwrap();
        param.add("auth_id", auth_id.clone()).unwrap();
        param.add("user_id", user_id.clone()).unwrap();

        app.mutate(
            r#"mutation mut {
                _Room{
                    id:$room_id
                    authorisations:[{
                        id:$auth_id
                        users: [{
                            id:$user_id
                            enabled: false
                        }]
                        
                    }]
                }

            }"#,
            Some(param),
        )
        .await
        .expect_err("Cannot disable itself");

        let mut param = Parameters::default();
        param.add("room_id", room_id.clone()).unwrap();
        param.add("auth_id", auth_id.clone()).unwrap();
        app.mutate(
            r#"mutation mut {
                _Room{
                    id:$room_id
                    authorisations:[{
                        id:$auth_id
                        users: [{
                            verifying_key:"cAH9ZO7FMgNhdaEpVLQbmQMb8gI-92d-b6wtTQbSLsw"
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
        app.mutate(
            r#"mutation mut {
                _Room{
                    id:$room_id
                    authorisations:[{
                        id:$auth_id
                        users: [{
                            verifying_key:"cAH9ZO7FMgNhdaEpVLQbmQMb8gI-92d-b6wtTQbSLsw"
                            enabled:false
                        }]
                    }]
                }
            }"#,
            Some(param),
        )
        .await
        .expect("can disable another user");

        let mut param = Parameters::default();
        param.add("room_id", room_id.clone()).unwrap();
        param.add("auth_id", auth_id.clone()).unwrap();
        app.mutate(
            r#"mutation mut {
                _Room{
                    id:$room_id
                    authorisations:[{
                        id:$auth_id
                        credentials: [{
                            mutate_room:true
                            mutate_room_users:false
                        }]
                        users: [{
                            verifying_key:"cAH9ZO7FMgNhdaEpVLQbmQMb8gI-92d-b6wtTQbSLsw"
                            enabled:false
                        }]
                        
                    }]
                }

            }"#,
            Some(param),
        )
        .await
        .expect_err("cannot add a new user anymore");

        let mut param = Parameters::default();
        param.add("room_id", room_id.clone()).unwrap();
        param.add("auth_id", auth_id.clone()).unwrap();
        app.mutate(
            r#"mutation mut {
                _Room{
                    id:$room_id
                    authorisations:[{
                        id:$auth_id
                        credentials: [{
                            mutate_room:true
                            mutate_room_users:false
                        }]
                    }]
                }

            }"#,
            Some(param),
        )
        .await
        .unwrap();

        let mut param = Parameters::default();
        param.add("room_id", room_id.clone()).unwrap();
        param.add("auth_id", auth_id.clone()).unwrap();
        app.mutate(
            r#"mutation mut {
                _Room{
                    id:$room_id
                    authorisations:[{
                        id:$auth_id
                        users: [{
                            verifying_key:"cAH9ZO7FMgNhdaEpVLQbmQMb8gI-92d-b6wtTQbSLsw"
                            enabled:false
                        }]
                        
                    }]
                }

            }"#,
            Some(param),
        )
        .await
        .expect_err("cannot add a new user anymore");
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn room_update_names() {
        init_database_path();
        let data_model = "Person{ name:String } ";

        let secret = random_secret();
        let path: PathBuf = DATA_PATH.into();
        let app = GraphDatabaseService::start(
            "authorisation app",
            data_model,
            &secret,
            path,
            Configuration::default(),
        )
        .await
        .unwrap();

        let user_id = base64_encode(app.verifying_key());

        let mut param = Parameters::default();
        param.add("user_id", user_id.clone()).unwrap();
        let room = app
            .mutate(
                r#"mutation mut {
                    _Room{
                        type: "whatever"
                        authorisations:[{
                            name:"admin"
                            credentials: [{
                                mutate_room:true
                                mutate_room_users:true
                            }]
                            users: [{
                                verifying_key:$user_id
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
        param.add("auth_id", auth_id.clone()).unwrap();

        app.mutate(
            r#"mutation mut {
                _Room{
                    id:$room_id
                    type: "new_type"
                    authorisations:[{
                        id:$auth_id
                        name:"new_admin"  
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
                    _Room(order_by(type asc)){
                        type
                        authorisations{
                            name
                            credentials(order_by(mdate desc)){
                                mutate_room
                                mutate_room_users
                            }
                        }

                    }
                }",
                None,
            )
            .await
            .unwrap();
        let expected = "{\n\"_Room\":[{\"type\":\"new_type\",\"authorisations\":[{\"name\":\"new_admin\",\"credentials\":[{\"mutate_room\":true,\"mutate_room_users\":true}]}]}]\n}";
        assert_eq!(result, expected);

        // println!("{:#?}", result);
        // println!("{}", result);
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn room_load() {
        init_database_path();
        let data_model = "
            Person{ name:String } 
            Pet{ name:String }
            ";

        let secret = random_secret();
        let path: PathBuf = DATA_PATH.into();

        //open a database, creates two rooms and close it
        let ids = {
            let app = GraphDatabaseService::start(
                "authorisation app",
                data_model,
                &secret,
                path.clone(),
                Configuration::default(),
            )
            .await
            .unwrap();

            let user_id = base64_encode(app.verifying_key());

            let mut param = Parameters::default();
            param.add("user_id", user_id.clone()).unwrap();
            let room = app
                .mutate(
                    r#"mutation mut {
                    _Room{
                        type: "person_only"
                        authorisations:[{
                            name:"admin"
                            credentials: [{
                                mutate_room:true
                                mutate_room_users:true
                                rights:[{
                                    entity:"Person"
                                    mutate_self:true
                                    delete_all:true
                                    mutate_all:true
                                }]
                            }]
                            users: [{
                                verifying_key:$user_id
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
                .mutate(
                    r#"mutation mut {
                    _Room{
                        type: "pet_only"
                        authorisations:[{
                            name:"admin"
                            credentials: [{
                                mutate_room:true
                                mutate_room_users:true
                                rights:[{
                                    entity:"Pet"
                                    mutate_self:true
                                    delete_all:true
                                    mutate_all:true
                                }]
                            }]
                            users: [{
                                verifying_key:$user_id
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

        let app = GraphDatabaseService::start(
            "authorisation app",
            data_model,
            &secret,
            path,
            Configuration::default(),
        )
        .await
        .unwrap();

        let result = app
            .query(
                "query q{
                    _Room(order_by(type asc)){
                        type
                    }
                }",
                None,
            )
            .await
            .unwrap();
        let expected = "{\n\"_Room\":[{\"type\":\"person_only\"},{\"type\":\"pet_only\"}]\n}";
        assert_eq!(result, expected);

        let mut param = Parameters::default();
        param.add("room_id", ids.0.clone()).unwrap();
        app.mutate(
            r#"mutation mut {
                    Person{
                        _rooms: [{id:$room_id}]
                        name: "me"
                    }

                }"#,
            Some(param),
        )
        .await
        .unwrap();

        let mut param = Parameters::default();
        param.add("room_id", ids.1.clone()).unwrap();
        app.mutate(
            r#"mutation mut {
                    Person{
                        _rooms: [{id:$room_id}]
                        name: "me"
                    }

                }"#,
            Some(param),
        )
        .await
        .expect_err("cannot insert a Person in the second room");

        let mut param = Parameters::default();
        param.add("room_id", ids.0.clone()).unwrap();
        app.mutate(
            r#"mutation mut {
                    Pet{
                        _rooms: [{id:$room_id}]
                        name: "me"
                    }

                }"#,
            Some(param),
        )
        .await
        .expect_err("cannot insert a Pet in the first room");

        let mut param = Parameters::default();
        param.add("room_id", ids.1.clone()).unwrap();
        app.mutate(
            r#"mutation mut {
                    Pet{
                        _rooms: [{id:$room_id}]
                        name: "me"
                    }

                }"#,
            Some(param),
        )
        .await
        .expect("can insert a Pet in the second room");

        //println!("{:#?}", result);
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn deletion_auth() {
        init_database_path();
        let data_model = "
        Person{ 
            name:String, 
            parents:[Person]
        }   
        ";

        let secret = random_secret();
        let path: PathBuf = DATA_PATH.into();
        let app = GraphDatabaseService::start(
            "authorisation app",
            data_model,
            &secret,
            path,
            Configuration::default(),
        )
        .await
        .unwrap();

        let user_id = base64_encode(app.verifying_key());

        let mut param = Parameters::default();
        param.add("user_id", user_id.clone()).unwrap();

        let room = app
            .mutate(
                r#"mutation mut {
                    _Room{
                        type: "whatever"
                        authorisations:[{
                            name:"admin"
                            credentials: [{
                                mutate_room:true
                                mutate_room_users:true
                                rights:[{
                                    entity:"Person"
                                    mutate_self:true
                                    delete_all:true
                                    mutate_all:true
                                }]
                            }]
                            users: [{
                                verifying_key:$user_id
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
            .mutate(
                r#"mutation mut {
                P1: Person{
                    _rooms: [{id:$room_id}]
                    name: "me"
                    parents:[{name:"father"},{name:"mother"}]
                }
                P2: Person{
                    _rooms: [{id:$room_id}]
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
            "deletion delete_person {
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
            "deletion delete_person {
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
        app.mutate(
            r#"mutation mut {
                _Room{
                    id:$id
                    authorisations:[{
                        id:$auth_id
                        credentials: [{
                            mutate_room:true
                            mutate_room_users:true
                            rights:[{
                                entity:"Person"
                                mutate_self:false
                                delete_all:true
                                mutate_all:true
                            }]
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
            "deletion delete_person {
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
            "deletion delete_person {
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
        //println!("{:#?}", result);
        //println!("{}", result);
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn deletion_log() {
        init_database_path();
        let data_model = "
        Person{ 
            name:String, 
            parents:[Person]
        }   
        ";

        let secret = random_secret();
        let path: PathBuf = DATA_PATH.into();
        let app = GraphDatabaseService::start(
            "authorisation app",
            data_model,
            &secret,
            path,
            Configuration::default(),
        )
        .await
        .unwrap();

        let user_id = base64_encode(app.verifying_key());

        let mut param = Parameters::default();
        param.add("user_id", user_id.clone()).unwrap();

        let room = app
            .mutate(
                r#"mutation mut {
                    _Room{
                        type: "whatever"
                        authorisations:[{
                            name:"admin"
                            credentials: [{
                                mutate_room:true
                                mutate_room_users:true
                                rights:[{
                                    entity:"Person"
                                    mutate_self:true
                                    delete_all:true
                                    mutate_all:true
                                }]
                            }]
                            users: [{
                                verifying_key:$user_id
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
            .mutate(
                r#"mutation mut {
                P1: Person{
                    _rooms: [{id:$room_id}]
                    name: "me"
                    parents:[{name:"father"},{name:"mother"}]
                }
                P2: Person{
                    _rooms: [{id:$room_id}]
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
            "deletion delete_person {
            Person { $id  }
        }",
            Some(param),
        )
        .await
        .unwrap();

        let node_log_query = "SELECT  
            room,
            id,
            entity,
            deletion_date,
            verifying_key,
            signature 
        FROM _node_deletion_log";

        let res = app
            .select(
                node_log_query.to_string(),
                Vec::new(),
                NodeDeletionEntry::MAPPING,
            )
            .await
            .unwrap();

        assert_eq!(1, res.len());
        assert_eq!(id2, base64_encode(&res[0].id));

        let mut param = Parameters::default();
        param.add("id", id1.clone()).unwrap();
        param.add("father_id", father_id.clone()).unwrap();
        app.delete(
            "deletion delete_person {
            Person { 
                $id
                parents[$father_id]
            }
        }",
            Some(param),
        )
        .await
        .unwrap();

        let edge_log_query = "SELECT 
                room,
                src,
                src_entity, 
                dest,
                label,
                deletion_date,
                verifying_key,
                signature
            FROM  _edge_deletion_log";

        let res = app
            .select(
                edge_log_query.to_string(),
                Vec::new(),
                EdgeDeletionEntry::MAPPING,
            )
            .await
            .unwrap();

        assert_eq!(1, res.len());
        assert_eq!(id1.clone(), base64_encode(&res[0].src));
        assert_eq!(father_id.clone(), base64_encode(&res[0].dest));

        let mut param = Parameters::default();
        param.add("id", id1.clone()).unwrap();

        app.mutate(
            "mutation mut {
            Person{
                id:$id
                parents: null
            }
        }",
            Some(param),
        )
        .await
        .unwrap();

        let res = app
            .select(
                edge_log_query.to_string(),
                Vec::new(),
                EdgeDeletionEntry::MAPPING,
            )
            .await
            .unwrap();

        assert_eq!(2, res.len());
    }
}
