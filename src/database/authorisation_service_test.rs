#[cfg(test)]
mod tests {

    use std::{collections::HashMap, fs, path::PathBuf};

    use crate::{
        cryptography::{base64_decode, base64_encode, random32, Ed25519SigningKey},
        database::{
            authorisation_service::*,
            configuration::Configuration,
            graph_database::GraphDatabaseService,
            query_language::parameter::{Parameters, ParametersAdd},
            room::{Authorisation, EntityRight, RightType, Room, User},
        },
        date_utils::now,
        event_service::EventService,
    };

    #[test]
    fn room_admins() {
        let valid_date: i64 = 10000;
        let mut user1 = User {
            verifying_key: random32().to_vec(),
            date: valid_date,
            enabled: true,
        };

        let mut room = Room::default();
        assert!(!room.is_admin(&user1.verifying_key, valid_date));

        room.add_admin_user(user1.clone()).unwrap();
        assert!(room.is_admin(&user1.verifying_key, valid_date));

        //invalid before valid_date
        assert!(!room.is_admin(&user1.verifying_key, valid_date - 1));

        user1.date = valid_date - 100;
        room.add_admin_user(user1.clone())
            .expect_err("Cannot add a  user admin definition before the last date");

        user1.date = valid_date + 1000;
        user1.enabled = false;
        room.add_admin_user(user1.clone()).unwrap();

        //user is valid beetween valid_date and valid_date+1000
        assert!(room.is_admin(&user1.verifying_key, valid_date + 10));

        //user is disabled
        assert!(!room.is_admin(&user1.verifying_key, user1.date));
    }

    #[test]
    fn room_user_admins() {
        let valid_date: i64 = 10000;
        let mut user1 = User {
            verifying_key: random32().to_vec(),
            date: valid_date,
            enabled: true,
        };

        let mut room = Room::default();
        assert!(!room.is_user_admin(&user1.verifying_key, valid_date));

        room.add_user_admin_user(user1.clone()).unwrap();
        assert!(room.is_user_admin(&user1.verifying_key, valid_date));

        //invalid before valid_date
        assert!(!room.is_user_admin(&user1.verifying_key, valid_date - 1));

        user1.date = valid_date - 100;
        room.add_user_admin_user(user1.clone())
            .expect_err("Cannot add a  user admin definition before the last date");

        user1.date = valid_date + 1000;
        user1.enabled = false;
        room.add_user_admin_user(user1.clone()).unwrap();

        //user is valid beetween valid_date and valid_date+1000
        assert!(room.is_user_admin(&user1.verifying_key, valid_date + 10));

        //user is disabled
        assert!(!room.is_user_admin(&user1.verifying_key, user1.date));
    }

    #[test]
    fn entity_right() {
        let user_valid_date: i64 = 1000;
        let user1 = User {
            verifying_key: random32().to_vec(),
            date: user_valid_date,
            enabled: true,
        };

        let mut room = Room::default();
        room.add_admin_user(user1.clone()).unwrap();
        room.add_user_admin_user(user1.clone()).unwrap();

        let mut auth = Authorisation::default();
        auth.add_user(user1.clone()).unwrap();
        assert!(auth.is_user_valid_at(&user1.verifying_key, user_valid_date));
        assert!(!auth.is_user_valid_at(&user1.verifying_key, user_valid_date - 1));

        let ent_date: i64 = 100;
        let entity = "Person";
        let person_right = EntityRight::new(ent_date, entity.to_string(), true, true);

        auth.add_right(person_right).unwrap();

        let person_right = EntityRight::new(ent_date - 1, entity.to_string(), true, true);

        auth.add_right(person_right)
            .expect_err("Cannot insert a right before an existing one");
        let last_date = ent_date + 1000;
        let person_right = EntityRight::new(last_date, entity.to_string(), false, false);
        auth.add_right(person_right.clone()).unwrap();

        room.add_auth(auth).unwrap();

        //user is invalid at this date

        assert!(!room.can(
            &user1.verifying_key,
            entity,
            ent_date,
            &RightType::MutateSelf
        ));
        assert!(!room.can(
            &user1.verifying_key,
            entity,
            ent_date,
            &RightType::MutateAll
        ));

        //user is valid at this date
        assert!(room.can(
            &user1.verifying_key,
            entity,
            user_valid_date,
            &RightType::MutateSelf
        ));
        assert!(room.can(
            &user1.verifying_key,
            entity,
            user_valid_date,
            &RightType::MutateAll
        ));

        //the last right disable it all
        assert!(!room.can(
            &user1.verifying_key,
            entity,
            last_date,
            &RightType::MutateSelf
        ));
        assert!(!room.can(
            &user1.verifying_key,
            entity,
            last_date,
            &RightType::MutateAll
        ));
    }

    #[test]
    fn get_room_for_user() {
        let user_valid_date: i64 = 1000;
        let user1 = User {
            verifying_key: random32().to_vec(),
            date: user_valid_date,
            enabled: true,
        };

        let user2 = User {
            verifying_key: random32().to_vec(),
            date: user_valid_date,
            enabled: true,
        };

        let user3 = User {
            verifying_key: random32().to_vec(),
            date: user_valid_date,
            enabled: true,
        };

        let mut room = Room {
            id: random32().to_vec(),
            ..Default::default()
        };
        room.add_admin_user(user1.clone()).unwrap();
        room.add_user_admin_user(user2.clone()).unwrap();

        let mut auth = Authorisation::default();
        auth.add_user(user3.clone()).unwrap();

        room.add_auth(auth).unwrap();

        let mut room_auth = RoomAuthorisations {
            signing_key: Ed25519SigningKey::new(),
            rooms: HashMap::new(),
        };

        room_auth.add_room(room);

        let room_list = room_auth.get_rooms_for_user(&random32().to_vec(), user_valid_date);
        assert_eq!(0, room_list.len());

        let room_list = room_auth.get_rooms_for_user(&user1.verifying_key, user_valid_date);
        assert_eq!(1, room_list.len());

        let room_list = room_auth.get_rooms_for_user(&user2.verifying_key, user_valid_date);
        assert_eq!(1, room_list.len());

        let room_list = room_auth.get_rooms_for_user(&user3.verifying_key, user_valid_date);
        assert_eq!(1, room_list.len());

        let room_list = room_auth.get_rooms_for_user(&user1.verifying_key, 0);
        assert_eq!(0, room_list.len());

        let room_list = room_auth.get_rooms_for_user(&user2.verifying_key, 0);
        assert_eq!(0, room_list.len());

        let room_list = room_auth.get_rooms_for_user(&user3.verifying_key, 0);
        assert_eq!(0, room_list.len());
    }

    const DATA_PATH: &str = "test_data/database/authorisation_service_test/";
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
        let secret = random32();
        let path: PathBuf = DATA_PATH.into();
        let app = GraphDatabaseService::start(
            "authorisation app",
            data_model,
            &secret,
            path,
            Configuration::default(),
            EventService::new(),
        )
        .await
        .unwrap();

        let user_id = base64_encode(app.verifying_key());

        let mut param = Parameters::default();
        param.add("user_id", user_id).unwrap();

        let _room = app
            .mutate_raw(
                r#"mutation mut {
                    _Room{
                        admin: [{
                            verifying_key:$user_id
                        }]
                        user_admin: [{
                            verifying_key:$user_id
                        }]
                        authorisations:[{
                            name:"what"
                            rights:[{
                                entity:"Person"
                                mutate_self:true
                                mutate_all:true
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
                        admin{
                            enabled
                        }
                        user_admin{
                            enabled
                        }
                        authorisations{
                            name 
                            rights{
                                entity
                                mutate_self
                                mutate_all
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
        let expected = "{\n\"_Room\":[{\"admin\":[{\"enabled\":true}],\"user_admin\":[{\"enabled\":true}],\"authorisations\":[{\"name\":\"what\",\"rights\":[{\"entity\":\"Person\",\"mutate_self\":true,\"mutate_all\":true}],\"users\":[{\"enabled\":true}]}]}]\n}";
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

        let secret = random32();
        let path: PathBuf = DATA_PATH.into();
        let app = GraphDatabaseService::start(
            "authorisation app",
            data_model,
            &secret,
            path,
            Configuration::default(),
            EventService::new(),
        )
        .await
        .unwrap();

        let user_id = base64_encode(app.verifying_key());

        let mut param = Parameters::default();
        param.add("user_id", user_id.clone()).unwrap();

        let room = app
            .mutate_raw(
                r#"mutation mut {
                    _Room{
                        admin: [{
                            verifying_key:$user_id
                        }]
                        user_admin: [{
                            verifying_key:$user_id
                        }]
                        authorisations:[{
                            name:"admin"
                            rights:[{
                                entity:"Person"
                                mutate_self:true
                                mutate_all:true
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

        let mut param = Parameters::default();
        param.add("room_id", room_id.clone()).unwrap();

        app.mutate_raw(
            r#"mutation mut {
                    Person{
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
            r#"mutation mut {
                    Pet{
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
            r#"mutation mut {
                    Person{
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
                r#"mutation mut {
                _Room{
                    admin: [{
                        verifying_key:$user_id
                    }]
                    user_admin: [{
                        verifying_key:$user_id
                    }]
                    authorisations:[{
                        name:"admin"
                        rights:[{
                            entity:"Pet"
                            mutate_self:true
                            mutate_all:true
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
        app.mutate_raw(
            r#"mutation mut {
                    Pet{
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
            r#"mutation mut {
                    Person{
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
        let secret = random32();
        let path: PathBuf = DATA_PATH.into();
        let app = GraphDatabaseService::start(
            "authorisation app",
            data_model,
            &secret,
            path,
            Configuration::default(),
            EventService::new(),
        )
        .await
        .unwrap();

        let user_id = base64_encode(app.verifying_key());

        let mut param = Parameters::default();
        param.add("user_id", user_id.clone()).unwrap();

        app.mutate_raw(
            r#"mutation mut {
                    _Authorisation{
                        name:"admin" 
                        rights:[{
                            entity:"Person"
                            mutate_self:true
                            mutate_all:true
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

        app.mutate_raw(
            r#"mutation mut {
                    _EntityRight {
                        entity:"Person"
                        mutate_self:true
                        mutate_all:true
                    }
                }"#,
            None,
        )
        .await
        .expect_err("_EntityRight cannot be mutated outside of a room context");

        app.mutate_raw(
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
    async fn room_update_rights() {
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

        let secret = random32();
        let path: PathBuf = DATA_PATH.into();
        let app = GraphDatabaseService::start(
            "authorisation app",
            data_model,
            &secret,
            path,
            Configuration::default(),
            EventService::new(),
        )
        .await
        .unwrap();

        let user_id = base64_encode(app.verifying_key());

        let mut param = Parameters::default();
        param.add("user_id", user_id.clone()).unwrap();

        let room = app
            .mutate_raw(
                r#"mutation mut {
                    _Room{
                        admin: [{
                            verifying_key:$user_id
                        }]
                        user_admin: [{
                            verifying_key:$user_id
                        }]
                        authorisations:[{
                            name:"admin"
                            rights:[{
                                entity:"Person"
                                mutate_self:true
                                mutate_all:true
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
        app.mutate_raw(
            r#"mutation mut {
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
            r#"mutation mut {
                _Room{
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
            r#"mutation mut {
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
                    _Room{
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
        let expected =  "{\n\"_Room\":[{\"authorisations\":[{\"name\":\"admin\",\"rights\":[{\"entity\":\"Person\",\"mutate_self\":false,\"mutate_all\":false},{\"entity\":\"Person\",\"mutate_self\":true,\"mutate_all\":true}]}]}]\n}";
        assert_eq!(result, expected);
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn room_update_user() {
        init_database_path();
        let data_model = "Person{ name:String } ";

        let secret = random32();
        let path: PathBuf = DATA_PATH.into();
        let app = GraphDatabaseService::start(
            "authorisation app",
            data_model,
            &secret,
            path,
            Configuration::default(),
            EventService::new(),
        )
        .await
        .unwrap();

        let user_id = base64_encode(app.verifying_key());

        let mut param = Parameters::default();
        param.add("user_id", user_id.clone()).unwrap();

        let room = app
            .mutate_raw(
                r#"mutation mut {
                    _Room{
                        admin: [{
                            verifying_key:$user_id
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
            r#"mutation mut {
                _Room{
                    id:$room_id
                    admin: [{
                        verifying_key:$user_id
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

        app.mutate_raw(
            r#"mutation mut {
                    _Room{
                        id:$room_id
                        authorisations:[{
                            id: $auth_id
                            users: [{
                                verifying_key:$user_id
                            }]
                        }]
                    }

                }"#,
            Some(param),
        )
        .await
        .expect_err("user_id is not allowed to insert new users");

        let mut param = Parameters::default();
        param.add("room_id", room_id.clone()).unwrap();
        param.add("auth_id", auth_id.clone()).unwrap();
        param.add("user_id", user_id.clone()).unwrap();

        app.mutate_raw(
            r#"mutation mut {
                _Room{
                    id:$room_id
                    user_admin: [{
                        verifying_key:$user_id
                    }]
                    authorisations:[{
                        id:$auth_id
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

        let mut param = Parameters::default();
        param.add("room_id", room_id.clone()).unwrap();
        param.add("auth_id", auth_id.clone()).unwrap();
        app.mutate_raw(
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

        app.mutate_raw(
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
        param.add("user_id", user_id.clone()).unwrap();
        app.mutate_raw(
            r#"mutation mut {
                _Room{
                    id:$room_id
                    authorisations:[{
                        id:$auth_id
                        users: [{
                            verifying_key:$user_id
                            enabled:false
                        }]
                    }]
                }
            }"#,
            Some(param),
        )
        .await
        .expect("can disable itself in an authorisation");

        let mut param = Parameters::default();
        param.add("room_id", room_id.clone()).unwrap();
        param.add("user_id", user_id.clone()).unwrap();
        app.mutate_raw(
            r#"mutation mut {
                _Room{
                    id:$room_id
                    user_admin: [{
                        verifying_key:$user_id
                        enabled:false
                    }]
                }
            }"#,
            Some(param),
        )
        .await
        .expect("can disable itself from user_admin");

        let mut param = Parameters::default();
        param.add("room_id", room_id.clone()).unwrap();
        param.add("auth_id", auth_id.clone()).unwrap();
        app.mutate_raw(
            r#"mutation mut {
                _Room{
                    id:$room_id
                    authorisations:[{
                        id:$auth_id
                        users: [{
                            verifying_key:"cAH9ZO7FMgNhdaEpVLQbmQMb8gI-92d-b6wtTQbSLsw"
                            enabled:true
                        }]
                        
                    }]
                }

            }"#,
            Some(param),
        )
        .await
        .expect_err("cannot mutate user anymore");
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn room_load() {
        init_database_path();
        let data_model = "
            Person{ name:String } 
            Pet{ name:String }
            ";

        let secret = random32();
        let path: PathBuf = DATA_PATH.into();

        //open a database, creates two rooms and close it
        let ids = {
            let app = GraphDatabaseService::start(
                "authorisation app",
                data_model,
                &secret,
                path.clone(),
                Configuration::default(),
                EventService::new(),
            )
            .await
            .unwrap();

            let user_id = base64_encode(app.verifying_key());

            let mut param = Parameters::default();
            param.add("user_id", user_id.clone()).unwrap();
            let room = app
                .mutate_raw(
                    r#"mutation mut {
                    _Room{
                        admin: [{
                            verifying_key:$user_id
                        }]
                        user_admin: [{
                            verifying_key:$user_id
                        }]
                        authorisations:[{
                            name:"admin"
                            rights:[{
                                entity:"Person"
                                mutate_self:true
                                mutate_all:true
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
                .mutate_raw(
                    r#"mutation mut {
                    _Room{
                        admin: [{
                            verifying_key:$user_id
                        }]
                        user_admin: [{
                            verifying_key:$user_id
                        }]
                        authorisations:[{
                            name:"admin"
                            rights:[{
                                entity:"Pet"
                                mutate_self:true
                                mutate_all:true
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
            EventService::new(),
        )
        .await
        .unwrap();

        let mut param = Parameters::default();
        param.add("room_id", ids.0.clone()).unwrap();
        app.mutate_raw(
            r#"mutation mut {
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
            r#"mutation mut {
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
            r#"mutation mut {
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
            r#"mutation mut {
                    Pet{
                        room_id: $room_id
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

        let secret = random32();
        let path: PathBuf = DATA_PATH.into();
        let app = GraphDatabaseService::start(
            "authorisation app",
            data_model,
            &secret,
            path,
            Configuration::default(),
            EventService::new(),
        )
        .await
        .unwrap();

        let user_id = base64_encode(app.verifying_key());

        let mut param = Parameters::default();
        param.add("user_id", user_id.clone()).unwrap();

        let room = app
            .mutate_raw(
                r#"mutation mut {
                    _Room{
                        admin: [{
                            verifying_key:$user_id
                        }]
                        user_admin: [{
                            verifying_key:$user_id
                        }]
                        authorisations:[{
                            name:"admin"
                            rights:[{
                                entity:"Person"
                                mutate_self:true
                                mutate_all:true
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
            .mutate_raw(
                r#"mutation mut {
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
        app.mutate_raw(
            r#"mutation mut {
                _Room{
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

        let secret = random32();
        let path: PathBuf = DATA_PATH.into();
        let app = GraphDatabaseService::start(
            "authorisation app",
            data_model,
            &secret,
            path,
            Configuration::default(),
            EventService::new(),
        )
        .await
        .unwrap();

        let user_id = base64_encode(app.verifying_key());

        let mut param = Parameters::default();
        param.add("user_id", user_id.clone()).unwrap();

        let room = app
            .mutate_raw(
                r#"mutation mut {
                    _Room{
                        admin: [{
                            verifying_key:$user_id
                        }]
                        user_admin: [{
                            verifying_key:$user_id
                        }]
                        authorisations:[{
                            name:"admin"
                            rights:[{
                                entity:"Person"
                                mutate_self:true
                                mutate_all:true
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
            .mutate_raw(
                r#"mutation mut {
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
            "deletion delete_person {
            Person { $id  }
        }",
            Some(param),
        )
        .await
        .unwrap();

        let del_log = app
            .get_room_node_deletion_log(base64_decode(&room_id.as_bytes()).unwrap(), now())
            .await
            .unwrap();
        assert_eq!(1, del_log.len());
        let deletion_entry = &del_log[0];
        deletion_entry.verify().unwrap();
        assert_eq!(id2, base64_encode(&deletion_entry.id));

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
        let log_entries = app
            .get_room_edge_deletion_log(base64_decode(&room_id.as_bytes()).unwrap(), now())
            .await
            .unwrap();

        assert_eq!(1, log_entries.len());
        let deletion_entry = &log_entries[0];
        deletion_entry.verify().unwrap();
        assert_eq!(id1.clone(), base64_encode(&deletion_entry.src));
        assert_eq!(father_id.clone(), base64_encode(&deletion_entry.dest));

        let mut param = Parameters::default();
        param.add("id", id1.clone()).unwrap();

        app.mutate_raw(
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
        let log_entries = app
            .get_room_edge_deletion_log(base64_decode(&room_id.as_bytes()).unwrap(), now())
            .await
            .unwrap();

        assert_eq!(2, log_entries.len());
    }
}
