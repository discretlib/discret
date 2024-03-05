#[cfg(test)]
mod tests {

    use std::{fs, path::PathBuf};

    use crate::{
        cryptography::{base64_encode, now, random_secret},
        database::{
            authorisation::*,
            configuration::Configuration,
            graph_database::GraphDatabaseService,
            query_language::parameter::{Parameters, ParametersAdd},
        },
    };

    pub const USER1: &'static str = "cAH9ZO7FMgNhdaEpVLQbmQMb8gI-92d-b6wtTQbSLsw";
    pub const USER2: &'static str = "Vd5TCzm0QfQVWpsq47IIC6nKNIkCBw9PHnfJ4eX3HL4";
    pub const USER3: &'static str = "eNDCXC4jToBqPz5-pcobB7tQPlIMexYp-wUk9v2gIlY";

    #[test]
    fn mutate_room() {
        let user1 = random_secret().to_vec();

        let mut room = Room::default();
        let mut auth = Authorisation::default();
        auth.enable_user(user1.clone());
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

        assert!(auth.is_user_valid_at(&user1, 1500));

        auth.disable_user_starting_at(user1.clone(), 1500).unwrap();
        auth.disable_user_starting_at(user1.clone(), 1000)
            .expect_err("cannot set a user validity date to a lower value than the current one");
        assert!(auth.is_user_valid_at(&user1, 1400));
        assert!(!auth.is_user_valid_at(&user1, 1501));

        let authorisation_id = random_secret().to_vec();
        room.add_auth(authorisation_id.clone(), auth).unwrap();
        room.add_auth(authorisation_id, Authorisation::default())
            .expect_err("cannot insert twice");

        assert!(!room.can(&user1, "", 10, &RightType::MutateRoom));
        assert!(room.can(&user1, "", 1400, &RightType::MutateRoom));
        assert!(!room.can(&user1, "", 1501, &RightType::MutateRoom));
    }

    #[test]
    fn entity_right() {
        let user1 = random_secret().to_vec();

        let mut room = Room::default();
        let mut auth = Authorisation::default();
        auth.enable_user(user1.clone());
        let mut cred1 = Credential::default();
        cred1.valid_from = 1000;
        cred1
            .add_entity_rights(
                "Person",
                EntityRight {
                    entity: "Person".to_string(),
                    insert: true,
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
                    insert: false,
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
                    insert: false,
                    delete_all: false,
                    mutate_all: false,
                },
            )
            .expect_err("cannot insert twice");

        auth.set_credential(cred1).unwrap();
        let authorisation_id = random_secret().to_vec();
        room.add_auth(authorisation_id, auth).unwrap();

        assert!(!room.can(&user1, "Person", 0, &RightType::DeleteAll));
        assert!(!room.can(&user1, "Person", 0, &RightType::Insert));
        assert!(!room.can(&user1, "Person", 0, &RightType::MutateAll));

        assert!(room.can(&user1, "Person", 1000, &RightType::DeleteAll));
        assert!(room.can(&user1, "Person", 1000, &RightType::Insert));
        assert!(room.can(&user1, "Person", 1000, &RightType::MutateAll));

        assert!(!room.can(&user1, "Pet", 1000, &RightType::DeleteAll));
        assert!(!room.can(&user1, "Pet", 1000, &RightType::Insert));
        assert!(!room.can(&user1, "Pet", 1000, &RightType::MutateAll));

        let user2 = random_secret().to_vec();
        assert!(!room.can(&user2, "Person", 1000, &RightType::DeleteAll));
        assert!(!room.can(&user2, "Person", 1000, &RightType::Insert));
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
        .unwrap();

        let user_id = base64_encode(app.verifying_key());

        let mut param = Parameters::default();
        param.add("user_id", user_id).unwrap();

        let _room = app
            .mutate(
                r#"mutation mut {
                    _Room{
                        name: "test"
                        type: "whatever"
                        authorisations:[{
                            name:"admin"
                            credentials: [{
                                mutate_room:true
                                mutate_room_users:true
                                rights:[{
                                    entity:"Person"
                                    insert:true
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
                        name
                        type
                        authorisations{
                            name 
                            credentials{
                                mutate_room
                                mutate_room_users
                                rights{
                                    entity
                                    insert
                                    delete_all
                                    mutate_all
                                }
                            } 
                            users{
                                valid_before
                            }
                        }
                    }
                }",
                None,
            )
            .await
            .unwrap();

        let expected = "{\n\"_Room\":[{\"name\":\"test\",\"type\":\"whatever\",\"authorisations\":[{\"name\":\"admin\",\"credentials\":[{\"mutate_room\":true,\"mutate_room_users\":true,\"rights\":[{\"entity\":\"Person\",\"insert\":true,\"delete_all\":true,\"mutate_all\":true}]}],\"users\":[{\"valid_before\":null}]}]}]\n}";
        assert_eq!(result, expected);
        //println!("{:#?}", result);
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
        .unwrap();

        let user_id = base64_encode(app.verifying_key());

        let mut param = Parameters::default();
        param.add("user_id", user_id).unwrap();

        let room = app
            .mutate(
                r#"mutation mut {
                    _Room{
                        name: "test"
                        type: "whatever"
                        authorisations:[{
                            name:"admin"
                            credentials: [{
                                mutate_room:true
                                mutate_room_users:true
                                rights:[{
                                    entity:"Person"
                                    insert:true
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

        let room_insert = &room.insert_entities[0];
        let room_id = base64_encode(&room_insert.node_insert.id);

        let authorisation_insert = &room_insert.sub_nodes.get("authorisations").unwrap()[0];
        let _auth_id = base64_encode(&authorisation_insert.node_insert.id);

        let credentials_insert = &authorisation_insert.sub_nodes.get("credentials").unwrap()[0];
        let _cred_id = base64_encode(&credentials_insert.node_insert.id);

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

        let result = app
            .query(
                "query q{
                    Person{
                        _rooms {id}
                        name
                        pets{
                            _rooms {id} 
                            name
                        }
                    }
                }",
                None,
            )
            .await
            .unwrap();

        // let expected = "{\n\"_Room\":[{\"name\":\"test\",\"type\":\"whatever\",\"authorisations\":[{\"name\":\"admin\",\"credentials\":[{\"mutate_room\":true,\"mutate_room_users\":true,\"rights\":[{\"entity\":\"Person\",\"insert\":true,\"delete_all\":true,\"mutate_all\":true}]}],\"users\":[{\"valid_before\":null}]}]}]\n}";
        // assert_eq!(result, expected);
        // println!("{:#?}", result);
        println!("{}", result);
    }
}
