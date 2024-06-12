use std::{path::PathBuf, time::Duration};

use discret::{
    base64_encode, uid_decode, Configuration, DefaultRoom, Discret, Event, Parameters,
    ParametersAdd, ResultParser,
};
use rand::{rngs::OsRng, RngCore};
use serde::Deserialize;
const DATA_PATH: &str = "test_data/tests/";
pub fn random32() -> [u8; 32] {
    let mut random: [u8; 32] = [0; 32];

    OsRng.fill_bytes(&mut random);
    random
}
#[tokio::test(flavor = "multi_thread")]
async fn minimal() {
    let datamodel = "{ 
            Greetings{
                message:String
            }
        }";

    let mut key_material: [u8; 32] = [0; 32];
    OsRng.fill_bytes(&mut key_material);
    //let key_material = derive_pass_phrase("me", "my passphrase");

    let data_folder: PathBuf = DATA_PATH.into();
    let app = Discret::new(
        datamodel,
        "myappkey", //this key should be unique to your application and must never change once in production
        &key_material,
        data_folder,
        Configuration::default(),
    )
    .await
    .unwrap();

    let mut_result = app
        .mutate(
            r#"mutate {
                result: Greetings{
                    message: "Hello World"
                }
            }"#,
            None,
        )
        .await
        .unwrap();

    #[derive(Deserialize)]
    struct Id {
        id: String,
    }
    let parser = ResultParser::new(&mut_result).unwrap();
    let ids: Id = parser.object("result").unwrap();
    let id = ids.id;

    let mut params = Parameters::new();
    params.add("id", id.clone()).unwrap();
    let result = app
        .query(
            "query {
                Greetings(id=$id){
                    message
                }
            }",
            Some(params),
        )
        .await
        .unwrap();

    //println!("{:#?}", result);
    assert_eq!(
        result,
        "{\n\"Greetings\":[{\"message\":\"Hello World\"}]\n}"
    )
}

#[tokio::test(flavor = "multi_thread")]
async fn multicast_connect() {
    let path: PathBuf = DATA_PATH.into();
    let model = "{Person{name:String,}}";
    let key_material = random32();
    let _: Discret = Discret::new(
        model,
        "hello",
        &key_material,
        path,
        Configuration::default(),
    )
    .await
    .unwrap();

    let second_path: PathBuf = format!("{}/second", DATA_PATH).into();
    let discret2: Discret = Discret::new(
        model,
        "hello",
        &key_material,
        second_path,
        Configuration::default(),
    )
    .await
    .unwrap();
    let private_room_id = discret2.private_room();
    let mut events = discret2.subscribe_for_events().await;
    let handle = tokio::spawn(async move {
        loop {
            let event = events.recv().await;
            match event {
                Ok(e) => match e {
                    Event::RoomSynchronized(room_id) => {
                        assert_eq!(room_id, private_room_id);
                        break;
                    }
                    _ => {}
                },
                Err(e) => println!("Error {}", e),
            }
        }
    });

    let s = tokio::time::timeout(Duration::from_secs(1), handle).await;

    assert!(s.is_ok());
}

#[tokio::test(flavor = "multi_thread")]
async fn invites() {
    let path: PathBuf = DATA_PATH.into();
    let app_name = "hello";
    let model = "{Person{name:String,}}";
    let key_material = random32();
    let discret1: Discret = Discret::new(
        model,
        app_name,
        &key_material,
        path.clone(),
        Configuration::default(),
    )
    .await
    .unwrap();

    let mut param = Parameters::new();
    param
        .add("key", base64_encode(discret1.verifying_key()))
        .unwrap();
    let result = discret1
        .mutate(
            r#"mutate mut {
                sys.Room{
                    admin: [{
                        verif_key:$key
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

    #[derive(Deserialize)]
    struct Ids {
        id: String,
        authorisations: Vec<Auth>,
    }
    #[derive(Deserialize)]
    struct Auth {
        id: String,
    }
    let parser = ResultParser::new(&result).unwrap();
    let mut ids: Ids = parser.object("sys.Room").unwrap();
    let room_id = ids.id;
    let auth_id = ids.authorisations.pop().unwrap().id;

    // println!("{}", res.json);

    let mut param = Parameters::new();
    param.add("room_id", room_id.clone()).unwrap();

    discret1
        .mutate(
            r#"mutate mut {
            Person{
                room_id:$room_id
                name: "John Doe"
            }
        }"#,
            Some(param),
        )
        .await
        .unwrap();

    let invite = discret1
        .invite(
            1,
            Some(DefaultRoom {
                room: room_id.clone(),
                authorisation: auth_id,
            }),
        )
        .await
        .unwrap();

    let key_material = random32();
    let discret2: Discret = Discret::new(
        model,
        app_name,
        &key_material,
        path,
        Configuration::default(),
    )
    .await
    .unwrap();

    discret2.accept_invite(invite).await.unwrap();

    let new_room = uid_decode(&room_id).unwrap();

    let mut events = discret2.subscribe_for_events().await;
    let handle = tokio::spawn(async move {
        loop {
            let event = events.recv().await;
            match event {
                Ok(e) => match e {
                    Event::RoomSynchronized(room_id) => {
                        assert_eq!(room_id, new_room);
                        break;
                    }
                    _ => {}
                },
                Err(e) => println!("Error {}", e),
            }
        }
    });
    let s = tokio::time::timeout(Duration::from_millis(500), handle).await;
    assert!(s.is_ok());
    let query = "query{
        Person{
            name
        }
    }";
    let res1 = discret1.query(query, None).await.unwrap();
    let res2 = discret2.query(query, None).await.unwrap();
    assert_eq!(res1, res2);

    let query = "query{
        sys.AllowedPeer{
            id
            peer{
                pub_key
            }
            meeting_token
            status
        }
    }";

    #[derive(Deserialize)]
    struct Id {
        pub id: String,
    }

    let res1 = discret1.query(query, None).await.unwrap();
    let parser = ResultParser::new(&res1).unwrap();
    let ids: Vec<Id> = parser.array("sys.AllowedPeer").unwrap();
    assert_eq!(ids.len(), 2);
    assert!(ids[0].id.len() > 0);

    let res2 = discret2.query(query, None).await.unwrap();
    let parser = ResultParser::new(&res2).unwrap();
    let ids: Vec<Id> = parser.array("sys.AllowedPeer").unwrap();
    assert_eq!(ids.len(), 2);

    let query = "query{
        sys.OwnedInvite{
            id
        }
    }";

    let res1 = discret1.query(query, None).await.unwrap();
    let parser = ResultParser::new(&res1).unwrap();
    let ids: Vec<Id> = parser.array("sys.OwnedInvite").unwrap();
    assert_eq!(ids.len(), 0);

    let res2 = discret2.query(query, None).await.unwrap();
    let parser = ResultParser::new(&res2).unwrap();
    let ids: Vec<Id> = parser.array("sys.OwnedInvite").unwrap();
    assert_eq!(ids.len(), 0);

    let query = "query{
        sys.Invite{
            id
        }
    }";

    let res1 = discret1.query(query, None).await.unwrap();
    let parser = ResultParser::new(&res1).unwrap();
    let ids: Vec<Id> = parser.array("sys.Invite").unwrap();
    assert_eq!(ids.len(), 0);

    let res2 = discret2.query(query, None).await.unwrap();
    let parser = ResultParser::new(&res2).unwrap();
    let ids: Vec<Id> = parser.array("sys.Invite").unwrap();
    assert_eq!(ids.len(), 0);
}
