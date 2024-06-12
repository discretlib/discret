use std::{path::PathBuf, time::Duration};

use discret::{
    base64_encode, uid_decode, Configuration, DefaultRoom, Discret, Event, Parameters,
    ParametersAdd,
};
use rand::{rngs::OsRng, RngCore};
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

    let id = &mut_result.ids[0].uid;

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
    let res = discret1
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

    let ids = res.ids.first().unwrap();
    let room_id = ids.uid.clone();
    let auth_id = ids.childs.first().unwrap().uid.clone();

    let mut param = Parameters::new();
    param.add("room_id", room_id.clone()).unwrap();

    discret1
        .mutate(
            r#"mutate mut {
            Person{
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
}
