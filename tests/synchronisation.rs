use std::{ops::Deref, path::PathBuf, time::Duration};

use discret::{
    base64_encode, generate_x509_certificate, hash, Beacon, BeaconConfig, Configuration,
    DefaultRoom, Discret, Event, LogService, Parameters, ParametersAdd, ResultParser,
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

    let s = tokio::time::timeout(Duration::from_secs(2), handle).await;

    assert!(s.is_ok());
}

#[tokio::test(flavor = "multi_thread")]
async fn beacon_ipv4_connect() {
    let path: PathBuf = DATA_PATH.into();
    let model = "{Person{name:String,}}";
    let key_material = random32();
    let certificate = generate_x509_certificate("sample.org");
    let cert_hash = hash(certificate.cert.der().deref());
    let cert_hash = base64_encode(&cert_hash);
    let der: Vec<u8> = certificate.cert.der().deref().to_vec();
    let pks_der: Vec<u8> = certificate.key_pair.serialize_der();

    let port = 4242;
    let hostname = format!("127.0.0.1:{}", port); //::1
    let beacon_conf = BeaconConfig {
        hostname,
        cert_hash,
    };
    let beacons_def = vec![beacon_conf];

    let config = Configuration {
        enable_multicast: false,
        beacons: beacons_def,
        ..Default::default()
    };
    let _ = Beacon::start(port, port + 1, der, pks_der, LogService::start(), 10).unwrap();

    let _: Discret = Discret::new(model, "hello", &key_material, path, config.clone())
        .await
        .unwrap();

    let second_path: PathBuf = format!("{}/second", DATA_PATH).into();
    let discret2: Discret = Discret::new(model, "hello", &key_material, second_path, config)
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

    let s = tokio::time::timeout(Duration::from_secs(4), handle).await;

    assert!(s.is_ok());
}

#[tokio::test(flavor = "multi_thread")]
async fn beacon_ipv6_connect() {
    let path: PathBuf = DATA_PATH.into();
    let model = "{Person{name:String,}}";
    let key_material = random32();
    let certificate = generate_x509_certificate("sample.org");
    let cert_hash = hash(certificate.cert.der().deref());
    let cert_hash = base64_encode(&cert_hash);
    let der: Vec<u8> = certificate.cert.der().deref().to_vec();
    let pks_der: Vec<u8> = certificate.key_pair.serialize_der();

    let port = 4252;
    let hostname = format!("::1:{}", port); //::1
    let beacon_conf = BeaconConfig {
        hostname,
        cert_hash,
    };
    let beacons_def = vec![beacon_conf];

    let config = Configuration {
        enable_multicast: false,
        beacons: beacons_def,
        ..Default::default()
    };
    let _ = Beacon::start(port - 1, port, der, pks_der, LogService::start(), 10).unwrap();

    let _: Discret = Discret::new(model, "hello", &key_material, path, config.clone())
        .await
        .unwrap();

    let second_path: PathBuf = format!("{}/second", DATA_PATH).into();
    let discret2: Discret = Discret::new(model, "hello", &key_material, second_path, config)
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

    let s = tokio::time::timeout(Duration::from_secs(4), handle).await;

    assert!(s.is_ok());
}

#[tokio::test(flavor = "multi_thread")]
async fn invites() {
    let path: PathBuf = DATA_PATH.into();
    let app_name = "hello";
    let model = "{Person{name:String,}}";
    let key_material = random32();
    let config = Configuration {
        multicast_ipv4_group: "224.0.0.224:22403".to_string(),
        ..Default::default()
    };

    let discret1: Discret =
        Discret::new(model, app_name, &key_material, path.clone(), config.clone())
            .await
            .unwrap();

    let mut param = Parameters::new();
    param.add("key", discret1.verifying_key()).unwrap();
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
    let mut parser = ResultParser::new(&result).unwrap();
    let mut ids: Ids = parser.take_object("sys.Room").unwrap();
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
        .invite(Some(DefaultRoom {
            room: room_id.clone(),
            authorisation: auth_id,
        }))
        .await
        .unwrap();

    println!("inviter {}", discret1.verifying_key());

    let key_material = random32();
    let discret2: Discret = Discret::new(model, app_name, &key_material, path, config.clone())
        .await
        .unwrap();

    discret2.accept_invite(invite).await.unwrap();
    println!("Accept Invite {}", discret2.verifying_key());

    let new_room = room_id;

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
    tokio::time::timeout(Duration::from_millis(3000), handle)
        .await
        .unwrap()
        .unwrap();

    tokio::time::sleep(Duration::from_millis(100)).await;
    //allowedpeers can be synchronized after room synchronisation so we wati for them a little
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
    let mut parser = ResultParser::new(&res1).unwrap();
    let ids: Vec<Id> = parser.take_array("sys.AllowedPeer").unwrap();
    assert_eq!(ids.len(), 2);
    assert!(ids[0].id.len() > 0);

    let res2 = discret2.query(query, None).await.unwrap();
    let mut parser = ResultParser::new(&res2).unwrap();
    let ids: Vec<Id> = parser.take_array("sys.AllowedPeer").unwrap();
    assert_eq!(ids.len(), 2);

    let query = "query{
        sys.OwnedInvite{
            id
        }
    }";

    let res1 = discret1.query(query, None).await.unwrap();
    let mut parser = ResultParser::new(&res1).unwrap();
    let ids: Vec<Id> = parser.take_array("sys.OwnedInvite").unwrap();
    assert_eq!(ids.len(), 0);

    let res2 = discret2.query(query, None).await.unwrap();
    let mut parser = ResultParser::new(&res2).unwrap();
    let ids: Vec<Id> = parser.take_array("sys.OwnedInvite").unwrap();
    assert_eq!(ids.len(), 0);

    let query = "query{
        sys.Invite{
            id
        }
    }";

    let res1 = discret1.query(query, None).await.unwrap();
    let mut parser = ResultParser::new(&res1).unwrap();
    let ids: Vec<Id> = parser.take_array("sys.Invite").unwrap();
    assert_eq!(ids.len(), 0);

    let res2 = discret2.query(query, None).await.unwrap();
    let mut parser = ResultParser::new(&res2).unwrap();
    let ids: Vec<Id> = parser.take_array("sys.Invite").unwrap();
    assert_eq!(ids.len(), 0);
}

#[tokio::test(flavor = "multi_thread")]
async fn invites_beacon_ipv6() {
    let path: PathBuf = DATA_PATH.into();
    let app_name = "hello";
    let model = "{Person{name:String,}}";
    let key_material = random32();
    let certificate = generate_x509_certificate("sample.org");
    let cert_hash = hash(certificate.cert.der().deref());
    let cert_hash = base64_encode(&cert_hash);
    let der: Vec<u8> = certificate.cert.der().deref().to_vec();
    let pks_der: Vec<u8> = certificate.key_pair.serialize_der();

    let port = 4262;
    let hostname = format!("::1:{}", port); //::1
    let beacon_conf = BeaconConfig {
        hostname,
        cert_hash,
    };
    let beacons_def = vec![beacon_conf];

    let config = Configuration {
        enable_multicast: false,
        beacons: beacons_def,
        ..Default::default()
    };
    let _ = Beacon::start(port - 1, port, der, pks_der, LogService::start(), 10).unwrap();

    let discret1: Discret =
        Discret::new(model, app_name, &key_material, path.clone(), config.clone())
            .await
            .unwrap();

    let mut param = Parameters::new();
    param.add("key", discret1.verifying_key()).unwrap();
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
    let mut parser = ResultParser::new(&result).unwrap();
    let mut ids: Ids = parser.take_object("sys.Room").unwrap();
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
        .invite(Some(DefaultRoom {
            room: room_id.clone(),
            authorisation: auth_id,
        }))
        .await
        .unwrap();

    let key_material = random32();
    let discret2: Discret = Discret::new(model, app_name, &key_material, path, config.clone())
        .await
        .unwrap();

    discret2.accept_invite(invite).await.unwrap();

    let new_room = room_id;

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
    tokio::time::timeout(Duration::from_millis(3000), handle)
        .await
        .unwrap()
        .unwrap();
    //allowedpeers can be synchronized after room synchronisation so we wati for them a little
    tokio::time::sleep(Duration::from_millis(100)).await;

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
    let mut parser = ResultParser::new(&res1).unwrap();
    let ids: Vec<Id> = parser.take_array("sys.AllowedPeer").unwrap();
    assert_eq!(ids.len(), 2);
    assert!(ids[0].id.len() > 0);

    let res2 = discret2.query(query, None).await.unwrap();
    let mut parser = ResultParser::new(&res2).unwrap();
    let ids: Vec<Id> = parser.take_array("sys.AllowedPeer").unwrap();
    assert_eq!(ids.len(), 2);

    let query = "query{
        sys.OwnedInvite{
            id
        }
    }";

    let res1 = discret1.query(query, None).await.unwrap();
    let mut parser = ResultParser::new(&res1).unwrap();
    let ids: Vec<Id> = parser.take_array("sys.OwnedInvite").unwrap();
    assert_eq!(ids.len(), 0);

    let res2 = discret2.query(query, None).await.unwrap();
    let mut parser = ResultParser::new(&res2).unwrap();
    let ids: Vec<Id> = parser.take_array("sys.OwnedInvite").unwrap();
    assert_eq!(ids.len(), 0);

    let query = "query{
        sys.Invite{
            id
        }
    }";

    let res1 = discret1.query(query, None).await.unwrap();
    let mut parser = ResultParser::new(&res1).unwrap();
    let ids: Vec<Id> = parser.take_array("sys.Invite").unwrap();
    assert_eq!(ids.len(), 0);

    let res2 = discret2.query(query, None).await.unwrap();
    let mut parser = ResultParser::new(&res2).unwrap();
    let ids: Vec<Id> = parser.take_array("sys.Invite").unwrap();
    assert_eq!(ids.len(), 0);
}

#[tokio::test(flavor = "multi_thread")]
async fn new_peers_from_room() {
    let path: PathBuf = DATA_PATH.into();
    let app_name = "hello";
    let model = "{Person{name:String,}}";
    let key_material = random32();
    let config = Configuration {
        multicast_ipv4_group: "224.0.0.224:22404".to_string(),
        // announce_frequency_in_ms: 100,
        ..Default::default()
    };
    let discret1: Discret =
        Discret::new(model, app_name, &key_material, path.clone(), config.clone())
            .await
            .unwrap();

    let mut param = Parameters::new();
    param.add("key", discret1.verifying_key()).unwrap();
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
    let mut parser = ResultParser::new(&result).unwrap();
    let mut ids: Ids = parser.take_object("sys.Room").unwrap();
    let new_room = ids.id;
    let auth_id = ids.authorisations.pop().unwrap().id;

    // println!("{}", res.json);

    let mut param = Parameters::new();
    param.add("room_id", new_room.clone()).unwrap();

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
        .invite(Some(DefaultRoom {
            room: new_room.clone(),
            authorisation: auth_id.clone(),
        }))
        .await
        .unwrap();

    let key_material = random32();
    let discret2: Discret =
        Discret::new(model, app_name, &key_material, path.clone(), config.clone())
            .await
            .unwrap();

    discret2.accept_invite(invite).await.unwrap();

    let mut events = discret2.subscribe_for_events().await;
    let new_r = new_room.clone();
    let handle2 = tokio::spawn(async move {
        loop {
            let event = events.recv().await;
            match event {
                Ok(e) => match e {
                    Event::RoomSynchronized(room_id) => {
                        assert_eq!(room_id, new_r);
                        break;
                    }
                    _ => {}
                },
                Err(e) => println!("Error {}", e),
            }
        }
    });

    let key_material = random32();
    let discret3: Discret = Discret::new(model, app_name, &key_material, path, config.clone())
        .await
        .unwrap();
    let invite = discret1
        .invite(Some(DefaultRoom {
            room: new_room.clone(),
            authorisation: auth_id,
        }))
        .await
        .unwrap();

    discret3.accept_invite(invite.clone()).await.unwrap();
    let mut events = discret3.subscribe_for_events().await;
    let handle3 = tokio::spawn(async move {
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

    let s = tokio::time::timeout(Duration::from_millis(2000), handle2).await;
    assert!(s.is_ok());

    let s = tokio::time::timeout(Duration::from_millis(2000), handle3).await;
    assert!(s.is_ok());

    let query = "query{
        Person{
            name
        }
    }";
    let res1 = discret1.query(query, None).await.unwrap();
    let res2 = discret2.query(query, None).await.unwrap();
    let res3 = discret3.query(query, None).await.unwrap();
    assert_eq!(res1, res2);
    assert_eq!(res1, res3);

    tokio::time::sleep(Duration::from_millis(20)).await;
    //allowedpeers can be synchronized after room synchronisation so we wati for them a little

    let query = r#"query{
        sys.AllowedPeer(status="pending"){
            id
        }
    }"#;

    #[derive(Deserialize)]
    struct Id {
        pub id: String,
    }
    let res1 = discret1.query(query, None).await.unwrap();
    let mut parser = ResultParser::new(&res1).unwrap();
    let ids: Vec<Id> = parser.take_array("sys.AllowedPeer").unwrap();
    assert_eq!(ids.len(), 0);

    let res2 = discret2.query(query, None).await.unwrap();
    let mut parser = ResultParser::new(&res2).unwrap();
    let ids: Vec<Id> = parser.take_array("sys.AllowedPeer").unwrap();
    assert_eq!(ids.len(), 1);
    assert!(ids[0].id.len() > 0);

    let res3 = discret3.query(query, None).await.unwrap();
    let mut parser = ResultParser::new(&res3).unwrap();
    let ids: Vec<Id> = parser.take_array("sys.AllowedPeer").unwrap();
    assert_eq!(ids.len(), 1);
    assert!(ids[0].id.len() > 0);
}

#[tokio::test(flavor = "multi_thread")]
async fn multiple_entities() {
    let path: PathBuf = DATA_PATH.into();
    let model = "{
        Person{
            name:String,
            parents:[Person],
            pet : Pet
        }

        Pet {
            name: String
        }
    
    }";
    let key_material = random32();
    let discret1: Discret = Discret::new(
        model,
        "hello",
        &key_material,
        path,
        Configuration::default(),
    )
    .await
    .unwrap();

    let mut param = Parameters::new();
    param.add("room_id", discret1.private_room()).unwrap();

    let mutation = r#"
            mutate {
                P1: Person {
                    room_id:$room_id
                    name : "John"
                    parents:  [ {name : "John Mother"} ,{ name:"John Father" pet:{ name:"Kiki" }}]
                    pet: { name:"Truffle"}
                }
                P2: Person {
                    room_id:$room_id
                    name : "Ada"
                    parents:  [ {name : "Ada Mother" pet:{ name:"Lulu" }} ,{ name:"Ada Father" pet:{ name:"Waf" }}]
                } 

            } "#;
    discret1.mutate(mutation, Some(param)).await.unwrap();

    let query = "query {
        Person (order_by(name desc)) {
            id
            room_id
            name
            parents (order_by(name desc)){
                id
                room_id
                name
                pet{
                    id
                    room_id
                    name
                }
            }
            pet{
                id
                room_id
                name
            }
        }
    }";

    let res1 = discret1.query(query, None).await.unwrap();
    // println!("{}", res)
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

    tokio::time::timeout(Duration::from_secs(4), handle)
        .await
        .unwrap()
        .unwrap();

    let res2 = discret2.query(query, None).await.unwrap();
    assert_eq!(res1, res2);
}
