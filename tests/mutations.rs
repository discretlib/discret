use std::path::PathBuf;

use discret::{Configuration, Discret, Parameters, ParametersAdd, ResultParser};
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
    let mut parser = ResultParser::new(&mut_result).unwrap();
    let ids: Id = parser.take_object("result").unwrap();
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
async fn batch_insert() {
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

    let query = r#"mutate {
                result: Greetings{
                    message: $message
                }
            }"#;

    let num_message = 100;

    let (sender, mut receiver) = app.mutation_stream();

    let result_task = tokio::spawn(async move {
        while let Some(msg) = receiver.recv().await {
            if let Err(e) = msg {
                println!("{}", e);
            }
        }
    });

    for i in 0..num_message {
        let mut param = Parameters::new();
        let _ = param.add("message", format!("hello world {}", i));
        let _ = sender.send((query.to_string(), Some(param))).await;
    }

    // tokio::time::sleep(Duration::from_millis(2000)).await;

    drop(sender);
    result_task.await.unwrap();

    let result = app
        .query(
            "query {
                Greetings (order_by(message asc)){
                    message
                }
            }",
            None,
        )
        .await
        .unwrap();
    #[derive(Deserialize)]
    struct Messages {
        pub message: String,
    }
    let mut parser = ResultParser::new(&result).unwrap();
    let msg: Vec<Messages> = parser.take_array("Greetings").unwrap();
    assert_eq!(msg.len(), num_message);
    assert_eq!(&msg[0].message, "hello world 0");
}
