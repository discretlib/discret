use std::path::PathBuf;

use discret::{derive_pass_phrase, Configuration, Discret, Parameters, ParametersAdd};
use rand::{rngs::OsRng, RngCore};
use serde::{Deserialize, Serialize};
const DATA_PATH: &str = "test_data/tests/";

#[derive(Serialize, Deserialize)]
struct Result {
    result: Id,
}
#[derive(Serialize, Deserialize)]
struct Id {
    id: String,
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
        "my app",
        datamodel,
        &key_material,
        data_folder,
        Configuration::default(),
    )
    .await
    .unwrap();

    let mutation = app
        .mutate(
            r#"mutation {
                result: Greetings{
                    message: "Hello World"
                }
            }"#,
            None,
        )
        .await
        .unwrap();

    let res: Result = serde_json::from_str(&mutation).unwrap();
    println!("'{}'", &res.result.id);
    let mut params = Parameters::new();
    params.add("id", res.result.id).unwrap();
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

    println!("{:#?}", result);
    // assert_eq!(
    //     result,
    //     "{\n\"Greetings\":[{\"message\":\"Hello World\"}]\n}"
    // )
}
