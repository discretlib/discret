use std::path::PathBuf;

use discret::{Configuration, Discret, Parameters, ParametersAdd};
use rand::{rngs::OsRng, RngCore};
const DATA_PATH: &str = "test_data/tests/";

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
            r#"mutation {
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
