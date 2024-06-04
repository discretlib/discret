use std::{io, path::PathBuf};

use discret::{
    default_uid, derive_pass_phrase, uid_encode, Configuration, Discret, Parameters, ParametersAdd,
    QueryResult,
};
use serde::Deserialize;

#[tokio::main]
async fn main() {
    //define a datamodel
    let model = "{
        Chat{
            message:String
        }
    }";
    //this struct is used to parse the query result
    #[derive(Deserialize)]
    struct Chat {
        pub id: String,
        pub mdate: i64,
        pub message: String,
    }

    let path: PathBuf = "test_data".into(); //where data is stored

    //value used to derives all necessary secrets
    let key_material = derive_pass_phrase("my login", "my password");

    //start the discret application
    let app = Discret::new(
        model,
        "example_chat",
        &key_material,
        path,
        Configuration::default(),
    )
    .await
    .unwrap();

    //listen for events
    let mut events = app.subscribe_for_events().await;
    let eapp = app.clone();
    tokio::spawn(async move {
        let mut last_date = 0;
        let mut last_id = uid_encode(&default_uid());

        //data will is inserted in your private room
        let private_room = uid_encode(&eapp.private_room());
        while let Ok(event) = events.recv().await {
            match event {
                discret::Event::DataChanged(_) => {
                    //some data was modified
                    let mut param = Parameters::new();
                    param.add("mdate", last_date).unwrap();
                    param.add("id", last_id.clone()).unwrap();
                    param.add("room_id", private_room.clone()).unwrap();

                    //get the latest data, the result is a string in the JSON format
                    let result = eapp
                        .query(
                            "query {
                                res: Chat(
                                    order_by(mdate asc, id asc), 
                                    after($mdate, $id),
                                    room_id = $room_id
                                ) {
                                        id
                                        mdate
                                        message
                                }
                            }",
                            Some(param),
                        )
                        .await
                        .unwrap();
                    let query_result = QueryResult::new(&result).unwrap();
                    let res: Vec<Chat> = query_result.get("res").unwrap();
                    for msg in res {
                        last_date = msg.mdate;
                        last_id = msg.id;
                        println!("you said: {}", msg.message);
                    }
                }
                _ => {} //ignore other e vents
            }
        }
    });

    //data is inserted in your private room
    let private_room = uid_encode(&app.private_room());
    let stdin = io::stdin();
    let mut line = String::new();
    println!("{}", "Write Something");
    loop {
        stdin.read_line(&mut line).unwrap();
        if line.starts_with("/q") {
            break;
        }
        line.pop();
        let mut param = Parameters::new();
        param.add("message", line.clone()).unwrap();
        param.add("room_id", private_room.clone()).unwrap();
        app.mutate(
            "mutate {
                Chat{
                    room_id:$room_id 
                    message: $message 
                }
            }",
            Some(param),
        )
        .await
        .unwrap();
        line.clear();
    }
}
