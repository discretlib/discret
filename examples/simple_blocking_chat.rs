use std::{
    io,
    path::PathBuf,
    thread::{self},
};

use discret::{
    derive_pass_phrase, zero_uid, Configuration, DiscretBlocking, Parameters, ParametersAdd,
    ResultParser,
};
use serde::Deserialize;

//application unique identifier
const APPLICATION_KEY: &str = "github.com/discretlib/rust_example_simple_chat";

///
/// a basic chat that uses the Blocking API
///
fn main() {
    //define a datamodel
    let model = "chat {
        Message{
            content:String
        }
    }";
    //this struct is used to parse the query result
    #[derive(Deserialize)]
    struct Chat {
        pub id: String,
        pub mdate: i64,
        pub content: String,
    }

    let path: PathBuf = "test_data".into(); //where data is stored

    //used to derives all necessary secrets
    let key_material: [u8; 32] = derive_pass_phrase("my login", "my password");

    //start the discret application
    let app = DiscretBlocking::new(
        model,
        APPLICATION_KEY,
        &key_material,
        path,
        Configuration::default(),
    )
    .unwrap();

    //listen for events
    let mut events = app.subscribe_for_events();
    let event_app = app.clone();
    thread::spawn(move || {
        let mut last_date = 0;
        let mut last_id = zero_uid();

        let private_room: String = event_app.private_room();
        while let Ok(event) = events.blocking_recv() {
            match event {
                //triggered when data is modified
                discret::Event::DataChanged(_) => {
                    let mut param = Parameters::new();
                    param.add("mdate", last_date).unwrap();
                    param.add("id", last_id.clone()).unwrap();
                    param.add("room_id", private_room.clone()).unwrap();

                    //get the latest data, the result is in the JSON format
                    let result: String = event_app
                        .query(
                            "query {
                                res: chat.Message(
                                    order_by(mdate asc, id asc), 
                                    after($mdate, $id),
                                    room_id = $room_id
                                ) {
                                        id
                                        mdate
                                        content
                                }
                            }",
                            Some(param),
                        )
                        .unwrap();
                    let mut query_result = ResultParser::new(&result).unwrap();
                    let res: Vec<Chat> = query_result.take_array("res").unwrap();
                    for msg in res {
                        last_date = msg.mdate;
                        last_id = msg.id;
                        println!("you said: {}", msg.content);
                    }
                }
                _ => {} //ignores other events
            }
        }
    });

    //data is inserted in your private room
    let private_room: String = app.private_room();
    let stdin = io::stdin();
    let mut line = String::new();
    println!("{}", "Write Something!");
    loop {
        stdin.read_line(&mut line).unwrap();
        if line.starts_with("/q") {
            break;
        }
        line.pop();
        let mut params = Parameters::new();
        params.add("message", line.clone()).unwrap();
        params.add("room_id", private_room.clone()).unwrap();
        app.mutate(
            "mutate {
                chat.Message {
                    room_id:$room_id 
                    content: $message 
                }
            }",
            Some(params),
        )
        .unwrap();
        line.clear();
    }
}
