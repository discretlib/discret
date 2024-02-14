use std::time::SystemTime;

use crate::cryptography::{base64_decode, base64_encode};

use super::{edge_table::Edge, node_table::Node, synch_log::DailySynchLog, Result};

use rand::{rngs::OsRng, RngCore};
use rusqlite::{functions::FunctionFlags, Connection, OptionalExtension};
use zstd::{bulk::compress, bulk::decompress};

//pub type Result<T> = std::result::Result<T, Error>;

//Maximum allowed size for a row
pub const MAX_ROW_LENTGH: usize = 32768; //32kb

//min numbers of char in an id //policy
pub const DB_ID_MIN_SIZE: usize = 16;

//allows for storing a public key in the id
pub const DB_ID_MAX_SIZE: usize = 33;

pub struct RowFlag {}
impl RowFlag {
    //data is only soft deleted to avoid synchronization conflicts
    pub const DELETED: i8 = 0b0000001;
    //if disabled, a new version will be inserted when updating, keeping the full history.
    pub const KEEP_HISTORY: i8 = 0b0000010;
    //index text and json field
    pub const INDEX_ON_SAVE: i8 = 0b0000100;

    pub fn is(v: i8, f: &i8) -> bool {
        v & f > 0
    }
}
// impl FromRow for i32 {
//     fn from_row() -> super::database_service::MappingFn<Self> {
//         |row| Ok(Box::new(row.get(0)?))
//     }
// }
//Size in byte of a generated database id
pub const DB_ID_SIZE: usize = 16;

//id with time on first to improve index locality
pub fn new_id(time: i64) -> Vec<u8> {
    const TIME_BYTES: usize = 4;

    let time = &time.to_be_bytes()[TIME_BYTES..];

    let mut whole: [u8; DB_ID_SIZE] = [0; DB_ID_SIZE];
    let (one, two) = whole.split_at_mut(time.len());

    one.copy_from_slice(time);
    OsRng.fill_bytes(two);

    whole.to_vec()
}

pub fn is_valid_id(id: &Vec<u8>) -> bool {
    let v = id.len();

    (DB_ID_MIN_SIZE..=DB_ID_MAX_SIZE).contains(&v)
}

pub fn now() -> i64 {
    SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_millis()
        .try_into()
        .unwrap()
}

pub fn is_initialized(conn: &Connection) -> Result<bool> {
    let initialised: Option<String> = conn
        .query_row(
            "SELECT name FROM sqlite_schema WHERE type IN ('table','view') AND name = 'node_sys'",
            [],
            |row| row.get(0),
        )
        .optional()?;
    Ok(initialised.is_some())
}

//initialise database and create temporary views
pub fn prepare_connection(conn: &Connection) -> Result<()> {
    add_compression_function(conn)?;
    add_json_data_function(conn)?;
    add_base64_function(conn)?;

    if !is_initialized(conn)? {
        conn.execute("BEGIN TRANSACTION", [])?;
        Node::create_table(conn)?;
        Edge::create_table(conn)?;
        DailySynchLog::create_table(conn)?;
        conn.execute("COMMIT", [])?;
    }
    Node::create_temporary_view(conn)?;
    Edge::create_temporary_view(conn)?;
    Ok(())
}

//errors for the user defined function added to sqlite
#[derive(thiserror::Error, Debug)]
pub enum FunctionError {
    #[error("Invalid data type only TEXT and BLOB can be compressed")]
    InvalidCompressType,
    #[error("Invalid data type only BLOB can be decompressed")]
    InvalidDeCompressType,
    #[error("Invalid data type only TEXT can be used for json_data")]
    InvalidJSONType,
    #[error("{0}")]
    CompressedSizeError(String),
}

fn extract_json(val: serde_json::Value, buff: &mut String) -> rusqlite::Result<()> {
    match val {
        serde_json::Value::String(v) => {
            buff.push_str(&v);
            buff.push('\n');
            Ok(())
        }
        serde_json::Value::Array(arr) => {
            for v in arr {
                extract_json(v, buff)?;
            }
            Ok(())
        }
        serde_json::Value::Object(map) => {
            for v in map {
                extract_json(v.1, buff)?;
            }
            Ok(())
        }
        _ => Ok(()),
    }
}

//extract JSON textual data
pub fn add_json_data_function(db: &Connection) -> rusqlite::Result<()> {
    db.create_scalar_function(
        "json_data",
        1,
        FunctionFlags::SQLITE_UTF8 | FunctionFlags::SQLITE_DETERMINISTIC,
        move |ctx| {
            assert_eq!(ctx.len(), 1, "called with unexpected number of arguments");

            let data = ctx.get_raw(0).as_str_or_null()?;

            let mut extracted = String::new();
            let result = match data {
                Some(json) => {
                    let v: serde_json::Value = serde_json::from_str(json)
                        .map_err(|e| rusqlite::Error::UserFunctionError(e.into()))?;
                    extract_json(v, &mut extracted)?;
                    Some(extracted)
                }
                None => None,
            };

            Ok(result)
        },
    )?;

    Ok(())
}

//extract JSON textual data
pub fn add_base64_function(db: &Connection) -> rusqlite::Result<()> {
    db.create_scalar_function(
        "base64_encode",
        1,
        FunctionFlags::SQLITE_UTF8 | FunctionFlags::SQLITE_DETERMINISTIC,
        move |ctx| {
            assert_eq!(ctx.len(), 1, "called with unexpected number of arguments");

            let blob = ctx.get_raw(0).as_blob_or_null()?;

            let result = blob.map(base64_encode);

            Ok(result)
        },
    )?;

    db.create_scalar_function(
        "base64_decode",
        1,
        FunctionFlags::SQLITE_UTF8 | FunctionFlags::SQLITE_DETERMINISTIC,
        move |ctx| {
            assert_eq!(ctx.len(), 1, "called with unexpected number of arguments");

            let str = ctx.get_raw(0).as_str_or_null()?;

            let result = match str {
                Some(data) => {
                    let val = base64_decode(data.as_bytes());
                    match val {
                        Ok(e) => Some(e),
                        Err(_) => None,
                    }
                }
                None => None,
            };

            Ok(result)
        },
    )?;

    Ok(())
}

//Compression functions using zstd
// compress: compress TEXT or BLOG type
// decompress: decompress BLOG into a BLOB
// decompress_text: decompress BLOB into TEXT
pub fn add_compression_function(db: &Connection) -> rusqlite::Result<()> {
    const COMPRESSED: u8 = 1;
    db.create_scalar_function(
        "compress",
        1,
        FunctionFlags::SQLITE_UTF8 | FunctionFlags::SQLITE_DETERMINISTIC,
        move |ctx| {
            assert_eq!(ctx.len(), 1, "called with unexpected number of arguments");
            const COMPRESSION_LEVEL: i32 = 3;

            let data = ctx.get_raw(0);
            let data_type = data.data_type();

            match data_type {
                rusqlite::types::Type::Text => {
                    let text = data
                        .as_str()
                        .map_err(|e| rusqlite::Error::UserFunctionError(e.into()))?;
                    let compressed = compress(text.as_bytes(), COMPRESSION_LEVEL)
                        .map_err(|e| rusqlite::Error::UserFunctionError(e.into()))?;

                    let mut result;
                    if text.as_bytes().len() <= compressed.len() {
                        result = vec![0];
                        result.extend(text.as_bytes());
                    } else {
                        result = vec![COMPRESSED];
                        result.extend(compressed);
                    }

                    Ok(Some(result))
                }
                rusqlite::types::Type::Blob => {
                    let data = data
                        .as_blob()
                        .map_err(|e| rusqlite::Error::UserFunctionError(e.into()))?;
                    let compressed = compress(data, COMPRESSION_LEVEL)
                        .map_err(|e| rusqlite::Error::UserFunctionError(e.into()))?;

                    let mut result;
                    if data.len() <= compressed.len() {
                        result = vec![0];
                        result.extend(data);
                    } else {
                        result = vec![COMPRESSED];
                        result.extend(compressed);
                    }

                    Ok(Some(result))
                }
                rusqlite::types::Type::Null => Ok(None),
                _ => Err(rusqlite::Error::UserFunctionError(
                    FunctionError::InvalidCompressType.into(),
                )),
            }
        },
    )?;

    db.create_scalar_function(
        "decompress",
        1,
        FunctionFlags::SQLITE_UTF8 | FunctionFlags::SQLITE_DETERMINISTIC,
        move |ctx| {
            assert_eq!(ctx.len(), 1, "called with unexpected number of arguments");

            let data = ctx.get_raw(0);
            let data_type = data.data_type();

            match data_type {
                rusqlite::types::Type::Blob => {
                    let dat = data
                        .as_blob()
                        .map_err(|e| rusqlite::Error::UserFunctionError(e.into()))?;

                    if dat[0] != COMPRESSED {
                        Ok(Some(dat[1..].to_vec()))
                    } else {
                        let data = &dat[1..];
                        let size = zstd::zstd_safe::get_frame_content_size(data).map_err(|e| {
                            rusqlite::Error::UserFunctionError(
                                FunctionError::CompressedSizeError(e.to_string()).into(),
                            )
                        })?;
                        match size {
                            Some(siz) => {
                                let decomp = decompress(data, siz as usize)
                                    .map_err(|e| rusqlite::Error::UserFunctionError(e.into()))?;
                                Ok(Some(decomp))
                            }
                            None => Err(rusqlite::Error::UserFunctionError(
                                FunctionError::CompressedSizeError("Empty size".to_string()).into(),
                            )),
                        }
                    }
                }
                rusqlite::types::Type::Null => Ok(None),
                _ => Err(rusqlite::Error::UserFunctionError(
                    FunctionError::InvalidDeCompressType.into(),
                )),
            }
        },
    )?;

    db.create_scalar_function(
        "decompress_text",
        1,
        FunctionFlags::SQLITE_UTF8 | FunctionFlags::SQLITE_DETERMINISTIC,
        move |ctx| {
            assert_eq!(ctx.len(), 1, "called with unexpected number of arguments");

            let data = ctx.get_raw(0);
            let data_type = data.data_type();

            match data_type {
                rusqlite::types::Type::Blob => {
                    let dat = data
                        .as_blob()
                        .map_err(|e| rusqlite::Error::UserFunctionError(e.into()))?;

                    if dat[0] != COMPRESSED {
                        let data = &dat[1..];
                        let text = std::str::from_utf8(data)
                            .map_err(|e| rusqlite::Error::UserFunctionError(e.into()))?
                            .to_string();
                        Ok(Some(text))
                    } else {
                        let data = &dat[1..];
                        let size = zstd::zstd_safe::get_frame_content_size(data).map_err(|e| {
                            rusqlite::Error::UserFunctionError(
                                FunctionError::CompressedSizeError(e.to_string()).into(),
                            )
                        })?;
                        match size {
                            Some(siz) => {
                                let data = &dat[1..];
                                let decomp = decompress(data, siz as usize)
                                    .map_err(|e| rusqlite::Error::UserFunctionError(e.into()))?;
                                let text = std::str::from_utf8(&decomp)
                                    .map_err(|e| rusqlite::Error::UserFunctionError(e.into()))?
                                    .to_string();
                                Ok(Some(text))
                            }
                            None => Err(rusqlite::Error::UserFunctionError(
                                FunctionError::CompressedSizeError("Empty size".to_string()).into(),
                            )),
                        }
                    }
                }
                rusqlite::types::Type::Null => Ok(None),
                _ => Err(rusqlite::Error::UserFunctionError(
                    FunctionError::InvalidDeCompressType.into(),
                )),
            }
        },
    )?;

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use fallible_iterator::FallibleIterator;
    use rusqlite::types::Null;
    #[test]
    fn database_id_test() {
        let time = now();

        let id1 = new_id(time);

        let id2 = new_id(time);

        assert_eq!(id1[0..3], id2[0..3]);
        assert_ne!(id1, id2);
        assert_eq!(id1.len(), DB_ID_SIZE);
    }

    #[test]
    fn compress_test() {
        let text = "hello from a larger string larger than that very large very large very large very large";
        let compressed = compress(text.as_bytes(), 3).unwrap();
        println!("size {} - {}", text.as_bytes().len(), compressed.len());

        let mut content;
        if text.as_bytes().len() <= compressed.len() {
            content = vec![0];
            content.extend(text.as_bytes());
        } else {
            content = vec![1];
            content.extend(compressed);
        }

        let bytes = &content[..];
        let result;
        if bytes[0] == 0 {
            result = bytes[1..].to_vec();
        } else {
            let compressed = &bytes[1..];
            let size = zstd::zstd_safe::get_frame_content_size(&compressed)
                .unwrap()
                .unwrap();
            result = decompress(&compressed, size as usize).unwrap();
        }

        assert_eq!(text.as_bytes(), result);
    }

    #[test]
    fn compress_function() {
        let conn = Connection::open_in_memory().unwrap();
        prepare_connection(&conn).unwrap();
        conn.execute(
            "CREATE TABLE COMPRESS (
                string BLOB,
                binary BLOB
            ) ",
            [],
        )
        .unwrap();

        let value = "Lorem ipsum dolor sit amet, consectetur adipiscing elit, sed do eiusmod tempor incididunt ut labore et dolore magna aliqua.";
        let binary = " ipsum dolor sit amet, consectetur adipiscing elit, sed do eiusmod tempor incididunt ut labore et dolore magna aliqua.".as_bytes();

        let mut stmt = conn
            .prepare("INSERT INTO COMPRESS (string, binary) VALUES (compress(?1), compress(?2))")
            .unwrap();
        stmt.execute((value, binary)).unwrap();
        stmt.execute((value, Null)).unwrap();
        stmt.execute((Null, binary)).unwrap();

        let mut stmt = conn
            .prepare(
                "
        SELECT decompress_text(string)
        FROM COMPRESS
         ",
            )
            .unwrap();

        let results: Vec<Option<String>> = stmt
            .query([])
            .unwrap()
            .map(|row| Ok(row.get(0)?))
            .collect()
            .unwrap();
        let expected: Vec<Option<String>> =
            vec![Some(value.to_string()), Some(value.to_string()), None];
        assert_eq!(results, expected);

        let mut stmt = conn
            .prepare(
                "
        SELECT decompress(binary)
        FROM COMPRESS
         ",
            )
            .unwrap();

        let results: Vec<Option<Vec<u8>>> = stmt
            .query([])
            .unwrap()
            .map(|row| Ok(row.get(0)?))
            .collect()
            .unwrap();
        let expected: Vec<Option<Vec<u8>>> =
            vec![Some(binary.to_vec()), None, Some(binary.to_vec())];
        assert_eq!(results, expected);
    }

    #[test]
    fn extract_json_test() {
        let json = r#"
        {
            "name": "John Doe",
            "age": 43,
            "phones": [
                "+44 1234567",
                "+44 2345678"
            ]
        }"#;
        let v: serde_json::Value = serde_json::from_str(json).unwrap();
        let mut buff = String::new();
        extract_json(v, &mut buff).unwrap();

        let mut expected = String::new();
        expected.push_str("John Doe\n");
        expected.push_str("+44 1234567\n");
        expected.push_str("+44 2345678\n");
        assert_eq!(buff, expected);
    }

    #[test]
    fn json_data_function() {
        let conn = Connection::open_in_memory().unwrap();
        prepare_connection(&conn).unwrap();
        conn.execute(
            "CREATE TABLE JSON (
                string BLOB
            ) ",
            [],
        )
        .unwrap();

        let json = r#"
        {
            "name": "John Doe",
            "age": 43,
            "phones": [
                "+44 1234567",
                "+44 2345678"
            ]
        }"#;

        let mut stmt = conn
            .prepare("INSERT INTO JSON (string) VALUES (compress(?1))")
            .unwrap();

        stmt.execute([json]).unwrap();
        stmt.execute([Null]).unwrap();

        let mut stmt = conn
            .prepare(
                "
        SELECT json_data(decompress_text(string))
        FROM JSON
         ",
            )
            .unwrap();

        let results: Vec<Option<String>> = stmt
            .query([])
            .unwrap()
            .map(|row| Ok(row.get(0)?))
            .collect()
            .unwrap();

        let mut extract = String::new();
        extract.push_str("John Doe\n");
        extract.push_str("+44 1234567\n");
        extract.push_str("+44 2345678\n");

        let expected: Vec<Option<String>> = vec![Some(extract), None];

        assert_eq!(results, expected);
    }
}
