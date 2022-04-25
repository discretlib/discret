use crate::cryptography;
use object_pool::{Pool, Reusable};
use rusqlite::Connection;
use std::{fs, path::PathBuf};

/*
let hook = |_: Action, _: &str, _: &str, _: i64| {
    if let Ok(ref mut mutex) = locked.try_lock() {
        **mutex = ();
    }
};

db.update_hook(Some(hook)); */

pub struct Database {
    pub file_name: String,
    path: PathBuf,
    secret: String,
    pool: Pool<Connection>,
}

impl Database {
    pub fn new(data_folder: impl Into<PathBuf>, secret: [u8; 32]) -> Self {
        //this key format avoids additional key derivation from SQLCipher
        let sqlcipher_key = format!("x'{}'", hex::encode(&secret));

        //hash the secret to get the database file name
        let file_name = hex::encode(cryptography::hash(&secret));

        let subfolder = &file_name[0..2];
        let mut path = data_folder.into();
        path.push(subfolder);

        let _c = fs::create_dir_all(&path).expect(
            format!(
                "Could not create create database folder path: {} ",
                &path.canonicalize().unwrap().to_str().unwrap()
            )
            .as_str(),
        );
        path.push(&file_name);

        Database {
            file_name,
            path,
            secret: sqlcipher_key,
            //start with zero capacity so the init closure  is never called
            //this avoid potential io error during initialisation
            pool: Pool::new(0, || Connection::open_in_memory().unwrap()),
        }
    }

    pub fn exist(&self) -> bool {
        self.path.exists()
    }

    pub fn pool_len(&self) -> usize {
        self.pool.len()
    }

    pub fn get_connection(&self) -> Result<Reusable<Connection>, rusqlite::Error> {
        let conn = self.pool.try_pull();
        match conn {
            Some(i) => Ok(i),
            None => {
                let newconn = self.create_connection()?;
                self.pool.attach(newconn);
                let newreusable = self.pool.try_pull().unwrap_or_else(|| {
                    panic!("This should never occur, we just put a new connection in the pool!")
                });
                Ok(newreusable)
            }
        }
    }

    fn create_connection(&self) -> Result<Connection, rusqlite::Error> {
        let conn = rusqlite::Connection::open(self.path.clone())?;
        {
            let query = format!("PRAGMA key=\"{}\" ", self.secret);
            let res: String = conn.query_row(&query, [], |row| row.get(0))?;
            assert_eq!("ok", res)
        }
        Ok(conn)
    }
}

#[cfg(test)]
mod tests {
    use super::Database;
    use crate::cryptography;
    use rusqlite::params;
    #[test]
    fn test_pool_reuse() -> Result<(), rusqlite::Error> {
        let secret: [u8; 3] = [1, 2, 3];

        let poule = Database::new("test/data/", cryptography::hash(&secret));
        // println!("Poule size  {:?}", poule.len());
        //brace to quickly push the Connection out of scope
        assert_eq!(poule.pool_len(), 0);
        {
            let conn = poule.get_connection()?;
            assert_eq!(poule.pool_len(), 0);
            let _t: i32 = conn.query_row("SELECT $1", [42], |row| row.get(0))?;
        }
        assert_eq!(poule.pool_len(), 1);
        {
            let conn = poule.get_connection()?;
            assert_eq!(poule.pool_len(), 0);
            let _t: i32 = conn.query_row("SELECT $1", [42], |row| row.get(0))?;
        }
        assert_eq!(poule.pool_len(), 1);
        Ok(())
    }

    struct Person {
        id: i32,
        name: String,
    }

    #[test]
    fn test_pool_encryption() -> Result<(), rusqlite::Error> {
        let db_path = "test/data/";
        let secret: [u8; 4] = [1, 2, 3, 4];

        let poule = Database::new(db_path, cryptography::hash(&secret));
        // println!("Poule size  {:?}", poule.len());
        //brace to quickly push the Connection out of scope
        {
            let good_conn_1 = poule.get_connection()?;
            good_conn_1.execute(
                "CREATE TABLE IF NOT EXISTS person (
                    id    INTEGER PRIMARY KEY,
                    name  TEXT NOT NULL
                )",
                [], // empty list of parameters.
            )?;
            good_conn_1.execute("DELETE FROM person", [])?;
            let me = Person {
                id: 0,
                name: "Steven".to_string(),
            };
            good_conn_1.execute("INSERT INTO person (name) VALUES (?1)", params![me.name])?;

            let good_conn_2 = poule.get_connection()?;

            let mut stmt = good_conn_2.prepare("SELECT id, name FROM person")?;
            let person_iter = stmt.query_map([], |row| {
                Ok(Person {
                    id: row.get(0)?,
                    name: row.get(1)?,
                })
            })?;

            for person in person_iter {
                let p = person.unwrap();
                assert_eq!(p.id, 1);
                assert_eq!(p.name, "Steven");
            }

            let bad_conn_1 = poule.get_connection()?;
            //setup a bad passwpord
            let query = "PRAGMA key=\"x'00081d171425a36312fa058d8712d5d05135a991ec20351ce9d65cdb19a05432'\" ";
            let res: String = bad_conn_1.query_row(&query, [], |row| row.get(0))?;
            assert_eq!("ok", res);

            let result: Result<i32, rusqlite::Error> =
                bad_conn_1.query_row("SELECT id FROM person", [], |row| row.get(0));
            let error_message = result
                .expect_err("Should have failed due to wrong database password")
                .to_string();
            assert_eq!("file is not a database", error_message);
        }
        assert_eq!(poule.pool_len(), 3);

        Ok(())
    }
}
