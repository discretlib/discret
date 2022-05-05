use object_pool::{Pool, Reusable};
use rusqlite::Connection;
use std::path::PathBuf;

/*
let hook = |_: Action, _: &str, _: &str, _: i64| {
    if let Ok(ref mut mutex) = locked.try_lock() {
        **mutex = ();
    }
};

db.update_hook(Some(hook)); */

pub struct Database {
    path: PathBuf,
    secret: String,
    pool: Pool<Connection>,
}

impl Database {
    pub fn new(path: PathBuf, secret: [u8; 32]) -> Self {
        //this key format avoids additional key derivation from SQLCipher
        let sqlcipher_key = format!("x'{}'", hex::encode(&secret));
        Database {
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
    use crate::{build_path, database_file_name_for};
    use rusqlite::params;
    #[test]
    fn test_pool_reuse() -> Result<(), rusqlite::Error> {
        let secret = [1; 32];
        let file_name = database_file_name_for(&secret);
        let path = build_path("test/data/", &file_name).unwrap();
        let poule = Database::new(path, secret);
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
        let secret = [1; 32];
        let file_name = database_file_name_for(&secret);
        let path = build_path(db_path, &file_name).unwrap();

        let poule = Database::new(path.clone(), secret);
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

            //setup a bad secret
            let secret = [5; 32];
            let bad_poule = Database::new(path, secret);
            let bad_conn_1 = bad_poule.get_connection()?;

            let result: Result<i32, rusqlite::Error> =
                bad_conn_1.query_row("SELECT id FROM person", [], |row| row.get(0));
            let error_message = result
                .expect_err("Should have failed due to wrong database password")
                .to_string();
            assert_eq!("file is not a database", error_message);
        }

        Ok(())
    }
}
