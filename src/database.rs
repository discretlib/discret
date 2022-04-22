use std::path::PathBuf;

use object_pool::{Pool, Reusable};

use rusqlite::Connection;
pub struct ConnectionPool {
    path: PathBuf,
    secret: String,
    pool: Pool<Connection>,
}

impl ConnectionPool {
    pub fn new(path: impl Into<PathBuf>, secret: String) -> Self {
        Self {
            path: path.into(),
            secret,
            //start with zero caps, the init closure  is never called
            //this avoid potential io error during initialisation
            pool: Pool::new(0, || Connection::open_in_memory().unwrap()),
        }
    }

    pub fn len(&self) -> usize {
        self.pool.len()
    }

    pub fn get(&self) -> Result<Reusable<Connection>, rusqlite::Error> {
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
            let query = vec![
                "PRAGMA key = \"".to_string(),
                self.secret.clone(),
                "'\"".to_string(),
            ]
            .concat();
            let mut key_stmt = conn.prepare(query.as_str())?;
            let mut rows = key_stmt.query([])?;
            let row = rows.next()?.unwrap();
            let res: String = row.get(0)?;
            assert_eq!("ok", res)
        }
        Ok(conn)
    }
}

#[cfg(test)]
mod tests {
    use super::ConnectionPool;
    use rusqlite::params;
    #[test]
    fn test_pool_reuse() -> Result<(), rusqlite::Error> {
        let poule = ConnectionPool::new("test/data/test_pool_reuse.db", "mysecret".to_string());
        // println!("Poule size  {:?}", poule.len());
        //brace to quickly push the Connection out of scope
        assert_eq!(poule.len(), 0);
        {
            let conn = poule.get()?;
            assert_eq!(poule.len(), 0);
            let _t: i32 = conn.query_row("SELECT $1", [42], |row| row.get(0))?;
        }
        assert_eq!(poule.len(), 1);
        {
            let conn = poule.get()?;
            assert_eq!(poule.len(), 0);
            let _t: i32 = conn.query_row("SELECT $1", [42], |row| row.get(0))?;
        }
        assert_eq!(poule.len(), 1);
        Ok(())
    }

    struct Person {
        id: i32,
        name: String,
    }

    #[test]
    fn test_pool_encryption() -> Result<(), rusqlite::Error> {
        let db_path = "test/data/test_pool_encryption.db";
        let secret = "x'f553b655b9515fc0f186b74bf485bb38c53954ba38fcaac16217554267a36646'";
        let wrong_secret = "x'A553b655b9515fc0f186b74bf485bb38c53954ba38fcaac16217554267a36646'";

        let poule = ConnectionPool::new(db_path, secret.to_string());
        let bad_poule = ConnectionPool::new(db_path, wrong_secret.to_string());
        // println!("Poule size  {:?}", poule.len());
        //brace to quickly push the Connection out of scope
        {
            let good_conn_1 = poule.get()?;
            good_conn_1.execute(
                "CREATE TABLE IF NOT EXISTS person (
                    id    INTEGER PRIMARY KEY,
                    name  TEXT NOT NULL
                )",
                [], // empty list of parameters.
            )?;
            let me = Person {
                id: 0,
                name: "Steven".to_string(),
            };
            good_conn_1.execute("INSERT INTO person (name) VALUES (?1)", params![me.name])?;

            let good_conn_2 = poule.get()?;

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

            let bad_conn_1 = bad_poule.get()?;
            let ressult: Result<i32, rusqlite::Error> =
                bad_conn_1.query_row("SELECT id FROM person", [], |row| row.get(0));
            ressult.expect_err("all is fine");

            good_conn_2.execute("DELETE FROM person", [])?;
        }
        assert_eq!(poule.len(), 2);
        assert_eq!(bad_poule.len(), 1);
        Ok(())
    }
}
