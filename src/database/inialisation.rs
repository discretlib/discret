use rusqlite::{Connection, OptionalExtension};

pub fn is_initialized(conn: &Connection) -> Result<bool, rusqlite::Error> {
    let initialised: Option<String> = conn
        .query_row(
            "SELECT name FROM sqlite_schema 
    WHERE type IN ('table','view') 
    AND name = 'User_'",
            [],
            |row| row.get(0),
        )
        .optional()?;
    Ok(initialised.is_some())
}

pub fn initialise(conn: &Connection) -> Result<(), rusqlite::Error> {
    let query = format!(
        "BEGIN;
     {}
     {}
     {}
     {}
     {}
     {}
     COMMIT;",
        USER_TABLE, MANAGED_TABLE, CONTEXT_TABLE, CONTEXT_AUTH_TABLE, ROLE_TABLE, DAILY_HASH_TABLE
    );
    conn.execute_batch(&query)
}

const USER_TABLE: &str = "CREATE TABLE User_( 
	id TEXT PRIMARY KEY, 
	pub_key BLOB, 
	sec_key BLOB, 
	shared_secret BLOB, 
	flag INTEGER 
) STRICT ;";

const MANAGED_TABLE: &str = "CREATE TABLE ManagedTable_(
	table_name TEXT PRIMARY KEY	
) STRICT ;";

const CONTEXT_TABLE: &str = "CREATE TABLE Context_ ( 
	context_id TEXT PRIMARY KEY, 
	cdate INTEGER, 
 	owner_id TEXT, 
	signature BLOB 
) STRICT;";

const CONTEXT_AUTH_TABLE: &str = "CREATE TABLE ContextAuth_ (
	context_id TEXT,
 	user_id TEXT,
	role_id TEXT,
	cdate INTEGER,
	authorizer_id TEXT,
	signature BLOB,
    CONSTRAINT pk_ca_user_context_role_ PRIMARY KEY (user_id, context_id, role_id)
) STRICT; ";

const ROLE_TABLE: &str = "CREATE TABLE Role_(
	role_id TEXT PRIMARY KEY,
	cdate INTEGER,	
	name TEXT,
	activities BLOB	
) STRICT;";

const DAILY_HASH_TABLE: &str = "CREATE TABLE DailyContextHash_(
	context_id TEXT,
	table_name TEXT,
	date INTEGER,
	CONSTRAINT pk_dch_ctx_table_date PRIMARY KEY (context_id, table_name, date)
) STRICT;";

#[cfg(test)]
mod tests {

    use super::*;
    #[test]
    fn initialisation() -> Result<(), rusqlite::Error> {
        let conn = Connection::open_in_memory()?;
        assert!(!is_initialized(&conn)?);
        initialise(&conn)?;
        assert!(is_initialized(&conn)?);
        Ok(())
    }
}
