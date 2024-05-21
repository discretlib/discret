use rusqlite::Connection;
use serde::{Deserialize, Serialize};

#[derive(Debug, Serialize, Deserialize)]
pub struct Configuration {
    ///
    /// Default 8192
    /// set the maximum cache size for the reading threads. increasing it can improve performances
    /// each read threads defined in read_parallelism consume up to that amount
    ///
    /// Real max memory usage is read_cache_size_in_kb *read_parallelism
    /// default memory usage is 32 Mb.
    pub read_cache_size_in_kb: u32,

    ///
    /// Default: 4
    ///
    /// set the number of parallel read thread for the database
    /// set the maximum of cache size for the writing thread.
    /// increasing it may improve performances
    ///
    pub read_parallelism: usize,

    ///
    /// Default 2048
    /// set the maximum of cache size for the writing thread. increasing it may improvee performances
    ///
    pub write_cache_size_in_kb: u32,

    ///
    /// Default: 1000
    ///
    /// Write queries are buffered while the database thread is working.
    /// When the database thread is ready, the buffer is sent and is processed in one single transaction
    /// This greatly increase insertion and update rate, compared to autocommit.
    ///      To get an idea of the perforance difference,
    ///      a very simple benchmak on a laptop with 100 000 insertions gives:
    ///      Buffer size: 1      Insert/seconds: 55  <- this is equivalent to autocommit
    ///      Buffer size: 10     Insert/seconds: 500
    ///      Buffer size: 100    Insert/seconds: 3000
    ///      Buffer size: 1000   Insert/seconds: 32000
    ///
    /// If one a buffered query fails, the transaction will be rolled back and every other queries in the buffer will fail too.
    /// This should not be an issue as INSERT query are not expected to fail.
    /// The only reasons to fail an insertion are a bugs or a system failure (like no more space available on disk),
    /// And in both case, it is ok to fail the last insertions batch.
    ///
    pub write_buffer_size: usize,

    ///
    /// Default: false (disabled)
    ///
    /// Enable_memory_security: Prevents memory to be written into swap and zeroise memory after free
    ///  Can be disabled because of a huge performance impact (about 50%),
    ///  When this feature is disabled, locking/unlocking of the memory address only occur for the internal SQLCipher
    ///  data structures used to store key material, and cryptographic structures.
    ///  source: https://discuss.zetetic.net/t/what-is-the-purpose-of-pragma-cipher-memory-security/3953
    ///
    pub enable_database_memory_security: bool,
}
impl Default for Configuration {
    fn default() -> Self {
        Self {
            read_cache_size_in_kb: 8192,
            read_parallelism: 4,
            write_cache_size_in_kb: 2048,
            write_buffer_size: 1000,
            enable_database_memory_security: false,
        }
    }
}

pub fn create_table(conn: &Connection) -> Result<(), rusqlite::Error> {
    conn.execute(
        "
        CREATE TABLE _configuration (
            key TEXT NOT NULL,
            value TEXT,
            PRIMARY KEY(key)
        ) WITHOUT ROWID, STRICT",
        [],
    )?;
    Ok(())
}

pub const SYSTEM_NAMESPACE: &str = "sys";
//name of the system entities
pub const ROOM_ENT: &str = "sys.Room";
pub const ROOM_ENT_SHORT: &str = "0.0";

pub const AUTHORISATION_ENT: &str = "sys.Authorisation";
pub const AUTHORISATION_ENT_SHORT: &str = "0.1";

pub const USER_AUTH_ENT: &str = "sys.UserAuth";
pub const USER_AUTH_ENT_SHORT: &str = "0.2";

pub const ENTITY_RIGHT_ENT: &str = "sys.EntityRight";
pub const ENTITY_RIGHT_ENT_SHORT: &str = "0.3";

pub const AUTHOR_ENT: &str = "sys.User";

//name of the system fields
pub const ID_FIELD: &str = "id";
pub const ROOM_ID_FIELD: &str = "room_id";
pub const CREATION_DATE_FIELD: &str = "cdate";
pub const MODIFICATION_DATE_FIELD: &str = "mdate";
pub const AUTHOR_FIELD: &str = "author";
pub const ROOM_FIELD: &str = "room";
pub const ENTITY_FIELD: &str = "_entity";
pub const JSON_FIELD: &str = "_json";
pub const BINARY_FIELD: &str = "_binary";
pub const VERIFYING_KEY_FIELD: &str = "_verifying_key";
pub const SIGNATURE_FIELD: &str = "_signature";

//name of the entity fields
pub const AUTHORS_FIELD_SHORT: &str = "0";

//names of some authentication fields used during auth validation
pub const ROOM_ADMIN_FIELD: &str = "admin";
pub const ROOM_ADMIN_FIELD_SHORT: &str = "32";
pub const ROOM_USER_ADMIN_FIELD: &str = "user_admin";
pub const ROOM_USER_ADMIN_FIELD_SHORT: &str = "33";
pub const ROOM_AUTHORISATION_FIELD: &str = "authorisations";
pub const ROOM_AUTHORISATION_FIELD_SHORT: &str = "34";

//names of some authentication fields used during auth validation
pub const AUTH_RIGHTS_FIELD: &str = "rights";
pub const AUTH_RIGHTS_FIELD_SHORT: &str = "33";
pub const AUTH_USER_FIELD: &str = "users";
pub const AUTH_USER_FIELD_SHORT: &str = "34";

pub const USER_VERIFYING_KEY_SHORT: &str = "32";
pub const USER_ENABLED_SHORT: &str = "33";

pub const RIGHT_ENTITY_SHORT: &str = "32";
pub const RIGHT_MUTATE_SELF_SHORT: &str = "33";
pub const RIGHT_MUTATE_ALL_SHORT: &str = "34";

pub const SYSTEM_DATA_MODEL: &str = "
sys{
    // Entities for the authorisation model
    Room {
        admin: [sys.UserAuth],
        user_admin: [sys.UserAuth],
        authorisations:[sys.Authorisation]
    }
    
    Authorisation {
        name: String,
        rights:[sys.EntityRight] ,
        users:[sys.UserAuth],
    }
    
    UserAuth{
        verifying_key: Base64,
        enabled: Boolean default true,
    }
    
    EntityRight {
        entity: String,
        mutate_self: Boolean,
        mutate_all: Boolean,
    }

    //Entities for the peer connection
    User {
        name: String,
        data: Json nullable,
        meeting_pub_key: Base64 ,
        index(_verifying_key)
    }

    AllowedPeer{
        verifying_key: Base64,
        meeting_pub_key: Base64,
        banned_until: Integer,
        beacons: [sys.Beacon],
        enabled: Boolean,
    }

    AllowedHardware{
        fingerprint: Base64,
        name: String,
    }

    InboundInvitation{
        invite_id: Base64,
        beacons: [sys.Beacon],
        static_adress: String nullable,
        signature: Base64,
    }

    ProposedInvitation{
        remaining_use: Integer,
        target_room: Base64,
        target_authorisation: Base64,
    }

    Beacon{
        address : String,
    }
}";

pub fn sys_tables() -> Vec<String> {
    vec![
        "sys.AllowedPeer".to_string(),
        "sys.AllowedHardware".to_string(),
        "sys.InboundInvitation".to_string(),
        "sys.ProposedInvitation".to_string(),
        "sys.Beacon".to_string(),
    ]
}
