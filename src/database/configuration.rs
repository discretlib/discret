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

//name of the system entities
pub const ROOM_ENT: &str = "_Room";
pub const AUTHORISATION_ENT: &str = "_Authorisation";

pub const USER_AUTH_ENT: &str = "_UserAuth";
pub const CREDENTIAL_ENT: &str = "_Credential";
pub const ENTITY_RIGHT_ENT: &str = "_EntityRight";
pub const AUTHOR_ENT: &str = "_User";

//name of the system fields
pub const ID_FIELD: &str = "id";
pub const CREATION_DATE_FIELD: &str = "cdate";
pub const MODIFICATION_DATE_FIELD: &str = "mdate";
pub const ENTITY_FIELD: &str = "_entity";
pub const JSON_FIELD: &str = "_json";
pub const BINARY_FIELD: &str = "_binary";
pub const PUB_KEY_FIELD: &str = "_verifying_key";
pub const SIGNATURE_FIELD: &str = "_signature";

//name of the entity fields
pub const AUTHORS_FIELD: &str = "_authors";
pub const AUTHORS_FIELD_SHORT: &str = "0";

pub const ROOMS_FIELD: &str = "_rooms";
pub const ROOMS_FIELD_SHORT: &str = "1";

//names of some authentication fields used during auth validation
pub const AUTH_CRED_FIELD: &str = "credentials";
pub const AUTH_USER_FIELD: &str = "users";

//names of some authentication fields used during auth validation
pub const CRED_MUTATE_ROOM_SHORT: &str = "32";
pub const CRED_MUTATE_ROOM_USERS_SHORT: &str = "33";

pub const USER_VERIFYING_KEY_SHORT: &str = "32";
pub const USER_ENABLED_SHORT: &str = "33";

pub const RIGHT_ENTITY_SHORT: &str = "32";
pub const RIGHT_MUTATE_SELF_SHORT: &str = "33";
pub const RIGHT_MUTATE_SHORT: &str = "34";
pub const RIGHT_DELETE_SHORT: &str = "35";

pub const SYSTEM_DATA_MODEL: &str = "    
    _Room {
        type: String,
        authorisations:[_Authorisation],
        index(type)
    }
    
    _Authorisation {
        name: String,
        credentials:[_Credential] ,
        users:[_UserAuth],
    }
    
    _UserAuth{
        verifying_key: Base64,
        enabled: Boolean default true,
    }

    _Credential {
        mutate_room: Boolean default false,
        mutate_room_users: Boolean default false,
        rights:[_EntityRight],
    }
    
    _EntityRight {
        entity: String,
        mutate_self: Boolean,
        mutate_all: Boolean,
        delete_all: Boolean,
    }";
