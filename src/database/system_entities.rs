use rusqlite::Connection;

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

pub const PEER_ENT: &str = "sys.Peer";

//name of the system fields
pub const ID_FIELD: &str = "id";
pub const ROOM_ID_FIELD: &str = "room_id";
pub const CREATION_DATE_FIELD: &str = "cdate";
pub const MODIFICATION_DATE_FIELD: &str = "mdate";
pub const PEER_FIELD: &str = "sys_peer";
pub const ROOM_FIELD: &str = "sys_room";
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
    Peer {
        meeting_pub_key: Base64 ,
        index(_verifying_key)
    }

    AllowedPeer{
        peer: sys.Peer,
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

pub fn sys_room_entities() -> Vec<String> {
    vec![
        "sys.AllowedPeer".to_string(),
        "sys.AllowedHardware".to_string(),
        "sys.InboundInvitation".to_string(),
        "sys.ProposedInvitation".to_string(),
        "sys.Beacon".to_string(),
    ]
}

pub struct Peer {}
impl Peer {}

pub struct AllowedPeer {
    id: String,
    verifying_key: String,
    meeting_pub_key: String,
    banned_until: i64,
    beacons: Vec<Beacon>,
    static_adress: Option<String>,
}

pub struct AllowedHardware {
    id: String,
    fingerprint: String,
    name: String,
}

pub struct InboundInvitation {
    id: String,
    invite_id: String,
    beacons: Vec<Beacon>,
    static_adress: Option<String>,
    signature: String,
}

pub struct ProposedInvitation {
    id: String,
    beacons: Vec<Beacon>,
    remaining_use: i64,
    room: String,
    authorisation: String,
}

pub struct Beacon {
    id: String,
    address: String,
}
