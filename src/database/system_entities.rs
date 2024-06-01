use std::{collections::HashSet, fmt::Write};

use rusqlite::{params_from_iter, Connection, OptionalExtension};
use serde::{Deserialize, Serialize};
use tokio::sync::oneshot;

use crate::{
    base64_encode,
    security::{Ed25519SigningKey, MeetingToken},
    Parameters, ParametersAdd, Uid,
};

use super::{
    edge::Edge,
    graph_database::GraphDatabaseService,
    node::Node,
    query::QueryResult,
    sqlite_database::{Database, Writeable},
    Error,
};

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
pub const PEER_ENT_SHORT: &str = "0.4";

pub const ALLOWED_PEER_ENT: &str = "sys.AllowedPeer";
pub const ALLOWED_PEER_ENT_SHORT: &str = "0.5";

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
pub const VERIFYING_KEY_FIELD: &str = "verifying_key";
pub const SIGNATURE_FIELD: &str = "_signature";

//names of some authentication fields used during auth validation
pub const ROOM_ADMIN_FIELD: &str = "admin";
pub const ROOM_ADMIN_FIELD_SHORT: &str = "32";
pub const ROOM_AUTHORISATION_FIELD: &str = "authorisations";
pub const ROOM_AUTHORISATION_FIELD_SHORT: &str = "33";

//names of some authentication fields used during auth validation
pub const AUTH_RIGHTS_FIELD: &str = "rights";
pub const AUTH_RIGHTS_FIELD_SHORT: &str = "33";
pub const AUTH_USER_FIELD: &str = "users";
pub const AUTH_USER_FIELD_SHORT: &str = "34";
pub const AUTH_USER_ADMIN_FIELD: &str = "user_admin";
pub const AUTH_USER_ADMIN_FIELD_SHORT: &str = "35";

pub const USER_VERIFYING_KEY_SHORT: &str = "32";
pub const USER_ENABLED_SHORT: &str = "33";

pub const RIGHT_ENTITY_SHORT: &str = "32";
pub const RIGHT_MUTATE_SELF_SHORT: &str = "33";
pub const RIGHT_MUTATE_ALL_SHORT: &str = "34";

pub const ALLOWED_PEER_PEER_SHORT: &str = "32";

pub const SYSTEM_DATA_MODEL: &str = r#"
sys{
    // Entities for the authorisation model
    Room {
        admin: [sys.UserAuth],
        authorisations:[sys.Authorisation]
    }
    
    Authorisation {
        name: String,
        rights:[sys.EntityRight] ,
        users:[sys.UserAuth],
        user_admin: [sys.UserAuth],
    }
    
    UserAuth{
        verif_key: Base64,
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
        name: String default "anonymous",
        ext: Json default "{}",
        index(verifying_key)
    }

    AllowedPeer{
        peer: sys.Peer,
        meeting_token: Base64,
        enabled: Boolean default true,
    }

    AllowedHardware{
        fingerprint: Base64,
        name: String,
    }

    InboundInvitation{
        invite_id: Base64,
        beacons: [sys.Beacon],
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
}"#;

pub fn sys_room_entities() -> Vec<String> {
    vec![
        "sys.AllowedPeer".to_string(),
        "sys.AllowedHardware".to_string(),
        "sys.InboundInvitation".to_string(),
        "sys.ProposedInvitation".to_string(),
        "sys.Beacon".to_string(),
    ]
}

#[derive(Serialize, Deserialize)]
pub struct Peer {
    id: String,
    verifying_key: String,
    meeting_pub_key: String,
}
impl Peer {
    pub fn create(id: Uid, meeting_pub_key: String) -> Node {
        let json = format!(
            r#"{{ 
                "meeting_pub_key": "{}" 
            }}"#,
            meeting_pub_key
        );

        let node = Node {
            id,
            room_id: None,
            cdate: 0,
            mdate: 0,
            _entity: PEER_ENT_SHORT.to_string(),
            _json: Some(json),
            ..Default::default()
        };

        node
    }

    pub fn get_missing(
        keys: HashSet<Vec<u8>>,
        conn: &Connection,
    ) -> Result<HashSet<Vec<u8>>, Error> {
        let it = &mut keys.iter().peekable();
        let mut result = HashSet::with_capacity(keys.len());

        //limit the IN clause to a reasonable size, avoiding the 32766 parameter limit in sqlite
        let row_per_query = 500;
        let mut query_list = Vec::new();
        let mut row_num = 0;
        struct QueryParams<'a> {
            in_clause: String,
            ids: Vec<&'a Vec<u8>>,
        }
        let mut current_query = QueryParams {
            in_clause: String::new(),
            ids: Vec::new(),
        };

        while let Some(nid) = it.next() {
            current_query.in_clause.push('?');
            current_query.ids.push(nid);

            row_num += 1;
            if row_num < row_per_query {
                if it.peek().is_some() {
                    current_query.in_clause.push(',');
                }
            } else {
                query_list.push(current_query);
                row_num = 0;
                current_query = QueryParams {
                    in_clause: String::new(),
                    ids: Vec::new(),
                };
            }
            result.insert(nid.clone());
        }
        if !current_query.ids.is_empty() {
            query_list.push(current_query);
        }
        for i in 0..query_list.len() {
            let current_query = &query_list[i];
            let ids = &current_query.ids;
            let in_clause = &current_query.in_clause;

            let query = format!(
                "SELECT verifying_key 
                FROM _node 
                WHERE _entity='{}' 
                AND verifying_key IN ({})
                AND room_id IS NULL",
                PEER_ENT_SHORT, in_clause
            );
            let mut stmt = conn.prepare(&query)?;
            let mut rows = stmt.query(params_from_iter(ids.iter()))?;
            while let Some(row) = rows.next()? {
                let veri: Vec<u8> = row.get(0)?;
                result.remove(&veri);
            }
        }
        Ok(result)
    }

    pub fn get_peers(keys: Vec<Vec<u8>>, conn: &Connection) -> Result<Vec<Node>, Error> {
        let it = &mut keys.iter().peekable();
        let mut result = Vec::with_capacity(keys.len());

        //limit the IN clause to a reasonable size, avoiding the 32766 parameter limit in sqlite
        let row_per_query = 500;
        let mut query_list = Vec::new();
        let mut row_num = 0;
        struct QueryParams<'a> {
            in_clause: String,
            ids: Vec<&'a Vec<u8>>,
        }
        let mut current_query = QueryParams {
            in_clause: String::new(),
            ids: Vec::new(),
        };

        while let Some(nid) = it.next() {
            current_query.in_clause.push('?');
            current_query.ids.push(nid);

            row_num += 1;
            if row_num < row_per_query {
                if it.peek().is_some() {
                    current_query.in_clause.push(',');
                }
            } else {
                query_list.push(current_query);
                row_num = 0;
                current_query = QueryParams {
                    in_clause: String::new(),
                    ids: Vec::new(),
                };
            }
        }
        if !current_query.ids.is_empty() {
            query_list.push(current_query);
        }
        for i in 0..query_list.len() {
            let current_query = &query_list[i];
            let ids = &current_query.ids;
            let in_clause = &current_query.in_clause;

            let query = format!(
                "SELECT id, room_id, cdate, mdate, _entity,_json, _binary, verifying_key, _signature  
                FROM _node 
                WHERE _entity='{}' 
                AND verifying_key IN ({})
                AND room_id IS NULL",
                PEER_ENT_SHORT, in_clause
            );
            let mut stmt = conn.prepare(&query)?;
            let mut rows = stmt.query(params_from_iter(ids.iter()))?;
            while let Some(row) = rows.next()? {
                let node = Node {
                    id: row.get(0)?,
                    room_id: row.get(1)?,
                    cdate: row.get(2)?,
                    mdate: row.get(3)?,
                    _entity: row.get(4)?,
                    _json: row.get(5)?,
                    _binary: row.get(6)?,
                    verifying_key: row.get(7)?,
                    _signature: row.get(8)?,
                    _local_id: None,
                };
                result.push(node)
            }
        }
        Ok(result)
    }
}

pub struct PeerNodes {
    pub nodes: Vec<Node>,
}
impl Writeable for PeerNodes {
    fn write(&mut self, conn: &Connection) -> std::result::Result<(), rusqlite::Error> {
        for node in &self.nodes {
            let mut exists_stmt =
                conn.prepare_cached("SELECT 1 FROM _node WHERE id = ? AND _entity = ?")?;
            let exists: Option<i64> = exists_stmt
                .query_row((node.id, &node._entity), |row| row.get(0))
                .optional()?;
            if exists.is_none() {
                let mut insert_stmt = conn.prepare_cached(
                    "INSERT INTO _node ( 
                        id,
                        room_id,
                        cdate,
                        mdate,
                        _entity,
                        _json,
                        _binary,
                        verifying_key,
                        _signature
                    ) VALUES (
                        ?, ?, ?, ?, ?, ?, ?, ?, ?
                    )",
                )?;
                insert_stmt.insert((
                    &node.id,
                    &node.room_id,
                    &node.cdate,
                    &node.mdate,
                    &node._entity,
                    &node._json,
                    &node._binary,
                    &node.verifying_key,
                    &node._signature,
                ))?;
            }
        }

        Ok(())
    }
}

#[derive(Serialize, Deserialize)]
pub struct AllowedPeer {
    id: String,
    peer: Peer,
    enabled: bool,
    meeting_token: String,
}
impl AllowedPeer {
    pub fn create(id: Uid, room_id: Uid, token: String, peer_id: Uid) -> (Node, Edge) {
        let json = format!(
            r#"{{ 
                "meeting_token": "{}",
                "enabled": true
            }}"#,
            token
        );

        let node = Node {
            id,
            room_id: Some(room_id),
            cdate: 0,
            mdate: 0,
            _entity: ALLOWED_PEER_ENT_SHORT.to_string(),
            _json: Some(json),
            ..Default::default()
        };

        let edge = Edge {
            src: id,
            src_entity: ALLOWED_PEER_ENT_SHORT.to_string(),
            label: ALLOWED_PEER_PEER_SHORT.to_string(),
            dest: peer_id,
            cdate: 0,
            ..Default::default()
        };

        (node, edge)
    }

    pub async fn add(
        room_id: &str,
        public_key: &str,
        _meeting_token: String,
        db: &GraphDatabaseService,
    ) -> Result<(), Error> {
        let query = "query {
            result: sys.Peer(meeting_pub_key=$public_key){
                id
                verifying_key
                meeting_pub_key
            }";

        let mut param = Parameters::new();
        param.add("room_id", room_id.to_string())?;
        param.add("public_key", public_key.to_string())?;
        let peer_str = db.query(query, Some(param)).await?;

        let query_result: QueryResult = QueryResult::new(&peer_str)?;
        let result: Vec<Peer> = query_result.get("result").unwrap();

        if !result.is_empty() {
            return Ok(());
        }

        let mut param = Parameters::new();
        param.add("room_id", room_id.to_string())?;
        param.add("public_key", public_key.to_string())?;

        db.mutate(
            "mutate {
                result: sys.Peer{
                    room_id: $room_id
                    meeting_pub_key: public_key
                }",
            Some(param),
        )
        .await?;

        let mut param = Parameters::new();
        param.add("room_id", room_id.to_string())?;
        param.add("public_key", public_key.to_string())?;
        db.query(query, Some(param)).await?;

        Ok(())
    }
}

pub struct AllowedPeerWriter(pub Node, pub Edge);
impl Writeable for AllowedPeerWriter {
    fn write(&mut self, conn: &Connection) -> std::result::Result<(), rusqlite::Error> {
        self.0.write(conn, false, &None, &None)?;
        self.1.write(conn)?;
        Ok(())
    }
}
pub async fn init_allowed_peers(
    database: &Database,
    peer_uid: Uid,
    public_key: &[u8; 32],
    allowed_uid: Uid,
    private_room_id: Uid,
    token: MeetingToken,
    signing_key: &Ed25519SigningKey,
) -> Result<(), Error> {
    //init peer entity
    let (reply, receive) = oneshot::channel::<Result<bool, Error>>();
    database
        .reader
        .send_async(Box::new(move |conn| {
            let room_node = Node::exist(&peer_uid, PEER_ENT_SHORT, conn);
            let _ = reply.send(room_node);
        }))
        .await?;
    let exists = receive.await??;
    if !exists {
        let mut peer_node = Peer::create(peer_uid, base64_encode(public_key));
        peer_node.sign(signing_key)?;
        database.writer.write(Box::new(peer_node)).await?;
    }

    //init allowed_peer entity
    let (reply, receive) = oneshot::channel::<Result<bool, Error>>();
    database
        .reader
        .send_async(Box::new(move |conn| {
            let room_node = Node::exist(&allowed_uid, ALLOWED_PEER_ENT_SHORT, conn);
            let _ = reply.send(room_node);
        }))
        .await?;
    let exists = receive.await??;

    if !exists {
        let (mut all_node, mut all_edge) = AllowedPeer::create(
            allowed_uid,
            private_room_id,
            base64_encode(&token),
            peer_uid,
        );
        all_node.sign(signing_key)?;
        all_edge.sign(signing_key)?;

        let writer = AllowedPeerWriter(all_node, all_edge);
        database.writer.write(Box::new(writer)).await?;
    }

    Ok(())
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

#[derive(Serialize, Deserialize)]
pub struct Beacon {
    id: String,
    address: String,
}

#[cfg(test)]
mod tests {
    use crate::event_service::EventService;
    use crate::Configuration;
    use crate::{peer_connection_service::random32, security::Ed25519SigningKey};

    use crate::database::sqlite_database::prepare_connection;

    use super::*;

    use std::{fs, path::PathBuf};
    const DATA_PATH: &str = "test_data/database/system_entities/";
    fn init_database_path() {
        let path: PathBuf = DATA_PATH.into();
        fs::create_dir_all(&path).unwrap();
    }
    #[test]
    fn peer() {
        let conn1 = Connection::open_in_memory().unwrap();
        prepare_connection(&conn1).unwrap();

        let num_peer = 10;
        let mut peers = HashSet::with_capacity(num_peer);

        for _ in 0..num_peer {
            let keypair = Ed25519SigningKey::new();
            let mut node = Node {
                _entity: PEER_ENT_SHORT.to_string(),
                ..Default::default()
            };
            node.sign(&keypair).unwrap();
            assert!(node.verify().is_ok());
            peers.insert(node.verifying_key.clone());
            node.write(&conn1, false, &None, &None).unwrap();
        }

        let conn2 = Connection::open_in_memory().unwrap();
        prepare_connection(&conn2).unwrap();

        let missing_1 = Peer::get_missing(peers.clone(), &conn1).unwrap();
        assert_eq!(missing_1.len(), 0);

        let missing = Peer::get_missing(peers.clone(), &conn2).unwrap();
        assert_eq!(missing.len(), num_peer);

        let keys = missing.into_iter().collect();
        let nodes = Peer::get_peers(keys, &conn1).unwrap();
        assert_eq!(nodes.len(), num_peer);

        let mut pn = PeerNodes { nodes };

        pn.write(&conn2).unwrap();

        let missing = Peer::get_missing(peers, &conn2).unwrap();
        assert_eq!(missing.len(), 0);
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn inti_allowed_peer() {
        init_database_path();

        let path: PathBuf = DATA_PATH.into();
        let secret = random32();
        let pub_key = &random32();

        let (first_app, verifying_key, private_room) = GraphDatabaseService::start(
            "authorisation app",
            "",
            &secret,
            &pub_key,
            path,
            &Configuration::default(),
            EventService::new(),
        )
        .await
        .unwrap();
        let first_user_id = base64_encode(&verifying_key);
    }
}
