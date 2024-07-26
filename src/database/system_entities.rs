use std::collections::HashSet;

use rusqlite::{params_from_iter, Connection, OptionalExtension};
use serde::{Deserialize, Serialize};
use tokio::sync::{mpsc, oneshot};

use crate::{
    base64_decode, base64_encode,
    database::VEC_OVERHEAD,
    security::{uid_decode, uid_encode, Ed25519SigningKey, MeetingToken},
    Parameters, ParametersAdd, Uid,
};

use super::{
    edge::Edge,
    graph_database::GraphDatabaseService,
    node::{extract_json, Node},
    sqlite_database::{Database, Writeable},
    Error, ResultParser,
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

pub const ALLOWED_HARDWARE_ENT: &str = "sys.AllowedHardware";
pub const ALLOWED_HARDWARE_ENT_SHORT: &str = "0.6";

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

pub const PEER_PUB_KEY_SHORT: &str = "32";
pub const PEER_NAME_SHORT: &str = "33";

pub const ALLOWED_PEER_PEER_SHORT: &str = "32";
pub const ALLOWED_PEER_TOKEN_SHORT: &str = "33";
pub const ALLOWED_PEER_STATUS_SHORT: &str = "35";

pub const ALLOWED_HARDWARE_NAME_SHORT: &str = "32";
pub const ALLOWED_HARDWARE_STATUS_SHORT: &str = "33";

pub const SYSTEM_DATA_MODEL: &str = r#"
sys{
    // Entities for the authorisation model
    Room {
        admin: [sys.UserAuth],
        authorisations:[sys.Authorisation]
    }
    
    Authorisation( no_full_text_index) {
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

    Peer{
        pub_key: Base64 ,
        name: String default "anonymous"
    }

    AllowedPeer(no_full_text_index){
        peer: sys.Peer,
        meeting_token: Base64,
        last_connection: Integer default 0,
        status: String,
    }

    AllowedHardware{
        name: String,
        status: String default "enabled", //enabled, disabled, pending
    }

    OwnedInvite{
        room: Base64 nullable,
        authorisation: Base64 nullable,
    }

    Invite{
        invite_id: Base64,
        application : String,
        invite_sign: Base64,
    }

}"#;

#[derive(Deserialize, Clone)]
pub struct Peer {
    pub id: String,
    pub verifying_key: String,
}
impl Peer {
    pub fn create(id: Uid, meeting_pub_key: String) -> Node {
        let json = format!(
            r#"{{
                "{}": "{}", 
                "{}": "" 
            }}"#,
            PEER_PUB_KEY_SHORT, meeting_pub_key, PEER_NAME_SHORT
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

    pub fn validate(peer: &Node) -> Result<(), Error> {
        if peer.room_id.is_some() {
            return Err(Error::InvalidPeerNode("room not empty".to_string()));
        }

        if !peer._entity.eq(PEER_ENT_SHORT) {
            return Err(Error::InvalidPeerNode("Invalid Entity".to_string()));
        }
        if peer.verify().is_err() {
            return Err(Error::InvalidPeerNode("Invalid Signature".to_string()));
        }
        Self::pub_key(peer)?;
        Ok(())
    }

    pub fn pub_key(peer: &Node) -> Result<Vec<u8>, Error> {
        if peer._json.is_none() {
            return Err(Error::InvalidPeerNode("empty json".to_string()));
        }
        let json = peer._json.as_ref().unwrap();
        let json: serde_json::Value = serde_json::from_str(json)?;
        let map = json
            .as_object()
            .ok_or(Error::InvalidJsonObject("Peer json".to_string()))?;

        let pub_key = map
            .get(PEER_PUB_KEY_SHORT)
            .ok_or(Error::InvalidJsonObject("Peer pub_key".to_string()))?;

        let pub_key = pub_key.as_str().ok_or(Error::InvalidJsonObject(
            "Peer pub_key is not a string".to_string(),
        ))?;

        let key = base64_decode(pub_key.as_bytes())?;

        Ok(key)
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

    pub fn get_peers(
        keys: HashSet<Vec<u8>>,
        batch_size: usize,
        sender: &mpsc::Sender<Result<Vec<Node>, super::Error>>,
        conn: &Connection,
    ) -> Result<(), Error> {
        let it = &mut keys.iter().peekable();

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
        let mut res = Vec::new();
        let mut len = 0;

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
                let size = bincode::serialized_size(&node)?;
                let insert_len = len + size + VEC_OVERHEAD;
                if insert_len > batch_size as u64 {
                    let ready = res;
                    res = Vec::new();
                    len = 0;
                    let s = sender.blocking_send(Ok(ready));
                    if s.is_err() {
                        break;
                    }
                } else {
                    len = insert_len;
                }

                res.push(node)
            }
        }
        if !res.is_empty() {
            let _ = sender.blocking_send(Ok(res));
        }
        Ok(())
    }

    pub fn get_node(
        verifying_key: Vec<u8>,
        conn: &Connection,
    ) -> Result<Option<Node>, rusqlite::Error> {
        let mut exists_stmt = conn.prepare_cached(
            "SELECT id, room_id, cdate, mdate, _entity,_json, _binary, verifying_key, _signature  
            FROM _node 
            WHERE _entity=? 
            AND verifying_key =?
            AND room_id IS NULL",
        )?;
        let peer: Option<Node> = exists_stmt
            .query_row((PEER_ENT_SHORT, &verifying_key), |row| {
                Ok(Node {
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
                })
            })
            .optional()?;
        Ok(peer)
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

pub enum Status {
    Enabled,
    Pending,
    Disabled,
}
impl Status {
    pub fn value(&self) -> &str {
        match self {
            Status::Enabled => STATUS_ENABLED,
            Status::Pending => STATUS_PENDING,
            Status::Disabled => STATUS_DISABLED,
        }
    }
}

pub const STATUS_ENABLED: &str = "enabled";
pub const STATUS_PENDING: &str = "pending";
pub const STATUS_DISABLED: &str = "disabled";
#[derive(Deserialize, Clone)]
pub struct AllowedPeer {
    pub peer: Peer,
    pub status: String,
    pub meeting_token: String,
}
impl AllowedPeer {
    pub fn create(
        id: Uid,
        private_room_id: Uid,
        token: String,
        peer_id: Uid,
        status: Status,
    ) -> (Node, Edge) {
        let json = format!(
            r#"{{ 
                "{}": "{}",
                "{}": "{}"
            }}"#,
            ALLOWED_PEER_TOKEN_SHORT,
            token,
            ALLOWED_PEER_STATUS_SHORT,
            status.value()
        );

        let node = Node {
            id,
            room_id: Some(private_room_id),
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
        verifying_key: &str,
        meeting_token: &str,
        status: Status,
        db: &GraphDatabaseService,
    ) -> Result<Self, crate::Error> {
        let query = "query {
            result: sys.Peer(verifying_key=$verifying_key){
                id
                verifying_key
            }
        }";

        let mut param = Parameters::new();
        param.add("verifying_key", verifying_key.to_string())?;

        let peer_str = db.query(query, Some(param)).await?;

        let mut query_result: ResultParser = ResultParser::new(&peer_str)?;
        let mut result: Vec<Peer> = query_result.take_array("result")?;

        if result.is_empty() {
            return Err(crate::Error::from(Error::UnknownPeer()));
        }

        let peer_obj = result.pop().unwrap();
        let peer_id = peer_obj.id.clone();

        let query = "query {
            result: sys.AllowedPeer(room_id=$room_id){
                meeting_token
                status
                peer(id=$peer_id){
                    id
                    verifying_key
                }
            }
        }";

        let mut param = Parameters::new();
        param.add("room_id", room_id.to_string())?;
        param.add("peer_id", peer_id.to_string())?;
        let peer_str = db.query(query, Some(param)).await?;
        let mut query_result: ResultParser = ResultParser::new(&peer_str)?;
        let mut result: Vec<AllowedPeer> = query_result.take_array("result")?;

        if !result.is_empty() {
            return Ok(result.pop().unwrap());
        }

        let mut param = Parameters::new();
        param.add("room_id", room_id.to_string())?;
        param.add("peer_id", peer_id.to_string())?;
        param.add("meeting_token", meeting_token.to_string())?;
        param.add("status", status.value().to_string())?;
        db.mutate(
            "mutate {
                result: sys.AllowedPeer{
                    room_id: $room_id
                    meeting_token: $meeting_token
                    status: $status
                    peer: {id:$peer_id}
                }
            }",
            Some(param),
        )
        .await?;

        Ok(Self {
            peer: peer_obj,
            status: status.value().to_string(),
            meeting_token: meeting_token.to_string(),
        })
    }

    pub async fn get(
        room_id: String,
        status: Status,
        db: &GraphDatabaseService,
    ) -> Result<Vec<AllowedPeer>, crate::Error> {
        let query = "query {
            result: sys.AllowedPeer(room_id=$room_id, status=$status){
                meeting_token
                status
                peer {
                    id
                    verifying_key
                }
            }
        }";

        let mut param = Parameters::new();
        param.add("room_id", room_id)?;
        param.add("status", status.value().to_string())?;

        let peer_str = db.query(query, Some(param)).await?;
        let mut query_result: ResultParser = ResultParser::new(&peer_str)?;
        let result: Vec<AllowedPeer> = query_result.take_array("result")?;

        Ok(result)
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

        let mut index = String::new();
        let val = serde_json::from_str(&peer_node._json.clone().unwrap())?;
        extract_json(&val, &mut index)?;
        let peer_writer = PeerWriter {
            node: peer_node,
            index,
        };

        database.writer.write(Box::new(peer_writer)).await?;
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
            Status::Enabled,
        );
        all_node.sign(signing_key)?;
        all_edge.sign(signing_key)?;

        let writer = AllowedPeerWriter(all_node, all_edge);
        database.writer.write(Box::new(writer)).await?;
    }

    Ok(())
}

//Initialised Peers needs to be inserted with the ftse index, otherwise it is not possible to update their name without getting ans horrible:'database disk image is malformed' error
pub struct PeerWriter {
    pub node: Node,
    pub index: String,
}
impl Writeable for PeerWriter {
    fn write(&mut self, conn: &Connection) -> std::result::Result<(), rusqlite::Error> {
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
        let rowid = insert_stmt.insert((
            &self.node.id,
            &self.node.room_id,
            &self.node.cdate,
            &self.node.mdate,
            &self.node._entity,
            &self.node._json,
            &self.node._binary,
            &self.node.verifying_key,
            &self.node._signature,
        ))?;
        static UPDATE_FTS_QUERY: &str = "INSERT INTO _node_fts (rowid, text) VALUES (?, ?)";

        if !self.index.is_empty() {
            let mut insert_fts_stmt = conn.prepare_cached(UPDATE_FTS_QUERY)?;
            insert_fts_stmt.execute((rowid, &self.index))?;
        }
        Ok(())
    }
}

#[derive(Deserialize)]
pub struct AllowedHardware {
    pub id: String,
    pub name: String,
    pub status: String,
}
impl AllowedHardware {
    pub async fn get(
        id: Uid,
        private_room_id: Uid,
        status: &str,
        db: &GraphDatabaseService,
    ) -> Result<Option<Self>, crate::Error> {
        let mut param = Parameters::new();
        param.add("room_id", uid_encode(&private_room_id))?;
        param.add("id", uid_encode(&id))?;
        param.add("status", status.to_string())?;

        let res = db
            .query(
                r#"query {
                result: sys.AllowedHardware(id=$id, room_id=$room_id, status=$status){
                        id
                        name
                        status
                    }
                }"#,
                Some(param),
            )
            .await?;
        let mut query_result: ResultParser = ResultParser::new(&res)?;
        let mut result: Vec<Self> = query_result.take_array("result")?;
        Ok(result.pop())
    }

    pub async fn put(
        id: Uid,
        private_room_id: Uid,
        name: &str,
        status: &str,
        db: &GraphDatabaseService,
    ) -> Result<(), Error> {
        let json = format!(
            r#"{{ 
                "{}": "{}",
                "{}": "{}"
            }}"#,
            ALLOWED_HARDWARE_NAME_SHORT, name, ALLOWED_HARDWARE_STATUS_SHORT, status
        );

        let (reply, receive) = oneshot::channel::<Result<Option<Box<Node>>, rusqlite::Error>>();
        db.db
            .reader
            .send_async(Box::new(move |conn| {
                let room_node =
                    Node::get_in_room(&id, &private_room_id, ALLOWED_HARDWARE_ENT_SHORT, conn);
                let _ = reply.send(room_node);
            }))
            .await?;
        let existing = receive.await??;

        let mut node = match existing {
            Some(node) => *node,
            None => Node {
                id,
                room_id: Some(private_room_id),
                cdate: 0,
                mdate: 0,
                _entity: ALLOWED_HARDWARE_ENT_SHORT.to_string(),
                _json: None,
                ..Default::default()
            },
        };
        node._json = Some(json);
        db.db.writer.write(Box::new(node)).await?;
        Ok(())
    }
}

#[derive(Clone)]
pub struct OwnedInvite {
    pub id: Uid,
    pub room: Option<Uid>,
    pub authorisation: Option<Uid>,
}
impl OwnedInvite {
    pub async fn delete(id: Uid, db: &GraphDatabaseService) -> Result<(), Error> {
        let mut param = Parameters::new();
        param.add("id", uid_encode(&id))?;
        db.delete(
            "delete { 
            sys.OwnedInvite{
                $id
            }
        }",
            Some(param),
        )
        .await?;
        Ok(())
    }

    pub async fn list_valid(
        room_id: String,
        db: &GraphDatabaseService,
    ) -> Result<Vec<Self>, crate::Error> {
        let mut param = Parameters::new();
        param.add("room_id", room_id)?;

        let result = db
            .query(
                "query{
            sys.OwnedInvite(room_id=$room_id, order_by(mdate desc)){
                id
                room
                authorisation
            }
        }",
                Some(param),
            )
            .await?;

        #[derive(Deserialize)]
        struct SerProdInvite {
            id: String,
            room: Option<String>,
            authorisation: Option<String>,
        }

        let mut list = Vec::new();
        let mut q = ResultParser::new(&result)?;
        let invites: Vec<SerProdInvite> = q.take_array("sys.OwnedInvite")?;
        for invite in invites {
            let id = uid_decode(&invite.id)?;
            let room = match invite.room {
                Some(v) => Some(uid_decode(&v)?),
                None => None,
            };
            let authorisation = match invite.authorisation {
                Some(v) => Some(uid_decode(&v)?),
                None => None,
            };

            list.push(Self {
                id,
                room,
                authorisation,
            })
        }
        Ok(list)
    }
}

#[derive(Serialize, Deserialize, Clone)]
pub struct Invite {
    pub invite_id: Uid,
    pub application: String,
    pub invite_sign: Vec<u8>,
}
impl Invite {
    pub async fn create(
        room_id: String,
        default_room: Option<DefaultRoom>,
        application: String,
        db: &GraphDatabaseService,
    ) -> Result<(Self, OwnedInvite), Error> {
        let (default_room_id, default_auth_id) = match default_room.as_ref() {
            Some(r) => (
                Some(uid_decode(&r.room)?),
                Some(uid_decode(&r.authorisation)?),
            ),
            None => (None, None),
        };

        let (room, auth) = match default_room {
            Some(r) => (Some(r.room), Some(r.authorisation)),
            None => (None, None),
        };

        let mut param = Parameters::new();
        param.add("room_id", room_id)?;
        param.add("room", room)?;
        param.add("auth", auth)?;

        let res = db
            .mutate(
                "mutate {
            sys.OwnedInvite {
                room_id:$room_id
                room: $room
                authorisation: $auth 
            }
        }",
                Some(param),
            )
            .await?;
        #[derive(Deserialize)]
        struct Id {
            id: String,
        }
        let mut parser = ResultParser::new(&res).unwrap();
        let id: Id = parser.take_object("sys.OwnedInvite").unwrap();

        let invite_id = id.id;
        let invite_id = uid_decode(&invite_id)?;
        let hash_val = Self::hash_val(invite_id, &application);
        let (_key, invite_sign) = db.sign(hash_val).await;

        let invite = Self {
            invite_id,
            application,
            invite_sign,
        };

        let owned = OwnedInvite {
            id: invite_id,
            room: default_room_id,
            authorisation: default_auth_id,
        };

        Ok((invite, owned))
    }

    pub async fn delete(
        room_id: String,
        invite_id: Uid,
        db: &GraphDatabaseService,
    ) -> Result<(), crate::Error> {
        let mut param = Parameters::new();
        param.add("room_id", room_id.clone())?;
        param.add("invite_id", uid_encode(&invite_id))?;

        let result = db
            .query(
                "query{
        sys.Invite(room_id=$room_id, invite_id = $invite_id){
                id
            }
        }",
                Some(param),
            )
            .await?;

        #[derive(Deserialize)]
        struct InvId {
            id: String,
        }

        let mut q = ResultParser::new(&result)?;
        let ids: Vec<InvId> = q.take_array("sys.Invite")?;

        for id in ids {
            let mut param = Parameters::new();
            param.add("id", id.id)?;

            db.delete(
                "delete {
            sys.Invite{
                $id
            }
        }",
                Some(param),
            )
            .await?;
        }

        Ok(())
    }

    pub async fn insert(
        &self,
        room_id: String,
        db: &GraphDatabaseService,
    ) -> Result<(), crate::Error> {
        let mut param = Parameters::new();
        param.add("room_id", room_id.clone())?;
        param.add("invite_id", uid_encode(&self.invite_id))?;

        let result = db
            .query(
                "query{
            sys.Invite(room_id=$room_id,invite_id=$invite_id ){
                id
            }
        }",
                Some(param),
            )
            .await?;

        #[derive(Deserialize)]
        struct InvId {
            id: String,
        }
        let mut q = ResultParser::new(&result)?;
        let ids: Vec<InvId> = q.take_array("sys.Invite")?;

        if !ids.is_empty() {
            return Ok(());
        }

        let mut param = Parameters::new();
        param.add("room_id", room_id)?;
        param.add("invite_id", uid_encode(&self.invite_id))?;
        param.add("application", self.application.clone())?;
        param.add("invite_sign", base64_encode(&self.invite_sign))?;

        db.mutate(
            "mutate {
            sys.Invite {
                room_id: $room_id
                invite_id: $invite_id
                application: $application
                invite_sign: $invite_sign
            }
        }",
            Some(param),
        )
        .await?;
        Ok(())
    }

    pub async fn list(
        room_id: String,
        db: &GraphDatabaseService,
    ) -> Result<Vec<Self>, crate::Error> {
        let mut param = Parameters::new();
        param.add("room_id", room_id)?;

        let result = db
            .query(
                "query{
            sys.Invite(room_id=$room_id, order_by(mdate desc)){
                invite_id
                application
                invite_sign
            }
        }",
                Some(param),
            )
            .await?;

        #[derive(Deserialize)]
        struct SerInvite {
            invite_id: String,
            application: String,
            invite_sign: String,
        }

        let mut list = Vec::new();
        let mut q = ResultParser::new(&result)?;
        let invites: Vec<SerInvite> = q.take_array("sys.Invite")?;
        for invite in invites {
            let invite_id = uid_decode(&invite.invite_id)?;
            let application = invite.application;
            let invite_sign = base64_decode(invite.invite_sign.as_bytes())?;

            list.push(Self {
                invite_id,
                application,
                invite_sign,
            })
        }
        Ok(list)
    }

    pub fn hash(&self) -> Vec<u8> {
        Self::hash_val(self.invite_id, &self.application)
    }

    fn hash_val(invite_id: Uid, application: &String) -> Vec<u8> {
        let mut hasher = blake3::Hasher::new();
        hasher.update(&invite_id);
        hasher.update(application.as_bytes());
        let hash = hasher.finalize();
        hash.as_bytes().to_vec()
    }
}

///
/// When creating an invitation, you may specify a default room and authorisation.
/// New peers joining using this invitation will be inserted in this room.
///
pub struct DefaultRoom {
    pub room: String,
    pub authorisation: String,
}

#[cfg(test)]
mod tests {
    use crate::log_service::LogService;
    use crate::security::{Ed25519SigningKey, HardwareFingerprint};
    use crate::Configuration;
    use crate::{event_service::EventService, security::random32};

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
        let (reply, mut receive) = mpsc::channel::<Result<Vec<Node>, Error>>(1);

        Peer::get_peers(keys, 400 * 1024, &reply, &conn1).unwrap();

        let nodes = receive.blocking_recv().unwrap().unwrap();
        assert_eq!(nodes.len(), num_peer);

        let mut pn = PeerNodes { nodes };

        pn.write(&conn2).unwrap();

        let missing = Peer::get_missing(peers, &conn2).unwrap();
        assert_eq!(missing.len(), 0);
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn init_allowed_peer() {
        init_database_path();

        let path: PathBuf = DATA_PATH.into();
        let secret = random32();
        let pub_key = &random32();

        let base_result = {
            let (app, _verifying_key, _private_room) = GraphDatabaseService::start(
                "authorisation app",
                "",
                &secret,
                &pub_key,
                path.clone(),
                &Configuration::default(),
                EventService::new(),
                LogService::start(),
            )
            .await
            .unwrap();

            let res = app
                .query(
                    "query {
                    sys.AllowedPeer{
                        meeting_token
                        status
                        peer {
                            id
                            mdate
                            cdate
                            verifying_key
                            pub_key
                        }
                    }
                }",
                    None,
                )
                .await
                .unwrap();

            assert!(res.len() > 240); //make sure that it contains stuff

            res
        };
        {
            let (app, _verifying_key, _private_room) = GraphDatabaseService::start(
                "authorisation app",
                "",
                &secret,
                &pub_key,
                path,
                &Configuration::default(),
                EventService::new(),
                LogService::start(),
            )
            .await
            .unwrap();

            let res = app
                .query(
                    "query {
                    sys.AllowedPeer{
                        meeting_token
                        status
                        peer {
                            id
                            mdate
                            cdate
                            verifying_key
                            pub_key
                        }
                    }
                }",
                    None,
                )
                .await
                .unwrap();
            //ensure that we get the same result when reading the same database again
            assert_eq!(res, base_result);
        }

        let path: PathBuf = format!("{}/otherpaht", DATA_PATH).into();
        let (app, _verifying_key, _private_room) = GraphDatabaseService::start(
            "authorisation app",
            "",
            &secret,
            &pub_key,
            path,
            &Configuration::default(),
            EventService::new(),
            LogService::start(),
        )
        .await
        .unwrap();

        let res = app
            .query(
                "query {
                sys.AllowedPeer{
                    meeting_token
                    status
                    peer {
                        id
                        mdate
                        cdate
                        verifying_key
                        pub_key
                    }
                }
            }",
                None,
            )
            .await
            .unwrap();
        //ensure that we get the same result when creating a database with the same credentials
        assert_eq!(res, base_result);
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn get_allowed() {
        init_database_path();

        let path: PathBuf = DATA_PATH.into();
        let secret = random32();
        let pub_key = &random32();

        let (app, _verifying_key, private_room) = GraphDatabaseService::start(
            "authorisation app",
            "",
            &secret,
            &pub_key,
            path.clone(),
            &Configuration::default(),
            EventService::new(),
            LogService::start(),
        )
        .await
        .unwrap();

        let list = app.get_allowed_peers(private_room).await.unwrap();

        assert_eq!(1, list.len());
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn hardware() {
        init_database_path();

        let path: PathBuf = DATA_PATH.into();
        let secret = random32();
        let pub_key = &random32();

        let (app, _verifying_key, private_room) = GraphDatabaseService::start(
            "authorisation app",
            "",
            &secret,
            &pub_key,
            path.clone(),
            &Configuration::default(),
            EventService::new(),
            LogService::start(),
        )
        .await
        .unwrap();

        let hardware = HardwareFingerprint::new().unwrap();

        let status = "allowed";

        AllowedHardware::put(hardware.id, private_room, &hardware.name, status, &app)
            .await
            .unwrap();

        let allowed = AllowedHardware::get(hardware.id, private_room, status, &app)
            .await
            .unwrap();

        assert!(allowed.is_some());
        let allowed = allowed.unwrap();
        assert_eq!(hardware.name, allowed.name);
        assert_eq!(status, allowed.status);

        let disabled = "disabled";
        AllowedHardware::put(hardware.id, private_room, &hardware.name, disabled, &app)
            .await
            .unwrap();

        let allowed = AllowedHardware::get(hardware.id, private_room, status, &app)
            .await
            .unwrap();

        assert!(allowed.is_none());

        let allowed = AllowedHardware::get(hardware.id, private_room, disabled, &app)
            .await
            .unwrap();

        assert!(allowed.is_some());
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn invite() {
        init_database_path();

        let path: PathBuf = DATA_PATH.into();
        let secret = random32();
        let pub_key = &random32();

        let (db, _verifying_key, private_room) = GraphDatabaseService::start(
            "authorisation app",
            "",
            &secret,
            &pub_key,
            path.clone(),
            &Configuration::default(),
            EventService::new(),
            LogService::start(),
        )
        .await
        .unwrap();

        let (invite, _) = Invite::create(
            uid_encode(&private_room),
            None,
            "authorisation app".to_string(),
            &db,
        )
        .await
        .unwrap();

        let prod_list = OwnedInvite::list_valid(uid_encode(&private_room), &db)
            .await
            .unwrap();

        assert_eq!(prod_list.len(), 1);

        for prod in prod_list {
            OwnedInvite::delete(prod.id, &db).await.unwrap();
        }

        invite.insert(uid_encode(&private_room), &db).await.unwrap();
        invite.insert(uid_encode(&private_room), &db).await.unwrap();
        invite.insert(uid_encode(&private_room), &db).await.unwrap();
        invite.insert(uid_encode(&private_room), &db).await.unwrap();

        let prod_list = OwnedInvite::list_valid(uid_encode(&private_room), &db)
            .await
            .unwrap();
        assert_eq!(prod_list.len(), 0);

        let ins_list = Invite::list(uid_encode(&private_room), &db).await.unwrap();
        assert_eq!(ins_list.len(), 1);
        Invite::delete(uid_encode(&private_room), invite.invite_id, &db)
            .await
            .unwrap();

        let ins_list = Invite::list(uid_encode(&private_room), &db).await.unwrap();
        assert_eq!(ins_list.len(), 0);

        let bin_invite = bincode::serialize(&invite).unwrap();
        println!("Invite: {}", base64_encode(&bin_invite));

        drop(db);
    }
}
