use std::collections::{HashMap, HashSet};
use std::thread;

use rusqlite::{Connection, OptionalExtension};
use serde::{Deserialize, Serialize};
use tokio::sync::mpsc::{self, Sender};
use tokio::sync::oneshot;

use crate::cryptography::{base64_encode, Ed2519KeyPair};
use crate::database::{
    database_service::FromRow,
    datamodel::{now, RowFlag},
    edge_table::Edge,
    node_table::Node,
    Error, Result,
};

use super::database_service::set_pragma;

pub const PEER_SCHEMA: &str = "p";
pub const POLICY_GROUP_SCHEMA: &str = "g";
pub const POLICY_SCHEMA: &str = "$";

//https://arstechnica.com/information-technology/2023/02/lastpass-hackers-infected-employees-home-computer-and-stole-corporate-vault/

pub enum PolicyMsg {
    ValidateNode {
        policy_group: Vec<u8>,
        node: Node,
    },
    ValidateEdge {
        policy_group: Vec<u8>,
        edge: Edge,
    },
    ValidateSourceAndEdges {
        policy_group: Vec<u8>,
        edge: Vec<Edge>,
        source_node: Node,
    },
    RefreshCache {
        policy_group: Vec<u8>,
    },
}
pub struct ProcessPolicyMsg {
    policy_msg: Vec<PolicyMsg>,
    reply: oneshot::Sender<Vec<Result<PolicyMsg>>>,
}

#[derive(Clone)]
pub struct SecurityPolicyService {
    send_msg: Sender<ProcessPolicyMsg>,
}
impl SecurityPolicyService {
    pub fn start(conn: Connection) -> Self {
        let _ = set_pragma("query_only", "1", &conn);

        let (send_msg, mut receiv_msg) = mpsc::channel::<ProcessPolicyMsg>(10);
        thread::spawn(move || {
            let mut security_policy = SecurityPolicy::new();

            while let Some(to_process) = receiv_msg.blocking_recv() {
                let mut reply: Vec<std::result::Result<PolicyMsg, Error>> = vec![];
                for msg in to_process.policy_msg {
                    match &msg {
                        PolicyMsg::ValidateNode { policy_group, node } => {
                            let validation =
                                security_policy.validate_node(&policy_group, &node, &conn);

                            if let Err(e) = validation {
                                reply.push(Err(e));
                            } else {
                                reply.push(Ok(msg));
                            }
                        }
                        PolicyMsg::ValidateEdge { policy_group, edge } => {
                            let validation =
                                security_policy.validate_edge(&policy_group, &edge, &conn);
                            if let Err(e) = validation {
                                reply.push(Err(e));
                            } else {
                                reply.push(Ok(msg));
                            }
                        }
                        PolicyMsg::ValidateSourceAndEdges {
                            policy_group,
                            edge,
                            source_node,
                        } => {
                            let validation =
                                security_policy.validate_node(&policy_group, &source_node, &conn);
                            if let Err(e) = validation {
                                reply.push(Err(e));
                            } else {
                                let mut validation = None;
                                for edg in edge {
                                    let val = security_policy.validate_edge_node(
                                        &policy_group,
                                        &edg,
                                        &source_node,
                                        &conn,
                                    );
                                    if let Err(e) = val {
                                        validation = Some(e);
                                    }
                                }
                                if let Some(e) = validation {
                                    reply.push(Err(e));
                                    break;
                                } else {
                                    reply.push(Ok(msg));
                                }
                            }
                        }
                        PolicyMsg::RefreshCache { policy_group } => {
                            let validation = security_policy.refresh_cache(&policy_group, &conn);
                            if let Err(e) = validation {
                                reply.push(Err(e));
                            } else {
                                reply.push(Ok(msg));
                            }
                        }
                    }
                }
                let _ = to_process.reply.send(reply);
            }
        });

        Self { send_msg }
    }

    pub async fn validate_async(
        &self,
        policy_msg: Vec<PolicyMsg>,
    ) -> Result<Vec<Result<PolicyMsg>>> {
        let (send_response, receive_response) = oneshot::channel::<Vec<Result<PolicyMsg>>>();
        let process_msg = ProcessPolicyMsg {
            policy_msg,
            reply: send_response,
        };
        self.send_msg
            .send(process_msg)
            .await
            .map_err(|e| Error::TokioSendError(e.to_string()))?;

        let response = receive_response.await?;
        Ok(response)
    }

    pub fn validate_blocking(&self, policy_msg: Vec<PolicyMsg>) -> Result<Vec<Result<PolicyMsg>>> {
        let (send_response, receive_response) = oneshot::channel::<Vec<Result<PolicyMsg>>>();
        let process_msg = ProcessPolicyMsg {
            policy_msg,
            reply: send_response,
        };
        self.send_msg
            .blocking_send(process_msg)
            .map_err(|e| Error::TokioSendError(e.to_string()))?;

        let response = receive_response.blocking_recv()?;
        Ok(response)
    }
}

pub struct PolicyRight {}
impl PolicyRight {
    //enabled: can create schema
    pub const CREATE: i8 = 0b0000001;

    //enabled:  can read
    //disabled: peer can only read it's on rows
    pub const READ: i8 = 0b000010;

    //enabled: can update any rows, including deleting
    //disabled: can only update owned rows
    pub const UPDATE_ANY: i8 = 0b0000100;

    pub fn is(flag: &i8, right: &i8) -> bool {
        flag & right > 0
    }
}

//
// Define rights on specific schema
//
#[derive(Default, Serialize, Deserialize, Debug)]
pub struct Policy {
    //define rights for specific schema
    schema_policies: HashMap<String, i8>,

    //define wich shema ->schema link is allowed
    //Both schema must have schema_policies defined to work propertly
    edge_policie: HashMap<String, HashSet<String>>,
}
impl Policy {
    pub fn set_right(&mut self, schema: &str, right: i8) {
        self.schema_policies.insert(schema.to_string(), right);
    }

    pub fn has_right(&self, schema: &str, right: &i8) -> bool {
        if let Some(flag) = self.schema_policies.get(schema) {
            return PolicyRight::is(flag, right);
        }
        false
    }
    pub fn add_edge_policy(&mut self, source: &str, target: &str) {
        let poli = self.edge_policie.remove(source);
        let mut v = if let Some(targets) = poli {
            targets
        } else {
            HashSet::new()
        };
        v.insert(target.to_string());
        self.edge_policie.insert(source.to_string(), v);
    }

    pub fn has_edge_policy(&self, source: &str, target: &str) -> bool {
        let poli = self.edge_policie.get(source);
        if let Some(t) = poli {
            return t.contains(target);
        }
        false
    }
}
#[derive(Debug)]
pub struct PolicyNode {
    pub node: Node,
    pub policy: Policy,
}
impl PolicyNode {
    pub fn sign(
        &mut self,
        keypair: &Ed2519KeyPair,
    ) -> std::result::Result<(), crate::database::Error> {
        self.node.json = Some(serde_json::to_string(&self.policy)?);
        self.node.sign(keypair)?;
        Ok(())
    }
}
impl Default for PolicyNode {
    fn default() -> Self {
        Self {
            node: Node {
                schema: POLICY_SCHEMA.to_string(),
                cdate: now(),
                flag: RowFlag::KEEP_HISTORY, //it is mandatory to keep an history of the policy to be able to validate the history of every inserted edges
                ..Default::default()
            },
            policy: Default::default(),
        }
    }
}

///

///
/// chat_policy
///     message rw
///     chat rw
///     message->chat
///
/// message chat
///    find target chat group_policy SELECT pol_id FROM edge where source=? join node where id=target and schema= policy
///         verify read for user
///    find message group policy   SELECT pol_id FROM edge where source=? join node where id=target and schema= policy
///         verify write/update any for user
///         verify link autorized
///
/// peer policy
///     follow -> RW
///     follow -> *
/// ind target chat group_policy SELECT pol_id FROM edge where source=? join node where id=target and schema= policy
///         verify read for user
///    find message group policy   SELECT pol_id FROM edge where source=? join node where id=target and schema= policy
///         verify write/update any for user
#[derive(Default)]
struct PolicyCache {
    policy: HashMap<Vec<u8>, Vec<PolicyNode>>,
    peer_policy: HashMap<Vec<u8>, HashMap<Vec<u8>, Vec<Edge>>>,
}
impl PolicyCache {
    pub fn can_insert_node(&self, node: &Node, peer: &Vec<u8>) -> bool {
        if let Some(peer_policy) = self.peer_policy.get(peer) {
            for (policy_key, edges) in peer_policy {
                if let Some(policy_nodes) = self.policy.get(policy_key) {
                    let mut some_policy: Option<&PolicyNode> = None;
                    for pol in policy_nodes {
                        if pol.node.mdate <= node.mdate {
                            some_policy = Some(pol);
                        } else {
                            break;
                        }
                    }
                    // println!("  policy: {:?}", some_policy);
                    let mut some_peer = None;
                    for edge in edges {
                        if edge.date <= node.mdate {
                            some_peer = Some(edge);
                        } else {
                            break;
                        }
                    }
                    // println!("  edge: {:?}", some_policy);
                    if Self::check_node_right(some_policy, some_peer, node) {
                        return true;
                    }
                }
            }
        }
        false
    }

    fn check_node_right(
        some_policy: Option<&PolicyNode>,
        some_peer: Option<&Edge>,
        node: &Node,
    ) -> bool {
        if let Some(pol) = some_policy {
            if let Some(peer) = some_peer {
                if !RowFlag::is(peer.flag, &RowFlag::DELETED)
                    && !RowFlag::is(pol.node.flag, &RowFlag::DELETED)
                {
                    let write = pol.policy.has_right(&node.schema, &PolicyRight::CREATE);

                    if write {
                        if peer.pub_key.eq(&node.pub_key) {
                            return true;
                        } else {
                            let update =
                                pol.policy.has_right(&node.schema, &PolicyRight::UPDATE_ANY);
                            if update {
                                return true;
                            }
                        }
                    }
                }
            }
        }
        false
    }
    pub fn can_insert_edge(
        &self,
        source: &Node,
        target: &Node,
        edge: &Edge,
        peer: &Vec<u8>,
    ) -> bool {
        if let Some(peer_policy) = self.peer_policy.get(peer) {
            for (policy_key, edges) in peer_policy {
                if let Some(policy_nodes) = self.policy.get(policy_key) {
                    let mut some_policy: Option<&PolicyNode> = None;
                    for pol in policy_nodes {
                        if pol.node.mdate <= edge.date {
                            some_policy = Some(pol);
                        } else {
                            break;
                        }
                    }
                    //    println!("  policy: {:?}", some_policy);
                    let mut some_peer = None;
                    for edge in edges {
                        if edge.date <= edge.date {
                            some_peer = Some(edge);
                        } else {
                            break;
                        }
                    }
                    //  println!("  edge: {:?}", some_policy);
                    if Self::check_edge_right(source, target, edge, some_policy, some_peer) {
                        return true;
                    }
                }
            }
        }
        false
    }
    fn check_edge_right(
        source: &Node,
        target: &Node,
        edge: &Edge,
        some_policy: Option<&PolicyNode>,
        some_peer: Option<&Edge>,
    ) -> bool {
        if let Some(pol) = some_policy {
            if let Some(peer) = some_peer {
                if !RowFlag::is(peer.flag, &RowFlag::DELETED)
                    && !RowFlag::is(pol.node.flag, &RowFlag::DELETED)
                {
                    if !pol.policy.has_edge_policy(&source.schema, &target.schema) {
                        return false;
                    }
                    let write = pol.policy.has_right(&source.schema, &PolicyRight::CREATE);
                    if write {
                        if peer.pub_key.eq(&edge.pub_key) {
                            return true;
                        } else {
                            let update = pol
                                .policy
                                .has_right(&source.schema, &PolicyRight::UPDATE_ANY);
                            if update {
                                return true;
                            }
                        }
                    }
                }
            }
        }
        false
    }
}

//graph traversal: policy->peer
const PEER_IN_POLICY_GROUP_QUERY: &str = r#"
SELECT 1
FROM  edge_all peer_edge
WHERE 
    peer_edge.source = ?
    AND peer_edge.target = ?
    AND peer_edge.flag & 1 = 0
    AND peer_edge.date = (SELECT max(date) FROM edge_all WHERE source = peer_edge.source AND target = peer_edge.target AND date <= ?)
    
LIMIT 1
"#;

//graph traversal: policy->policy_group->peer
const ADMIN_PEER_FOR_POLICY_QUERY: &str = r#"
SELECT 1
FROM edge_all policy_edge 
JOIN node_sys node_policy_grp ON
    node_policy_grp.id = policy_edge.source
    AND node_policy_grp.flag & 1 = 0
    AND node_policy_grp.mdate = (SELECT max(mdate) FROM node_sys WHERE id= node_policy_grp.id AND schema = node_policy_grp.schema AND mdate <= ?)
JOIN edge_all peer_edge ON 
    node_policy_grp.id=peer_edge.source
    AND peer_edge.target=?
    AND peer_edge.flag & 1 = 0
    AND peer_edge.date = (SELECT max(date) FROM edge_all WHERE source = peer_edge.source AND target = peer_edge.target AND date <= ?)
WHERE 
    policy_edge.target=?
    AND policy_edge.flag & 1 = 0
    AND policy_edge.date = (SELECT max(date) FROM edge_all WHERE source = policy_edge.source AND target = policy_edge.target AND date <= ?)
LIMIT 1
"#;
struct SecurityPolicy {
    policy_group_cache: HashMap<Vec<u8>, PolicyCache>,
}
impl SecurityPolicy {
    pub fn new() -> Self {
        Self {
            policy_group_cache: HashMap::new(),
        }
    }

    fn cache_policy_group(&mut self, policy_group: &Vec<u8>, conn: &Connection) -> Result<()> {
        let mut stmt = conn.prepare_cached(
            "SELECT distinct policy.* 
        FROM edge_all 
        JOIN node_all policy 
            ON policy.id = edge_all.target AND policy.schema = ? 
        WHERE edge_all.source=?
        ORDER BY policy.mdate",
        )?;
        let nodes = stmt.query_map((POLICY_SCHEMA, policy_group.clone()), Node::from_row())?;

        for node in nodes {
            let node = *node?;
            self.add_policy(policy_group, node)?;
        }
        Ok(())
    }

    fn add_policy(&mut self, policy_group: &Vec<u8>, policy_node: Node) -> Result<()> {
        if let Some(val) = &policy_node.json {
            let policy = serde_json::from_str(val)?;
            let policy_node = PolicyNode {
                node: policy_node,
                policy,
            };

            if let Some(policy_cache) = self.policy_group_cache.get_mut(policy_group) {
                if let Some(pol) = policy_cache.policy.get_mut(&policy_node.node.id) {
                    pol.push(policy_node);
                } else {
                    policy_cache
                        .policy
                        .insert(policy_node.node.id.clone(), vec![policy_node]);
                }
            } else {
                let mut policy_cache = PolicyCache {
                    ..Default::default()
                };

                policy_cache
                    .policy
                    .insert(policy_node.node.id.clone(), vec![policy_node]);
                self.policy_group_cache
                    .insert(policy_group.clone(), policy_cache);
            }
            //   }
        }
        Ok(())
    }

    fn cache_peer_policy(&mut self, policy_group: &Vec<u8>, conn: &Connection) -> Result<()> {
        let mut stmt = conn.prepare_cached(
            "SELECT distinct peer.*
        FROM edge_all
        JOIN node policy ON 
            policy.id = edge_all.target AND policy.schema= ? 
        JOIN edge_all peer
            ON peer.source = policy.id
        WHERE edge_all.source = ?
        ORDER BY peer.date",
        )?;
        let edges = stmt.query_map((POLICY_SCHEMA, policy_group.clone()), Edge::from_row())?;
        for edge in edges {
            let edge = *edge?;
            self.add_peer_policy(policy_group, edge);
        }
        Ok(())
    }

    fn add_peer_policy(&mut self, policy_group: &Vec<u8>, peer_policy: Edge) {
        if let Some(policy_cache) = self.policy_group_cache.get_mut(policy_group) {
            if let Some(pol_map) = policy_cache.peer_policy.get_mut(&peer_policy.target) {
                if let Some(edge_list) = pol_map.get_mut(&peer_policy.source) {
                    edge_list.push(peer_policy);
                } else {
                    pol_map.insert(peer_policy.source.clone(), vec![peer_policy]);
                }
            } else {
                let mut pol_map: HashMap<Vec<u8>, Vec<Edge>> = HashMap::new();
                let target = peer_policy.target.clone();
                pol_map.insert(peer_policy.source.clone(), vec![peer_policy]);
                policy_cache.peer_policy.insert(target, pol_map);
            }
        } else {
            let mut policy_cache = PolicyCache {
                ..Default::default()
            };
            let mut pol_map: HashMap<Vec<u8>, Vec<Edge>> = HashMap::new();
            let target = peer_policy.target.clone();
            pol_map.insert(peer_policy.source.clone(), vec![peer_policy]);
            policy_cache.peer_policy.insert(target, pol_map);

            self.policy_group_cache
                .insert(policy_group.clone(), policy_cache);
        }
    }

    pub fn refresh_cache(&mut self, policy_group: &Vec<u8>, conn: &Connection) -> Result<()> {
        self.policy_group_cache.remove(policy_group);

        self.cache_policy_group(policy_group, conn)?;
        self.cache_peer_policy(policy_group, conn)?;
        Ok(())
    }

    fn get_cache(&mut self, policy_group: &Vec<u8>, conn: &Connection) -> Result<&PolicyCache> {
        if self.policy_group_cache.is_empty() {
            self.cache_policy_group(policy_group, conn)?;
            self.cache_peer_policy(policy_group, conn)?;
        }
        if let Some(policy_cache) = self.policy_group_cache.get(policy_group) {
            return Ok(policy_cache);
        } else {
            Err(crate::database::Error::PolicyError(format!(
                "unknown policy group: {} ",
                base64_encode(policy_group)
            )))
        }
    }

    pub fn validate_node(
        &mut self,
        policy_group: &Vec<u8>,
        node: &Node,
        conn: &Connection,
    ) -> Result<()> {
        if (node.schema.eq(POLICY_SCHEMA) || node.schema.eq(POLICY_GROUP_SCHEMA))
            && !RowFlag::is(node.flag, &RowFlag::KEEP_HISTORY)
        {
            return Err(Error::PolicyError(
                "Must keep the policy update history to be able to validate data consistency"
                    .to_string(),
            ));
        }
        let mut stmt = conn.prepare_cached(
            "SELECT node_all.* FROM node_all WHERE id=? ORDER BY mdate DESC LIMIT 1",
        )?;

        let previous_version = stmt.query_row([&node.id], Node::from_row()).optional()?;

        let previous_version = if let Some(node) = previous_version {
            node
        } else {
            return Ok(());
        };

        if node.schema.eq(POLICY_GROUP_SCHEMA) {
            if previous_version.mdate > node.mdate {
                return Err(Error::PolicyError(format!(
                    "A more recent version exists for the policy group: '{}'",
                    base64_encode(&node.id)
                )));
            }
            let mut stmt = conn.prepare_cached(PEER_IN_POLICY_GROUP_QUERY)?;

            let user: Option<i64> = stmt
                .query_row((&node.id, &node.pub_key, node.mdate), |row| row.get(0))
                .optional()?;

            if user.is_some() {
                Ok(())
            } else {
                return Err(Error::PolicyError(format!(
                    "Peer '{}' cannot update this policy group '{}'",
                    base64_encode(&node.pub_key),
                    base64_encode(&node.id)
                )));
            }
        } else if node.schema.eq(POLICY_SCHEMA) {
            if previous_version.mdate > node.mdate {
                return Err(Error::PolicyError(format!(
                    "A more recent version exists for the policy: '{}'",
                    base64_encode(&node.id)
                )));
            }
            let mut stmt = conn.prepare_cached(ADMIN_PEER_FOR_POLICY_QUERY)?;

            let user: Option<i64> = stmt
                .query_row(
                    (
                        &node.mdate,
                        &node.pub_key,
                        &node.mdate,
                        &node.id,
                        &node.mdate,
                    ),
                    |row| row.get(0),
                )
                .optional()?;

            if user.is_some() {
                return Ok(());
            } else {
                return Err(Error::PolicyError(format!(
                    "Peer '{}' cannot update this policy '{}'",
                    base64_encode(&node.pub_key),
                    base64_encode(&node.id)
                )));
            }
        } else {
            if previous_version.pub_key.eq(&node.pub_key) {
                return Ok(());
            }
            let policy_cache = self.get_cache(policy_group, conn)?;
            if policy_cache.can_insert_node(&node, &node.pub_key) {
                return Ok(());
            } else {
                return Err(Error::PolicyError(format!(
                    "Peer '{}' has insufficient rights to insert this node: '{}'",
                    base64_encode(&node.pub_key),
                    base64_encode(&node.id),
                )));
            }
        }
    }

    pub fn validate_edge(
        &mut self,
        policy_group: &Vec<u8>,
        edge: &Edge,
        conn: &Connection,
    ) -> Result<()> {
        let mut stmt =
            conn.prepare_cached("SELECT * FROM node_all WHERE id=? ORDER BY mdate DESC LIMIT 1")?;
        let res = stmt
            .query_row([&edge.source], Node::from_row())
            .optional()?;

        let source_node = if let Some(nod) = res {
            nod
        } else {
            return Err(Error::PolicyError(format!(
                "unknown edge source {} ",
                base64_encode(&edge.source),
            )));
        };
        self.validate_edge_node(policy_group, edge, &source_node, conn)
    }

    pub fn validate_edge_node(
        &mut self,
        policy_group: &Vec<u8>,
        edge: &Edge,
        source_node: &Node,
        conn: &Connection,
    ) -> Result<()> {
        let mut stmt =
            conn.prepare_cached("SELECT * FROM node_all WHERE id=? ORDER BY mdate DESC LIMIT 1")?;

        let res = stmt
            .query_row([&edge.target], Node::from_row())
            .optional()?;
        let target_node = if let Some(nod) = res {
            nod
        } else {
            return Err(Error::PolicyError(format!(
                "unknown edge target {} ",
                base64_encode(&edge.target),
            )));
        };

        if source_node.schema.eq(POLICY_SCHEMA) || source_node.schema.eq(POLICY_GROUP_SCHEMA) {
            if !RowFlag::is(edge.flag, &RowFlag::KEEP_HISTORY) {
                return Err(Error::PolicyError(
                    "Must keep the policy update history to be able to validate data consistency"
                        .to_string(),
                ));
            }

            let mut stmt = conn.prepare_cached(
                "SELECT * FROM edge_all WHERE source = ? AND target = ? ORDER BY date DESC LIMIT 1",
            )?;

            let previous_edge = stmt
                .query_row([&edge.source, &edge.target], Edge::from_row())
                .optional()?;
            if let Some(p) = previous_edge {
                if p.date > edge.date {
                    return Err(Error::PolicyError(format!(
                        "A more recent version exists for the policy edge: '{}'->'{}'",
                        base64_encode(&edge.source),
                        base64_encode(&edge.target)
                    )));
                }
            }

            if source_node.schema.eq(POLICY_GROUP_SCHEMA) {
                if !(target_node.schema.eq(POLICY_SCHEMA) || target_node.schema.eq(PEER_SCHEMA)) {
                    return Err(Error::PolicyError(format!(
                        "Target for policy group can only be '{}' or '{}'",
                        POLICY_SCHEMA, PEER_SCHEMA
                    )));
                }

                if edge.pub_key.eq(&source_node.pub_key) {
                    return Ok(());
                }

                let mut stmt = conn.prepare_cached(PEER_IN_POLICY_GROUP_QUERY)?;
                let rows: Option<i64> = stmt
                    .query_row((&edge.pub_key, &edge.date, &edge.source), |row| row.get(0))
                    .optional()?;

                if rows.is_some() {
                    return Ok(());
                } else {
                    return Err(Error::PolicyError(format!(
                        "Peer '{}' is not allowed to modify this policy group",
                        base64_encode(&edge.pub_key),
                    )));
                }
            }
            if source_node.schema.eq(POLICY_SCHEMA) {
                if !target_node.schema.eq(PEER_SCHEMA) {
                    return Err(Error::PolicyError(format!(
                        "Target for policy can only be '{}'",
                        PEER_SCHEMA
                    )));
                }
                if edge.pub_key.eq(&source_node.pub_key) {
                    return Ok(());
                }
                let mut stmt = conn.prepare_cached(ADMIN_PEER_FOR_POLICY_QUERY)?;
                let mut rows = stmt.query((
                    edge.date,
                    edge.pub_key.clone(),
                    edge.date,
                    edge.source.clone(),
                    edge.date,
                ))?;
                let mut user: Vec<i32> = Vec::new();
                while let Some(row) = rows.next()? {
                    user.push(row.get(0)?);
                }

                if !user.is_empty() {
                    return Ok(());
                } else {
                    return Err(Error::PolicyError(format!(
                        "Peer '{}' is not allowed to modify this policy",
                        base64_encode(&edge.pub_key),
                    )));
                }
            }
        } else {
            if target_node.schema.eq(POLICY_GROUP_SCHEMA) && edge.pub_key.eq(&source_node.pub_key) {
                return Ok(());
            }

            let policy_cache = self.get_cache(policy_group, conn)?;
            if policy_cache.can_insert_edge(&source_node, &target_node, &edge, &edge.pub_key) {
                return Ok(());
            } else {
                return Err(Error::PolicyError(format!(
                    "Peer '{}' has insufficient rights to insert this edge: '{}'->'{}'",
                    base64_encode(&edge.pub_key),
                    base64_encode(&edge.source),
                    base64_encode(&edge.target),
                )));
            }
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {

    use std::{
        error::Error,
        fs,
        path::{Path, PathBuf},
    };

    use rusqlite::Connection;

    use crate::{
        cryptography::{Ed2519KeyPair, KeyPair},
        database::security_policy::{
            PolicyNode, PolicyRight, SecurityPolicy, PEER_SCHEMA, POLICY_GROUP_SCHEMA,
            POLICY_SCHEMA,
        },
        database::{
            database_service::Writable,
            datamodel::{now, prepare_connection, RowFlag},
            edge_table::Edge,
            node_table::Node,
        },
    };

    const DATA_PATH: &str = "test/security/";
    fn init_database_path(file: &str) -> Result<PathBuf, Box<dyn Error>> {
        let mut path: PathBuf = DATA_PATH.into();
        fs::create_dir_all(&path)?;
        path.push(file);
        if Path::exists(&path) {
            fs::remove_file(&path)?;
        }
        Ok(path)
    }

    #[test]
    fn validate_node_policy_group() {
        let conn = Connection::open_in_memory().unwrap();
        prepare_connection(&conn).unwrap();
        let mut security_policy = SecurityPolicy::new();
        let keypair = Ed2519KeyPair::new();

        let mut peer = Node {
            id: keypair.export_public(),
            schema: PEER_SCHEMA.to_string(),
            cdate: now(),
            ..Default::default()
        };
        peer.sign(&keypair).unwrap();
        peer.write(&conn).unwrap();

        let mut policy_group = Node {
            schema: POLICY_GROUP_SCHEMA.to_string(),
            cdate: now(),
            text: Some("A Chat Room".to_string()),
            ..Default::default()
        };
        policy_group.sign(&keypair).unwrap();
        let pol_group_id = policy_group.id.clone();

        security_policy
            .validate_node(&pol_group_id, &policy_group, &conn)
            .expect_err("KEEP_HISTORY flag not set");

        policy_group.flag = RowFlag::KEEP_HISTORY;
        policy_group.sign(&keypair).unwrap();
        security_policy
            .validate_node(&pol_group_id, &policy_group, &conn)
            .unwrap();
        policy_group.write(&conn).unwrap();

        let mut user_edge = Edge {
            source: policy_group.id.clone(),
            target: peer.id.clone(),
            date: now(),
            flag: RowFlag::KEEP_HISTORY,
            ..Default::default()
        };
        user_edge.sign(&keypair).unwrap();
        user_edge.write(&conn).unwrap();

        policy_group.mdate -= 100;
        policy_group.sign(&keypair).unwrap();

        security_policy
            .validate_node(&pol_group_id, &policy_group, &conn)
            .expect_err("A more recent version exists");

        policy_group.mdate += 1000;
        policy_group.sign(&keypair).unwrap();
        security_policy
            .validate_node(&pol_group_id, &policy_group, &conn)
            .unwrap();

        let bad_keypair = Ed2519KeyPair::new();
        policy_group.sign(&bad_keypair).unwrap();
        security_policy
            .validate_node(&pol_group_id, &policy_group, &conn)
            .expect_err("Invalid Peer");

        policy_group.sign(&keypair).unwrap();
        policy_group.write(&conn).unwrap();

        user_edge.date = policy_group.mdate;
        user_edge.flag |= RowFlag::DELETED;
        user_edge.sign(&keypair).unwrap();
        user_edge.write(&conn).unwrap();

        policy_group.mdate += 1000;
        policy_group.sign(&keypair).unwrap();

        security_policy
            .validate_node(&pol_group_id, &policy_group, &conn)
            .expect_err("Deleted Peer");
    }

    #[test]
    fn validate_node_policy() {
        let conn = Connection::open_in_memory().unwrap();
        prepare_connection(&conn).unwrap();
        let mut security_policy = SecurityPolicy::new();
        let keypair = Ed2519KeyPair::new();

        let mut policy_group = Node {
            schema: POLICY_GROUP_SCHEMA.to_string(),
            flag: RowFlag::KEEP_HISTORY,
            text: Some("Some Policy Group".to_string()),
            ..Default::default()
        };
        policy_group.sign(&keypair).unwrap();
        policy_group.write(&conn).unwrap();
        let pol_group_id = policy_group.id.clone();

        let mut peer = Node {
            id: keypair.export_public(),
            schema: PEER_SCHEMA.to_string(),
            cdate: policy_group.mdate,
            mdate: policy_group.mdate,
            ..Default::default()
        };
        peer.sign(&keypair).unwrap();
        peer.write(&conn).unwrap();

        let mut peer_edge = Edge {
            source: policy_group.id.clone(),
            target: peer.id.clone(),
            date: policy_group.mdate,
            flag: RowFlag::KEEP_HISTORY,
            ..Default::default()
        };
        peer_edge.sign(&keypair).unwrap();
        peer_edge.write(&conn).unwrap();

        let mut policy = Node {
            schema: POLICY_SCHEMA.to_string(),
            cdate: policy_group.mdate,
            mdate: policy_group.mdate,
            text: Some("Some Policy".to_string()),
            ..Default::default()
        };
        policy.sign(&keypair).unwrap();

        security_policy
            .validate_node(&pol_group_id, &policy, &conn)
            .expect_err("KEEP_HISTORY flag not set");

        policy.flag = RowFlag::KEEP_HISTORY;
        policy.sign(&keypair).unwrap();
        security_policy
            .validate_node(&pol_group_id, &policy, &conn)
            .unwrap();
        policy.write(&conn).unwrap();

        policy.mdate += 100;
        policy.sign(&keypair).unwrap();
        security_policy
            .validate_node(&pol_group_id, &policy, &conn)
            .expect_err("missing edge: policy_group->policy");

        let mut policy_edge = Edge {
            source: policy_group.id.clone(),
            target: policy.id.clone(),
            date: policy_group.mdate,
            flag: RowFlag::KEEP_HISTORY,
            ..Default::default()
        };
        policy_edge.sign(&keypair).unwrap();
        policy_edge.write(&conn).unwrap();
        security_policy
            .validate_node(&pol_group_id, &policy, &conn)
            .unwrap();

        let bad_keypair = Ed2519KeyPair::new();
        policy.sign(&bad_keypair).unwrap();
        security_policy
            .validate_node(&pol_group_id, &policy, &conn)
            .expect_err("Invalid peer");

        policy.sign(&keypair).unwrap();
        security_policy
            .validate_node(&pol_group_id, &policy, &conn)
            .unwrap();

        policy_edge.date += 1;
        policy_edge.flag |= RowFlag::DELETED;
        policy_edge.sign(&keypair).unwrap();
        policy_edge.write(&conn).unwrap();

        security_policy
            .validate_node(&pol_group_id, &policy, &conn)
            .expect_err("Deleted edge: policy_group->policy");
        policy_edge.date += 1;
        policy_edge.flag = RowFlag::KEEP_HISTORY;
        policy_edge.sign(&keypair).unwrap();
        policy_edge.write(&conn).unwrap();

        security_policy
            .validate_node(&pol_group_id, &policy, &conn)
            .unwrap();

        peer_edge.flag |= RowFlag::DELETED;
        peer_edge.sign(&keypair).unwrap();
        peer_edge.write(&conn).unwrap();

        security_policy
            .validate_node(&pol_group_id, &policy, &conn)
            .expect_err("Deleted edge: policy_group->peer");

        peer_edge.flag = RowFlag::KEEP_HISTORY;
        peer_edge.sign(&keypair).unwrap();
        peer_edge.write(&conn).unwrap();
        security_policy
            .validate_node(&pol_group_id, &policy, &conn)
            .unwrap();

        policy_group.mdate += 1;
        policy_group.flag |= RowFlag::DELETED;
        policy_group.sign(&keypair).unwrap();
        policy_group.write(&conn).unwrap();

        security_policy
            .validate_node(&pol_group_id, &policy, &conn)
            .expect_err("Deleted  Policy group");

        policy_group.flag = RowFlag::KEEP_HISTORY;
        policy_group.sign(&keypair).unwrap();
        policy_group.write(&conn).unwrap();
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn validate_node_standard() {
        let conn = Connection::open_in_memory().unwrap();
        prepare_connection(&conn).unwrap();

        let mut security_policy = SecurityPolicy::new();
        let keypair = Ed2519KeyPair::new();

        let mut policy_group = Node {
            schema: POLICY_GROUP_SCHEMA.to_string(),
            flag: RowFlag::KEEP_HISTORY,
            text: Some("Some Policy Group".to_string()),
            ..Default::default()
        };
        policy_group.sign(&keypair).unwrap();
        policy_group.write(&conn).unwrap();

        let pol_group_id = policy_group.id.clone();

        let mut policy = PolicyNode {
            ..Default::default()
        };
        policy.sign(&keypair).unwrap();
        policy.node.mdate = policy_group.mdate;
        policy.node.cdate = policy_group.mdate;
        policy.node.write(&conn).unwrap();

        let mut policy_edge = Edge {
            source: policy_group.id.clone(),
            target: policy.node.id.clone(),
            date: policy_group.mdate,
            flag: RowFlag::KEEP_HISTORY,
            ..Default::default()
        };
        policy_edge.sign(&keypair).unwrap();
        policy_edge.write(&conn).unwrap();

        let mut peer = Node {
            id: keypair.export_public(),
            schema: PEER_SCHEMA.to_string(),
            cdate: policy_group.mdate,
            mdate: policy_group.mdate,
            ..Default::default()
        };
        peer.sign(&keypair).unwrap();
        peer.write(&conn).unwrap();

        let mut policy_group_peer = Edge {
            source: policy_group.id.clone(),
            target: peer.id.clone(),
            date: policy_group.mdate,
            flag: RowFlag::KEEP_HISTORY,
            ..Default::default()
        };
        policy_group_peer.sign(&keypair).unwrap();
        policy_group_peer.write(&conn).unwrap();

        let mut policy_peer = Edge {
            source: policy.node.id.clone(),
            target: peer.id.clone(),
            date: policy_group.mdate,
            flag: RowFlag::KEEP_HISTORY,
            ..Default::default()
        };
        policy_peer.sign(&keypair).unwrap();
        policy_peer.write(&conn).unwrap();

        let schema = "SomeSchema";
        let mut some_schema = Node {
            schema: schema.to_string(),
            ..Default::default()
        };
        some_schema.sign(&keypair).unwrap();

        security_policy
            .validate_node(&pol_group_id, &some_schema, &conn)
            .unwrap();

        some_schema.write(&conn).unwrap();

        let mut some_schema_edge = Edge {
            source: some_schema.id.clone(),
            target: policy_group.id.clone(),
            date: now() + 10,
            ..Default::default()
        };
        some_schema_edge.sign(&keypair).unwrap();
        some_schema_edge.write(&conn).unwrap();

        let new_peer_key = Ed2519KeyPair::new();
        let mut new_peer = Node {
            id: new_peer_key.export_public(),
            schema: PEER_SCHEMA.to_string(),
            cdate: policy_group.mdate,
            mdate: policy_group.mdate,
            ..Default::default()
        };
        new_peer.sign(&new_peer_key).unwrap();
        new_peer.write(&conn).unwrap();

        let mut new_policy_peer = Edge {
            source: policy.node.id.clone(),
            target: new_peer.id.clone(),
            date: policy_group.mdate,
            flag: RowFlag::KEEP_HISTORY,
            ..Default::default()
        };
        new_policy_peer.sign(&keypair).unwrap();
        new_policy_peer.write(&conn).unwrap();

        some_schema.sign(&new_peer_key).unwrap();
        security_policy
            .validate_node(&pol_group_id, &some_schema, &conn)
            .expect_err("Peer has insufficient rights to insert this node");

        security_policy.refresh_cache(&pol_group_id, &conn).unwrap();

        //  validate_node(&some_schema, &conn).expect_err("missing edge: SomeSchema->PolicyGroup ");

        policy.policy.schema_policies.insert(schema.to_string(), 0);
        policy.sign(&keypair).unwrap();
        policy.node.write(&conn).unwrap();
        security_policy.refresh_cache(&pol_group_id, &conn).unwrap();
        security_policy
            .validate_node(&pol_group_id, &some_schema, &conn)
            .expect_err("missing insert right for the schema ");

        policy
            .policy
            .schema_policies
            .insert(schema.to_string(), PolicyRight::CREATE);
        policy.sign(&keypair).unwrap();
        policy.node.write(&conn).unwrap();
        security_policy.refresh_cache(&pol_group_id, &conn).unwrap();
        security_policy
            .validate_node(&pol_group_id, &some_schema, &conn)
            .expect_err("missing insert right for the schema ");

        policy.policy.schema_policies.insert(
            schema.to_string(),
            PolicyRight::CREATE | PolicyRight::UPDATE_ANY,
        );
        policy.sign(&keypair).unwrap();
        policy.node.write(&conn).unwrap();
        security_policy.refresh_cache(&pol_group_id, &conn).unwrap();
        security_policy
            .validate_node(&pol_group_id, &some_schema, &conn)
            .unwrap();

        // new_policy_peer.date += 1;
        // new_policy_peer.flag |= RowFlag::DELETED;
        // new_policy_peer.sign(&keypair).unwrap();
        // new_policy_peer.write(&conn).unwrap();
        // validate_node(&some_schema, &conn).expect_err("edge deleted: policy->peer ");

        // new_policy_peer.flag = RowFlag::KEEP_HISTORY;
        // new_policy_peer.sign(&keypair).unwrap();
        // new_policy_peer.write(&conn).unwrap();
        // validate_node(&some_schema, &conn).unwrap();

        // policy_edge.date += 1;
        // policy_edge.flag |= RowFlag::DELETED;
        // policy_edge.sign(&keypair).unwrap();
        // policy_edge.write(&conn).unwrap();
        // validate_node(&some_schema, &conn).expect_err("edge deleted: policy_group->policy ");
        // policy_edge.flag = RowFlag::KEEP_HISTORY;
        // policy_edge.sign(&keypair).unwrap();
        // policy_edge.write(&conn).unwrap();
        // validate_node(&some_schema, &conn).unwrap();
    }

    #[test]
    fn validate_edge_policy() {
        let conn = Connection::open_in_memory().unwrap();
        prepare_connection(&conn).unwrap();

        let mut security_policy = SecurityPolicy::new();

        let keypair = Ed2519KeyPair::new();

        let mut policy_group = Node {
            schema: POLICY_GROUP_SCHEMA.to_string(),
            cdate: now(),
            flag: RowFlag::KEEP_HISTORY,
            text: Some("Some Policy Group".to_string()),
            ..Default::default()
        };
        policy_group.sign(&keypair).unwrap();
        let pol_group_id = policy_group.id.clone();

        let mut peer = Node {
            id: keypair.export_public(),
            schema: PEER_SCHEMA.to_string(),
            cdate: now(),
            ..Default::default()
        };
        peer.sign(&keypair).unwrap();

        let mut peer_edge = Edge {
            source: policy_group.id.clone(),
            target: peer.id.clone(),
            date: policy_group.mdate,
            flag: RowFlag::KEEP_HISTORY,
            ..Default::default()
        };
        peer_edge.sign(&keypair).unwrap();

        security_policy
            .validate_edge(&pol_group_id, &peer_edge, &conn)
            .expect_err("unknown source");

        policy_group.write(&conn).unwrap();

        security_policy
            .validate_edge(&pol_group_id, &peer_edge, &conn)
            .expect_err("unknown target");

        peer.write(&conn).unwrap();
        security_policy
            .validate_edge(&pol_group_id, &peer_edge, &conn)
            .unwrap();

        peer_edge.flag = 0;
        peer_edge.sign(&keypair).unwrap();

        security_policy
            .validate_edge(&pol_group_id, &peer_edge, &conn)
            .expect_err("policy must keep history");

        peer_edge.flag = RowFlag::KEEP_HISTORY;
        peer_edge.sign(&keypair).unwrap();
        security_policy
            .validate_edge(&pol_group_id, &peer_edge, &conn)
            .unwrap();
        peer_edge.write(&conn).unwrap();

        peer_edge.date -= 10;
        peer_edge.sign(&keypair).unwrap();

        security_policy
            .validate_edge(&pol_group_id, &peer_edge, &conn)
            .expect_err("a more recent version exists");

        peer_edge.date += 10;
        peer_edge.sign(&keypair).unwrap();

        let mut bad_node = Node {
            schema: "badschema".to_string(),
            cdate: policy_group.cdate,
            ..Default::default()
        };
        bad_node.sign(&keypair).unwrap();
        bad_node.write(&conn).unwrap();

        let mut bad_edge = Edge {
            source: policy_group.id.clone(),
            target: bad_node.id.clone(),
            date: policy_group.mdate,
            flag: RowFlag::KEEP_HISTORY,
            ..Default::default()
        };
        bad_edge.sign(&keypair).unwrap();

        security_policy
            .validate_edge(&pol_group_id, &bad_edge, &conn)
            .expect_err("invalid target");

        let bad_keypair = Ed2519KeyPair::new();
        peer_edge.sign(&bad_keypair).unwrap();

        security_policy
            .validate_edge(&pol_group_id, &peer_edge, &conn)
            .expect_err("invalid peer");
        peer_edge.sign(&keypair).unwrap();
        security_policy
            .validate_edge(&pol_group_id, &peer_edge, &conn)
            .unwrap();

        let new_keypair = Ed2519KeyPair::new();
        let mut new_peer = Node {
            id: new_keypair.export_public(),
            schema: PEER_SCHEMA.to_string(),
            cdate: policy_group.mdate,
            ..Default::default()
        };
        new_peer.sign(&new_keypair).unwrap();
        new_peer.write(&conn).unwrap();

        let mut new_peer_edge = Edge {
            source: policy_group.id.clone(),
            target: new_peer.id.clone(),
            date: policy_group.mdate,
            flag: RowFlag::KEEP_HISTORY,
            ..Default::default()
        };
        new_peer_edge.sign(&new_keypair).unwrap();

        security_policy
            .validate_edge(&pol_group_id, &new_peer_edge, &conn)
            .expect_err("invalid signature peer");

        new_peer_edge.sign(&keypair).unwrap();
        security_policy
            .validate_edge(&pol_group_id, &new_peer_edge, &conn)
            .unwrap();
        new_peer_edge.write(&conn).unwrap();

        //
        // start policy test
        //
        let mut policy = Node {
            schema: POLICY_SCHEMA.to_string(),
            cdate: policy_group.mdate,
            mdate: policy_group.mdate,
            flag: RowFlag::KEEP_HISTORY,
            text: Some("Some Policy Group".to_string()),
            ..Default::default()
        };
        policy.sign(&keypair).unwrap();
        // validate_node(&policy, &conn).unwrap();
        policy.write(&conn).unwrap();

        bad_edge.source = policy.id.clone();
        bad_edge.sign(&keypair).unwrap();

        security_policy
            .validate_edge(&pol_group_id, &bad_edge, &conn)
            .expect_err("invalid target");

        let mut policy_policygr_edge = Edge {
            source: policy_group.id.clone(),
            target: policy.id.clone(),
            date: policy_group.mdate,
            flag: RowFlag::KEEP_HISTORY,
            ..Default::default()
        };
        policy_policygr_edge.sign(&keypair).unwrap();

        security_policy
            .validate_edge(&pol_group_id, &policy_policygr_edge, &conn)
            .unwrap();
        policy_policygr_edge.write(&conn).unwrap();

        let mut new_peer_edge = Edge {
            source: policy.id.clone(),
            target: new_peer.id.clone(),
            date: policy_group.mdate,
            flag: RowFlag::KEEP_HISTORY,
            ..Default::default()
        };
        new_peer_edge.sign(&new_keypair).unwrap();
        security_policy
            .validate_edge(&pol_group_id, &new_peer_edge, &conn)
            .unwrap();
        new_peer_edge.write(&conn).unwrap();

        new_peer_edge.sign(&bad_keypair).unwrap();

        security_policy
            .validate_edge(&pol_group_id, &new_peer_edge, &conn)
            .expect_err("invalid peer");
    }

    #[test]
    fn validate_edge_standard() {
        let conn = Connection::open_in_memory().unwrap();
        prepare_connection(&conn).unwrap();
        let mut security_policy = SecurityPolicy::new();
        let keypair = Ed2519KeyPair::new();

        let mut policy_group = Node {
            schema: POLICY_GROUP_SCHEMA.to_string(),
            flag: RowFlag::KEEP_HISTORY,
            text: Some("Some Policy Group".to_string()),
            ..Default::default()
        };
        policy_group.sign(&keypair).unwrap();
        policy_group.write(&conn).unwrap();
        let pol_group_id = policy_group.id.clone();

        let mut peer = Node {
            id: keypair.export_public(),
            schema: PEER_SCHEMA.to_string(),
            cdate: policy_group.mdate,
            ..Default::default()
        };
        peer.sign(&keypair).unwrap();
        peer.write(&conn).unwrap();
        let mut peer_edge = Edge {
            source: policy_group.id.clone(),
            target: peer.id.clone(),
            date: policy_group.mdate,
            flag: RowFlag::KEEP_HISTORY,
            ..Default::default()
        };
        peer_edge.sign(&keypair).unwrap();
        security_policy
            .validate_edge(&pol_group_id, &peer_edge, &conn)
            .unwrap();
        peer_edge.write(&conn).unwrap();

        let mut policy = PolicyNode {
            ..Default::default()
        };
        policy.node.mdate = policy_group.mdate;
        policy.node.cdate = policy_group.mdate;

        policy.sign(&keypair).unwrap();
        //   validate_node(&policy.node, &conn).unwrap();
        policy.node.write(&conn).unwrap();

        let mut policy_policygr_edge = Edge {
            source: policy_group.id.clone(),
            target: policy.node.id.clone(),
            date: policy_group.mdate,
            flag: RowFlag::KEEP_HISTORY,
            ..Default::default()
        };
        policy_policygr_edge.sign(&keypair).unwrap();
        security_policy
            .validate_edge(&pol_group_id, &policy_policygr_edge, &conn)
            .unwrap();
        policy_policygr_edge.write(&conn).unwrap();

        let chat_schema = "chat";
        let mut chat_group = Node {
            schema: chat_schema.to_string(),
            cdate: now(),
            ..Default::default()
        };
        chat_group.sign(&keypair).unwrap();
        chat_group.write(&conn).unwrap();

        let message_schema = "msg";
        let mut message = Node {
            schema: message_schema.to_string(),
            cdate: now(),
            text: Some("Hello world".to_string()),
            ..Default::default()
        };
        message.sign(&keypair).unwrap();
        message.write(&conn).unwrap();

        let mut message_to_chat = Edge {
            source: message.id.clone(),
            target: chat_group.id.clone(),
            ..Default::default()
        };
        message_to_chat.sign(&keypair).unwrap();
        security_policy
            .validate_edge(&pol_group_id, &message_to_chat, &conn)
            .expect_err("invalid rights");

        let mut policy_peer = Edge {
            source: policy.node.id.clone(),
            target: peer.id.clone(),
            date: policy_group.mdate,
            flag: RowFlag::KEEP_HISTORY,
            ..Default::default()
        };
        policy_peer.sign(&keypair).unwrap();
        security_policy
            .validate_edge(&pol_group_id, &policy_peer, &conn)
            .unwrap();
        policy_peer.write(&conn).unwrap();

        security_policy
            .validate_edge(&pol_group_id, &message_to_chat, &conn)
            .expect_err("invalid rights");

        let mut chat_policy_edge = Edge {
            source: chat_group.id.clone(),
            target: policy_group.id.clone(),
            date: policy_group.mdate,
            ..Default::default()
        };
        chat_policy_edge.sign(&keypair).unwrap();
        security_policy
            .validate_edge(&pol_group_id, &chat_policy_edge, &conn)
            .unwrap();
        chat_policy_edge.write(&conn).unwrap();

        security_policy
            .validate_edge(&pol_group_id, &message_to_chat, &conn)
            .expect_err("invalid rights");

        let mut message_policy_edge = Edge {
            source: message.id.clone(),
            target: policy_group.id.clone(),
            date: policy_group.mdate,
            ..Default::default()
        };
        message_policy_edge.sign(&keypair).unwrap();
        security_policy
            .validate_edge(&pol_group_id, &message_policy_edge, &conn)
            .unwrap();
        message_policy_edge.write(&conn).unwrap();

        security_policy
            .validate_edge(&pol_group_id, &message_to_chat, &conn)
            .expect_err("invalid rights");

        policy.policy.add_edge_policy(message_schema, chat_schema);
        policy.policy.set_right(message_schema, PolicyRight::CREATE);
        policy.sign(&keypair).unwrap();
        policy.node.write(&conn).unwrap();
        security_policy.refresh_cache(&pol_group_id, &conn).unwrap();
        security_policy
            .validate_edge(&pol_group_id, &message_to_chat, &conn)
            .unwrap();

        let newkeypair = Ed2519KeyPair::new();
        let mut newpeer = Node {
            id: newkeypair.export_public(),
            schema: PEER_SCHEMA.to_string(),
            cdate: now(),
            ..Default::default()
        };
        newpeer.sign(&newkeypair).unwrap();
        newpeer.write(&conn).unwrap();

        let mut new_peer_edge = Edge {
            source: policy.node.id.clone(),
            target: newpeer.id.clone(),
            date: policy_group.mdate,
            flag: RowFlag::KEEP_HISTORY,
            ..Default::default()
        };
        new_peer_edge.sign(&keypair).unwrap();
        security_policy
            .validate_edge(&pol_group_id, &new_peer_edge, &conn)
            .unwrap();
        new_peer_edge.write(&conn).unwrap();

        message_to_chat.sign(&newkeypair).unwrap();
        security_policy
            .validate_edge(&pol_group_id, &message_to_chat, &conn)
            .expect_err("UPDATE_ANY not set");

        policy.policy.set_right(
            message_schema,
            PolicyRight::CREATE | PolicyRight::UPDATE_ANY,
        );
        policy.sign(&keypair).unwrap();
        policy.node.write(&conn).unwrap();
        security_policy.refresh_cache(&pol_group_id, &conn).unwrap();
        security_policy
            .validate_edge(&pol_group_id, &message_to_chat, &conn)
            .unwrap();
    }
}
