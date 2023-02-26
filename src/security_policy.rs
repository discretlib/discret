pub type Result<T> = std::result::Result<T, Error>;
use std::collections::{HashMap, HashSet};

use serde::{Deserialize, Serialize};

use crate::cryptography::Ed2519KeyPair;

use crate::database::database_service::{DatabaseReader, FromRow};
use crate::database::edge_table::Edge;
use crate::database::{
    datamodel::{now, RowFlag},
    node_table::Node,
};
pub const PEER_SCHEMA: &str = "§";
pub const POLICY_GROUP_SCHEMA: &str = "g";
pub const POLICY_SCHEMA: &str = "$";

use thiserror::Error;
#[derive(Error, Debug)]
pub enum Error {
    #[error(transparent)]
    CryptoError(#[from] crate::cryptography::Error),

    #[error(transparent)]
    DatabaseError(#[from] crate::database::Error),

    #[error(transparent)]
    DatabaseReadError(#[from] rusqlite::Error),

    #[error(transparent)]
    JSONError(#[from] serde_json::Error),

    #[error("unknown edge source")]
    UnknownEdgeSource,

    #[error("unknown edge target")]
    UnknownEdgeTarget,

    #[error("policy node must keep it's history")]
    PolicyMustKeepHistory,

    #[error("peer cannot udate this node or edge")]
    UpdateDenied,

    #[error("peer cannot udate this node or edge")]
    InsertDenied,

    #[error("peer cannot update this policy group")]
    InvalidPolicyPeer,

    #[error("a more recent version of this entitry exists")]
    MoreRecentVersionExists,

    #[error("edge does not target a valid schema")]
    InvalidPolicyTarget,
}

pub struct PolicyRight {}
impl PolicyRight {
    //enabled: can insert data
    //disabled: read only
    pub const INSERT: i8 = 0b0000001;

    //enabled:  can't read
    //disabled: peer can only read it's on rows
    pub const READ: i8 = 0b000010;

    //enabled: can update any rows, including deletes
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
struct Policy {
    //define rights for specific schema
    schema_policies: HashMap<String, i8>,

    //define wich shema ->schema link is allowed
    //Both schema must have schema_policies defined to work propertly
    edge_policie: HashMap<String, HashSet<String>>,
}
impl Policy {
    fn set_right(&mut self, schema: &str, right: i8) {
        self.schema_policies.insert(schema.to_string(), right);
    }

    fn has_right(&self, schema: &str, right: &i8) -> bool {
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
struct PolicyNode {
    node: Node,
    policy: Policy,
}
impl PolicyNode {
    pub fn sign(&mut self, keypair: &Ed2519KeyPair) -> std::result::Result<(), Error> {
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
JOIN node_all node_policy_grp ON
    node_policy_grp.id = policy_edge.source
    AND node_policy_grp.flag & 1 = 0
    AND node_policy_grp.mdate = (SELECT max(mdate) FROM node_all WHERE id= node_policy_grp.id AND schema = node_policy_grp.schema AND mdate <= ?)
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

//graph traversal: node->policy_group->policy->peer
const POLICY_FOR_PEER_QUERY: &str = r#"
SELECT node_policy.json
FROM edge_all edge_policy_grp 
JOIN node_all node_policy_grp ON 
    node_policy_grp.id = edge_policy_grp.target 
    AND node_policy_grp.schema = ?                   --POLICY_GROUP_SCHEMA
    AND node_policy_grp.flag & 1 = 0
    AND node_policy_grp.mdate = (SELECT max(mdate) FROM node_all WHERE id= node_policy_grp.id AND schema = node_policy_grp.schema AND mdate <= ?)
JOIN edge_all edge_policy ON 
    edge_policy.source = node_policy_grp.id
    AND edge_policy.flag & 1 = 0
    AND edge_policy.date = (SELECT max(date) FROM edge_all  WHERE source = edge_policy.source AND target = edge_policy.target AND date <= ?)
JOIN node_all node_policy ON 
    node_policy.id = edge_policy.target 
    AND node_policy.schema = ?                       --POLICY_SCHEMA
    AND node_policy.flag & 1 = 0
    AND node_policy.mdate = (SELECT max(mdate) FROM node_all WHERE id= node_policy.id AND schema = node_policy.schema AND mdate <= ?)
JOIN edge_all peer_edge ON 
    peer_edge.source = node_policy.id 
    AND peer_edge.target = ?
    AND peer_edge.flag & 1 = 0
    AND peer_edge.date = (SELECT max(date) FROM edge_all WHERE source = peer_edge.source AND target = peer_edge.target AND date <= ?)
WHERE 
    edge_policy_grp.source = ?
    AND edge_policy_grp.flag & 1 = 0
"#;

//graph traversal: node->policy_group->policy->peer
const COMMON_POLICY_GROUP_FOR_EDGE: &str = r#"
SELECT node_policy.json
FROM  edge_all source_policy_group
JOIN node_all policy_grp ON 
    policy_grp.id = source_policy_group.target 
    AND policy_grp.schema = ?                   --POLICY_GROUP_SCHEMA
    AND policy_grp.flag & 1 = 0
    AND policy_grp.mdate = (SELECT max(mdate) FROM node_all WHERE id= policy_grp.id AND schema = policy_grp.schema AND mdate <= ?)
JOIN edge_all target_policy_group ON
    target_policy_group.source = ?
    AND target_policy_group.target = policy_grp.id
JOIN edge_all edge_policy ON 
    edge_policy.source = policy_grp.id
    AND edge_policy.flag & 1 = 0
    AND edge_policy.date = (SELECT max(date) FROM edge_all  WHERE source = edge_policy.source AND target = edge_policy.target AND date <= ?)
JOIN node_all node_policy ON 
    node_policy.id = edge_policy.target 
    AND node_policy.schema = ?                       --POLICY_SCHEMA
    AND node_policy.flag & 1 = 0
    AND node_policy.mdate = (SELECT max(mdate) FROM node_all WHERE id= node_policy.id AND schema = node_policy.schema AND mdate <= ?)
JOIN edge_all peer_edge ON 
    peer_edge.source = node_policy.id 
    AND peer_edge.target = ?
    AND peer_edge.flag & 1 = 0
    AND peer_edge.date = (SELECT max(date) FROM edge_all WHERE source = peer_edge.source AND target = peer_edge.target AND date <= ?)
WHERE
    source_policy_group.source = ?
"#;

pub struct PolicyManager {
    database: DatabaseReader,
}
impl PolicyManager {
    pub fn new(database: DatabaseReader) -> Self {
        Self { database }
    }

    pub async fn validate_node(&self, node: &Node) -> Result<()> {
        node.verify()?;

        //
        // policy must keep the entire update history to be able validate every node
        //
        if (node.schema.eq(POLICY_SCHEMA) || node.schema.eq(POLICY_GROUP_SCHEMA))
            && !RowFlag::is(node.flag, &RowFlag::KEEP_HISTORY)
        {
            return Err(Error::PolicyMustKeepHistory);
        }

        let query_node = "SELECT * FROM node_all WHERE id=? ORDER BY mdate DESC LIMIT 1";
        let mut some_version = self
            .database
            .query_async(
                query_node.to_string(),
                vec![Box::new(node.id.clone())],
                Node::from_row(),
            )
            .await?;
        if some_version.is_empty() {
            return Ok(());
        }
        let previous_version = some_version.pop().unwrap();
        // println!("{} --- {}", previous_version.pub_key, node.pub_key);

        if node.schema.eq(POLICY_GROUP_SCHEMA) {
            if previous_version.mdate > node.mdate {
                return Err(Error::MoreRecentVersionExists);
            }
            let user = self
                .database
                .query_async(
                    PEER_IN_POLICY_GROUP_QUERY.to_string(),
                    vec![
                        Box::new(node.id.clone()),
                        Box::new(node.pub_key.clone()),
                        Box::new(node.mdate),
                    ],
                    |row| Ok(Box::new(row.get::<_, i32>(0))),
                )
                .await?;
            //  println!("{} --- {}", previous_version.pub_key, node.pub_key);

            if !user.is_empty() {
                return Ok(());
            } else {
                return Err(Error::InvalidPolicyPeer);
            }
        } else if node.schema.eq(POLICY_SCHEMA) {
            if previous_version.mdate > node.mdate {
                return Err(Error::MoreRecentVersionExists);
            }
            let user = self
                .database
                .query_async(
                    ADMIN_PEER_FOR_POLICY_QUERY.to_string(),
                    vec![
                        Box::new(node.mdate),
                        Box::new(node.pub_key.clone()),
                        Box::new(node.mdate),
                        Box::new(node.id.clone()),
                        Box::new(node.mdate),
                    ],
                    |row| Ok(Box::new(row.get::<_, i32>(0))),
                )
                .await?;

            if !user.is_empty() {
                return Ok(());
            } else {
                return Err(Error::InvalidPolicyPeer);
            }
        } else {
            let policies = self
                .database
                .query_async(
                    POLICY_FOR_PEER_QUERY.to_string(),
                    vec![
                        Box::new(POLICY_GROUP_SCHEMA),
                        Box::new(node.mdate),
                        Box::new(node.mdate),
                        Box::new(POLICY_SCHEMA),
                        Box::new(node.mdate),
                        Box::new(node.pub_key.clone()),
                        Box::new(node.mdate),
                        Box::new(node.id.clone()),
                    ],
                    |row| Ok(Box::new(row.get::<_, String>(0))),
                )
                .await?;

            if policies.is_empty() {
                return Err(Error::InvalidPolicyPeer);
            }

            let mut update_any = false;
            let mut insert_right = false;

            for pol in policies {
                let pol = pol?;
                let policy: Policy = serde_json::from_str(&pol)?;
                // println!("{:?}", policy);

                if policy.has_right(&node.schema, &PolicyRight::UPDATE_ANY) {
                    update_any = true;
                }
                if policy.has_right(&node.schema, &PolicyRight::INSERT) {
                    insert_right = true;
                }
            }

            if !insert_right {
                return Err(Error::InsertDenied);
            }

            if !update_any && !previous_version.pub_key.eq(&node.pub_key) {
                return Err(Error::UpdateDenied);
            }
        }

        Ok(())
    }

    async fn validate_edge(&self, edge: &Edge) -> Result<()> {
        edge.verify()?;
        let query_node = "SELECT * FROM node_all WHERE id=? ORDER BY mdate DESC LIMIT 1";
        let mut source_node = self
            .database
            .query_async(
                query_node.to_string(),
                vec![Box::new(edge.source.clone())],
                Node::from_row(),
            )
            .await?;
        if source_node.is_empty() {
            return Err(Error::UnknownEdgeSource);
        }
        let source_node = source_node.pop().unwrap();

        let mut target_node = self
            .database
            .query_async(
                query_node.to_string(),
                vec![Box::new(edge.target.clone())],
                Node::from_row(),
            )
            .await?;
        if target_node.is_empty() {
            return Err(Error::UnknownEdgeSource);
        }
        let target_node = target_node.pop().unwrap();

        let query_edge =
            "SELECT * FROM edge_all WHERE source = ? AND target = ? ORDER BY date DESC LIMIT 1";
        let previous_edge = self
            .database
            .query_async(
                query_edge.to_string(),
                vec![Box::new(edge.source.clone()), Box::new(edge.target.clone())],
                Edge::from_row(),
            )
            .await?;

        if source_node.schema.eq(POLICY_SCHEMA) || source_node.schema.eq(POLICY_GROUP_SCHEMA) {
            if !RowFlag::is(edge.flag, &RowFlag::KEEP_HISTORY) {
                return Err(Error::PolicyMustKeepHistory);
            }

            if !previous_edge.is_empty() && previous_edge[0].date > edge.date {
                return Err(Error::MoreRecentVersionExists);
            }

            if source_node.schema.eq(POLICY_GROUP_SCHEMA) {
                if !(target_node.schema.eq(POLICY_SCHEMA) || target_node.schema.eq(PEER_SCHEMA)) {
                    return Err(Error::InvalidPolicyTarget);
                }

                if edge.pub_key.eq(&source_node.pub_key) {
                    return Ok(());
                }
                let user = self
                    .database
                    .query_async(
                        PEER_IN_POLICY_GROUP_QUERY.to_string(),
                        vec![
                            Box::new(edge.pub_key.clone()),
                            Box::new(edge.date),
                            Box::new(edge.source.clone()),
                        ],
                        |row| Ok(Box::new(row.get::<_, i32>(0))),
                    )
                    .await?;

                if !user.is_empty() {
                    return Ok(());
                } else {
                    return Err(Error::InvalidPolicyPeer);
                }
            }
            if source_node.schema.eq(POLICY_SCHEMA) {
                if !target_node.schema.eq(PEER_SCHEMA) {
                    return Err(Error::InvalidPolicyTarget);
                }
                if edge.pub_key.eq(&source_node.pub_key) {
                    return Ok(());
                }
                let user = self
                    .database
                    .query_async(
                        ADMIN_PEER_FOR_POLICY_QUERY.to_string(),
                        vec![
                            Box::new(edge.date),
                            Box::new(edge.pub_key.clone()),
                            Box::new(edge.date),
                            Box::new(edge.source.clone()),
                            Box::new(edge.date),
                        ],
                        |row| Ok(Box::new(row.get::<_, i32>(0))),
                    )
                    .await?;

                if !user.is_empty() {
                    return Ok(());
                } else {
                    return Err(Error::InvalidPolicyPeer);
                }
            }
        } else {
            if target_node.schema.eq(POLICY_GROUP_SCHEMA) && edge.pub_key.eq(&source_node.pub_key) {
                return Ok(());
            }
            let policies = self
                .database
                .query_async(
                    COMMON_POLICY_GROUP_FOR_EDGE.to_string(),
                    vec![
                        Box::new(POLICY_GROUP_SCHEMA),
                        Box::new(edge.date),
                        Box::new(edge.target.clone()),
                        Box::new(edge.date),
                        Box::new(POLICY_SCHEMA),
                        Box::new(edge.date),
                        Box::new(edge.pub_key.clone()),
                        Box::new(edge.date),
                        Box::new(edge.source.clone()),
                    ],
                    |row| Ok(Box::new(row.get::<_, String>(0))),
                )
                .await?;

            if policies.is_empty() {
                return Err(Error::InvalidPolicyPeer);
            }
            let mut source_insert = false;
            let mut source_update_any = false;
            let mut target_insert = false;
            let mut valid_edge = false;
            for pol in policies {
                let pol = pol?;
                let policy: Policy = serde_json::from_str(&pol)?;
                // println!("{:?}", policy);

                if policy.has_right(&source_node.schema, &PolicyRight::INSERT) {
                    source_insert = true;
                }
                if policy.has_right(&target_node.schema, &PolicyRight::INSERT) {
                    target_insert = true;
                }

                if policy.has_right(&source_node.schema, &PolicyRight::UPDATE_ANY) {
                    source_update_any = true;
                }

                if policy.has_edge_policy(&source_node.schema, &target_node.schema) {
                    valid_edge = true;
                }
            }
            // println!(
            //     "in:{}, up:{}, rea:{}, valid:{}, ",
            //     source_insert, source_update_any, target_read, valid_edge
            // );

            if valid_edge && source_insert && target_insert {
                if source_node.pub_key.eq(&edge.pub_key) {
                    return Ok(());
                }
                if source_update_any {
                    return Ok(());
                }
            }
        }

        Err(Error::InsertDenied)
    }
}

#[cfg(test)]
mod tests {

    use crate::{
        cryptography::{base64_encode, hash, Ed2519KeyPair, KeyPair},
        database::{
            database_service::{create_connection, DatabaseReader, Writable},
            datamodel::{now, prepare_connection, RowFlag},
            edge_table::Edge,
            node_table::Node,
        },
        security_policy::{PolicyRight, POLICY_GROUP_SCHEMA, POLICY_SCHEMA},
    };

    use std::{
        error::Error,
        fs,
        path::{Path, PathBuf},
    };

    use super::{PolicyManager, PolicyNode, PEER_SCHEMA};
    const DATA_PATH: &str = "test/data/policy/";
    fn init_database_path(file: &str) -> Result<PathBuf, Box<dyn Error>> {
        let mut path: PathBuf = DATA_PATH.into();
        fs::create_dir_all(&path)?;
        path.push(file);
        if Path::exists(&path) {
            fs::remove_file(&path)?;
        }
        Ok(path)
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn validate_node_policy_group() {
        let path: PathBuf = init_database_path("validate_node_policy_group.db").unwrap();
        let secret = hash(b"secret");
        let readcon = create_connection(&path, &secret, 1024, false).unwrap();
        prepare_connection(&readcon).unwrap();
        // println!("initialized {}", is_initialized(&readcon).unwrap());

        let policy_manager = PolicyManager::new(DatabaseReader::start(readcon));

        let conn = create_connection(&path, &secret, 1024, false).unwrap();
        prepare_connection(&conn).unwrap();

        let keypair = Ed2519KeyPair::new();

        let mut peer = Node {
            id: base64_encode(&keypair.export_public()),
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
        policy_manager
            .validate_node(&policy_group)
            .await
            .expect_err("KEEP_HISTORY flag not set");

        policy_group.flag = RowFlag::KEEP_HISTORY;
        policy_group.sign(&keypair).unwrap();
        policy_manager.validate_node(&policy_group).await.unwrap();
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
        policy_manager
            .validate_node(&policy_group)
            .await
            .expect_err("A more recent version exists");

        policy_group.mdate += 1000;
        policy_group.sign(&keypair).unwrap();
        policy_manager.validate_node(&policy_group).await.unwrap();

        let bad_keypair = Ed2519KeyPair::new();
        policy_group.sign(&bad_keypair).unwrap();
        policy_manager
            .validate_node(&policy_group)
            .await
            .expect_err("Invalid Peer");

        policy_group.sign(&keypair).unwrap();
        policy_group.write(&conn).unwrap();

        user_edge.date = policy_group.mdate;
        user_edge.flag |= RowFlag::DELETED;
        user_edge.sign(&keypair).unwrap();
        user_edge.write(&conn).unwrap();

        policy_group.mdate += 1000;
        policy_group.sign(&keypair).unwrap();
        policy_manager
            .validate_node(&policy_group)
            .await
            .expect_err("Deleted Peer");
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn validate_node_policy() {
        let path: PathBuf = init_database_path("validate_node_policy.db").unwrap();
        let secret = hash(b"secret");
        let readcon = create_connection(&path, &secret, 1024, false).unwrap();
        prepare_connection(&readcon).unwrap();
        // println!("initialized {}", is_initialized(&readcon).unwrap());

        let policy_manager = PolicyManager::new(DatabaseReader::start(readcon));

        let conn = create_connection(&path, &secret, 1024, false).unwrap();
        prepare_connection(&conn).unwrap();

        let keypair = Ed2519KeyPair::new();

        let mut peer = Node {
            id: base64_encode(&keypair.export_public()),
            schema: PEER_SCHEMA.to_string(),
            cdate: now(),
            ..Default::default()
        };
        peer.sign(&keypair).unwrap();
        peer.write(&conn).unwrap();

        let mut policy_group = Node {
            schema: POLICY_GROUP_SCHEMA.to_string(),
            cdate: now(),
            flag: RowFlag::KEEP_HISTORY,
            text: Some("Some Policy Group".to_string()),
            ..Default::default()
        };
        policy_group.sign(&keypair).unwrap();
        policy_group.write(&conn).unwrap();

        let mut peer_edge = Edge {
            source: policy_group.id.clone(),
            target: peer.id.clone(),
            date: now(),
            flag: RowFlag::KEEP_HISTORY,
            ..Default::default()
        };
        peer_edge.sign(&keypair).unwrap();
        peer_edge.write(&conn).unwrap();

        let mut policy = Node {
            schema: POLICY_SCHEMA.to_string(),
            cdate: now(),
            text: Some("Some Policy".to_string()),
            ..Default::default()
        };
        policy.sign(&keypair).unwrap();

        policy_manager
            .validate_node(&policy)
            .await
            .expect_err("KEEP_HISTORY flag not set");

        policy.flag = RowFlag::KEEP_HISTORY;

        policy_manager
            .validate_node(&policy)
            .await
            .expect_err("Invalid signature");
        policy.sign(&keypair).unwrap();
        policy_manager.validate_node(&policy).await.unwrap();
        policy.write(&conn).unwrap();

        policy.mdate += 100;
        policy.sign(&keypair).unwrap();
        policy_manager
            .validate_node(&policy)
            .await
            .expect_err("missing edge: policy_group->policy");

        let mut policy_edge = Edge {
            source: policy_group.id.clone(),
            target: policy.id.clone(),
            date: now(),
            flag: RowFlag::KEEP_HISTORY,
            ..Default::default()
        };
        policy_edge.sign(&keypair).unwrap();
        policy_edge.write(&conn).unwrap();
        policy_manager.validate_node(&policy).await.unwrap();

        let bad_keypair = Ed2519KeyPair::new();
        policy.sign(&bad_keypair).unwrap();
        policy_manager
            .validate_node(&policy)
            .await
            .expect_err("Invalid peer");

        policy.sign(&keypair).unwrap();
        policy_manager.validate_node(&policy).await.unwrap();

        policy_edge.date += 1;
        policy_edge.flag |= RowFlag::DELETED;
        policy_edge.sign(&keypair).unwrap();
        policy_edge.write(&conn).unwrap();

        policy_manager
            .validate_node(&policy)
            .await
            .expect_err("Deleted edge: policy_group->policy");
        policy_edge.date += 1;
        policy_edge.flag = RowFlag::KEEP_HISTORY;
        policy_edge.sign(&keypair).unwrap();
        policy_edge.write(&conn).unwrap();

        policy_manager.validate_node(&policy).await.unwrap();

        peer_edge.flag |= RowFlag::DELETED;
        peer_edge.sign(&keypair).unwrap();
        peer_edge.write(&conn).unwrap();

        policy_manager
            .validate_node(&policy)
            .await
            .expect_err("Deleted edge: policy_group->peer");

        peer_edge.flag = RowFlag::KEEP_HISTORY;
        peer_edge.sign(&keypair).unwrap();
        peer_edge.write(&conn).unwrap();
        policy_manager.validate_node(&policy).await.unwrap();

        policy_group.mdate += 1;
        policy_group.flag |= RowFlag::DELETED;
        policy_group.sign(&keypair).unwrap();
        policy_group.write(&conn).unwrap();

        policy_manager
            .validate_node(&policy)
            .await
            .expect_err("Deleted  Policy group");

        policy_group.flag = RowFlag::KEEP_HISTORY;
        policy_group.sign(&keypair).unwrap();
        policy_group.write(&conn).unwrap();
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn validate_node_standard() {
        let path: PathBuf = init_database_path("validate_node_standard.db").unwrap();
        let secret = hash(b"secret");
        let readcon = create_connection(&path, &secret, 1024, false).unwrap();
        prepare_connection(&readcon).unwrap();

        let policy_manager = PolicyManager::new(DatabaseReader::start(readcon));

        let conn = create_connection(&path, &secret, 1024, false).unwrap();
        prepare_connection(&conn).unwrap();

        let keypair = Ed2519KeyPair::new();

        let mut policy_group = Node {
            schema: POLICY_GROUP_SCHEMA.to_string(),
            cdate: now(),
            flag: RowFlag::KEEP_HISTORY,
            text: Some("Some Policy Group".to_string()),
            ..Default::default()
        };
        policy_group.sign(&keypair).unwrap();
        policy_group.write(&conn).unwrap();

        let mut policy = PolicyNode {
            ..Default::default()
        };
        policy.sign(&keypair).unwrap();
        policy.node.write(&conn).unwrap();

        let mut policy_edge = Edge {
            source: policy_group.id.clone(),
            target: policy.node.id.clone(),
            date: now(),
            flag: RowFlag::KEEP_HISTORY,
            ..Default::default()
        };
        policy_edge.sign(&keypair).unwrap();
        policy_edge.write(&conn).unwrap();

        let mut peer = Node {
            id: base64_encode(&keypair.export_public()),
            schema: PEER_SCHEMA.to_string(),
            cdate: now(),
            ..Default::default()
        };
        peer.sign(&keypair).unwrap();
        peer.write(&conn).unwrap();

        let mut peer_edge = Edge {
            source: policy.node.id.clone(),
            target: peer.id.clone(),
            date: now(),
            flag: RowFlag::KEEP_HISTORY,
            ..Default::default()
        };
        peer_edge.sign(&keypair).unwrap();
        peer_edge.write(&conn).unwrap();

        let schema = "SomeSchema";
        let mut some_schema = Node {
            schema: schema.to_string(),
            ..Default::default()
        };
        some_schema.sign(&keypair).unwrap();
        policy_manager.validate_node(&some_schema).await.unwrap();

        some_schema.write(&conn).unwrap();
        policy_manager
            .validate_node(&some_schema)
            .await
            .expect_err("missing edge: SomeSchema->PolicyGroup ");

        let mut some_schema_edge = Edge {
            source: some_schema.id.clone(),
            target: policy_group.id.clone(),
            date: now() + 10,
            ..Default::default()
        };
        some_schema_edge.sign(&keypair).unwrap();
        some_schema_edge.write(&conn).unwrap();
        policy_manager
            .validate_node(&some_schema)
            .await
            .expect_err("missing policy for the schema ");

        policy.policy.schema_policies.insert(schema.to_string(), 0);
        policy.sign(&keypair).unwrap();
        policy.node.write(&conn).unwrap();
        policy_manager
            .validate_node(&some_schema)
            .await
            .expect_err("missing insert right for the schema ");

        policy
            .policy
            .schema_policies
            .insert(schema.to_string(), PolicyRight::INSERT);
        policy.sign(&keypair).unwrap();
        policy.node.write(&conn).unwrap();
        policy_manager.validate_node(&some_schema).await.unwrap();

        let new_peer_key = Ed2519KeyPair::new();
        let mut new_peer = Node {
            id: base64_encode(&new_peer_key.export_public()),
            schema: PEER_SCHEMA.to_string(),
            cdate: policy_group.mdate,
            mdate: policy_group.mdate,
            ..Default::default()
        };
        new_peer.sign(&new_peer_key).unwrap();
        new_peer.write(&conn).unwrap();

        some_schema.sign(&new_peer_key).unwrap();
        policy_manager
            .validate_node(&some_schema)
            .await
            .expect_err("missing edge: policy->new peer");

        let mut peer_edge = Edge {
            source: policy.node.id.clone(),
            target: new_peer.id.clone(),
            date: policy_group.mdate,
            flag: RowFlag::KEEP_HISTORY,
            ..Default::default()
        };
        peer_edge.sign(&keypair).unwrap();
        peer_edge.write(&conn).unwrap();
        policy_manager
            .validate_node(&some_schema)
            .await
            .expect_err("missing UPDATE_ANY right ");

        policy.policy.schema_policies.insert(
            schema.to_string(),
            PolicyRight::INSERT | PolicyRight::UPDATE_ANY,
        );
        policy.sign(&keypair).unwrap();
        policy.node.write(&conn).unwrap();
        policy_manager.validate_node(&some_schema).await.unwrap();

        peer_edge.date += 1;
        peer_edge.flag |= RowFlag::DELETED;
        peer_edge.sign(&keypair).unwrap();
        peer_edge.write(&conn).unwrap();
        policy_manager
            .validate_node(&some_schema)
            .await
            .expect_err("edge deleted: policy->peer ");

        peer_edge.flag = RowFlag::KEEP_HISTORY;
        peer_edge.sign(&keypair).unwrap();
        peer_edge.write(&conn).unwrap();
        policy_manager.validate_node(&some_schema).await.unwrap();

        policy_edge.date += 1;
        policy_edge.flag |= RowFlag::DELETED;
        policy_edge.sign(&keypair).unwrap();
        policy_edge.write(&conn).unwrap();
        policy_manager
            .validate_node(&some_schema)
            .await
            .expect_err("edge deleted: policy_group->policy ");
        policy_edge.flag = RowFlag::KEEP_HISTORY;
        policy_edge.sign(&keypair).unwrap();
        policy_edge.write(&conn).unwrap();
        policy_manager.validate_node(&some_schema).await.unwrap();
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn validate_edge_policy() {
        let path: PathBuf = init_database_path("validate_edge_policy.db").unwrap();
        let secret = hash(b"secret");
        let readcon = create_connection(&path, &secret, 1024, false).unwrap();
        prepare_connection(&readcon).unwrap();

        let policy_manager = PolicyManager::new(DatabaseReader::start(readcon));

        let conn = create_connection(&path, &secret, 1024, false).unwrap();
        prepare_connection(&conn).unwrap();

        let keypair = Ed2519KeyPair::new();

        let mut policy_group = Node {
            schema: POLICY_GROUP_SCHEMA.to_string(),
            cdate: now(),
            flag: RowFlag::KEEP_HISTORY,
            text: Some("Some Policy Group".to_string()),
            ..Default::default()
        };
        policy_group.sign(&keypair).unwrap();
        policy_manager.validate_node(&policy_group).await.unwrap();

        let mut peer = Node {
            id: base64_encode(&keypair.export_public()),
            schema: PEER_SCHEMA.to_string(),
            cdate: now(),
            ..Default::default()
        };
        peer.sign(&keypair).unwrap();
        policy_manager.validate_node(&peer).await.unwrap();

        let mut peer_edge = Edge {
            source: policy_group.id.clone(),
            target: peer.id.clone(),
            date: policy_group.mdate,
            flag: RowFlag::KEEP_HISTORY,
            ..Default::default()
        };
        peer_edge.sign(&keypair).unwrap();
        policy_manager
            .validate_edge(&peer_edge)
            .await
            .expect_err("unknown source");

        policy_group.write(&conn).unwrap();
        policy_manager
            .validate_edge(&peer_edge)
            .await
            .expect_err("unknown target");

        peer.write(&conn).unwrap();
        policy_manager.validate_edge(&peer_edge).await.unwrap();

        peer_edge.flag = 0;
        peer_edge.sign(&keypair).unwrap();
        policy_manager
            .validate_edge(&peer_edge)
            .await
            .expect_err("policy must keep history");

        peer_edge.flag = RowFlag::KEEP_HISTORY;
        peer_edge.sign(&keypair).unwrap();
        policy_manager.validate_edge(&peer_edge).await.unwrap();
        peer_edge.write(&conn).unwrap();

        peer_edge.date -= 10;
        peer_edge.sign(&keypair).unwrap();
        policy_manager
            .validate_edge(&peer_edge)
            .await
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
        policy_manager
            .validate_edge(&bad_edge)
            .await
            .expect_err("invalid target");

        let bad_keypair = Ed2519KeyPair::new();
        peer_edge.sign(&bad_keypair).unwrap();
        policy_manager
            .validate_edge(&peer_edge)
            .await
            .expect_err("invalid peer");
        peer_edge.sign(&keypair).unwrap();
        policy_manager.validate_edge(&peer_edge).await.unwrap();

        let new_keypair = Ed2519KeyPair::new();
        let mut new_peer = Node {
            id: base64_encode(&new_keypair.export_public()),
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
        policy_manager
            .validate_edge(&new_peer_edge)
            .await
            .expect_err("invalid signature peer");

        new_peer_edge.sign(&keypair).unwrap();
        policy_manager.validate_edge(&new_peer_edge).await.unwrap();
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
        policy_manager.validate_node(&policy).await.unwrap();
        policy.write(&conn).unwrap();

        bad_edge.source = policy.id.clone();
        bad_edge.sign(&keypair).unwrap();
        policy_manager
            .validate_edge(&bad_edge)
            .await
            .expect_err("invalid target");

        let mut policy_policygr_edge = Edge {
            source: policy_group.id.clone(),
            target: policy.id.clone(),
            date: policy_group.mdate,
            flag: RowFlag::KEEP_HISTORY,
            ..Default::default()
        };
        policy_policygr_edge.sign(&keypair).unwrap();
        policy_manager
            .validate_edge(&policy_policygr_edge)
            .await
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
        policy_manager.validate_edge(&new_peer_edge).await.unwrap();
        new_peer_edge.write(&conn).unwrap();

        new_peer_edge.sign(&bad_keypair).unwrap();
        policy_manager
            .validate_edge(&new_peer_edge)
            .await
            .expect_err("invalid peer");
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn validate_edge_standard() {
        let path: PathBuf = init_database_path("validate_edge_standard.db").unwrap();
        let secret = hash(b"secret");
        let readcon = create_connection(&path, &secret, 1024, false).unwrap();
        prepare_connection(&readcon).unwrap();

        let policy_manager = PolicyManager::new(DatabaseReader::start(readcon));

        let conn = create_connection(&path, &secret, 1024, false).unwrap();
        prepare_connection(&conn).unwrap();

        let keypair = Ed2519KeyPair::new();

        let mut policy_group = Node {
            schema: POLICY_GROUP_SCHEMA.to_string(),
            cdate: now(),
            flag: RowFlag::KEEP_HISTORY,
            text: Some("Some Policy Group".to_string()),
            ..Default::default()
        };
        policy_group.sign(&keypair).unwrap();
        policy_group.write(&conn).unwrap();

        let mut peer = Node {
            id: base64_encode(&keypair.export_public()),
            schema: PEER_SCHEMA.to_string(),
            cdate: now(),
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

        policy_manager.validate_edge(&peer_edge).await.unwrap();

        let mut policy = PolicyNode {
            ..Default::default()
        };
        policy.node.mdate = policy_group.mdate;
        policy.node.cdate = policy_group.mdate;

        policy.sign(&keypair).unwrap();
        policy_manager.validate_node(&policy.node).await.unwrap();
        policy.node.write(&conn).unwrap();

        let mut policy_policygr_edge = Edge {
            source: policy_group.id.clone(),
            target: policy.node.id.clone(),
            date: policy_group.mdate,
            flag: RowFlag::KEEP_HISTORY,
            ..Default::default()
        };
        policy_policygr_edge.sign(&keypair).unwrap();
        policy_manager
            .validate_edge(&policy_policygr_edge)
            .await
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
            source: message.id.to_string(),
            target: chat_group.id.clone(),
            ..Default::default()
        };
        message_to_chat.sign(&keypair).unwrap();
        policy_manager
            .validate_edge(&message_to_chat)
            .await
            .expect_err("invalid rights");

        let mut policy_peer = Edge {
            source: policy.node.id.clone(),
            target: peer.id.clone(),
            date: policy_group.mdate,
            flag: RowFlag::KEEP_HISTORY,
            ..Default::default()
        };
        policy_peer.sign(&keypair).unwrap();
        policy_manager.validate_edge(&policy_peer).await.unwrap();
        policy_peer.write(&conn).unwrap();

        policy_manager
            .validate_edge(&message_to_chat)
            .await
            .expect_err("invalid rights");

        let mut chat_policy_edge = Edge {
            source: chat_group.id.clone(),
            target: policy_group.id.clone(),
            date: policy_group.mdate,
            ..Default::default()
        };
        chat_policy_edge.sign(&keypair).unwrap();
        policy_manager
            .validate_edge(&chat_policy_edge)
            .await
            .unwrap();
        chat_policy_edge.write(&conn).unwrap();

        policy_manager
            .validate_edge(&message_to_chat)
            .await
            .expect_err("invalid rights");

        let mut message_policy_edge = Edge {
            source: message.id.clone(),
            target: policy_group.id.clone(),
            date: policy_group.mdate,
            ..Default::default()
        };
        message_policy_edge.sign(&keypair).unwrap();
        policy_manager
            .validate_edge(&message_policy_edge)
            .await
            .unwrap();
        message_policy_edge.write(&conn).unwrap();

        policy_manager
            .validate_edge(&message_to_chat)
            .await
            .expect_err("invalid rights");

        policy.policy.set_right(chat_schema, PolicyRight::INSERT);

        policy.sign(&keypair).unwrap();
        policy.node.write(&conn).unwrap();

        policy_manager
            .validate_edge(&message_to_chat)
            .await
            .expect_err("invalid rights");

        policy.policy.set_right(message_schema, PolicyRight::READ);
        policy.sign(&keypair).unwrap();
        policy.node.write(&conn).unwrap();

        policy_manager
            .validate_edge(&message_to_chat)
            .await
            .expect_err("invalid rights");

        policy.policy.add_edge_policy(message_schema, chat_schema);
        policy.policy.set_right(message_schema, PolicyRight::INSERT);
        policy.sign(&keypair).unwrap();
        policy.node.write(&conn).unwrap();

        policy_manager
            .validate_edge(&message_to_chat)
            .await
            .unwrap();

        let newkeypair = Ed2519KeyPair::new();
        let mut newpeer = Node {
            id: base64_encode(&newkeypair.export_public()),
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
        policy_manager.validate_edge(&new_peer_edge).await.unwrap();
        new_peer_edge.write(&conn).unwrap();

        message_to_chat.sign(&newkeypair).unwrap();
        policy_manager
            .validate_edge(&message_to_chat)
            .await
            .expect_err("UPDATE_ANY not set");

        policy.policy.set_right(
            message_schema,
            PolicyRight::INSERT | PolicyRight::UPDATE_ANY,
        );
        policy.sign(&keypair).unwrap();
        policy.node.write(&conn).unwrap();
        policy_manager
            .validate_edge(&message_to_chat)
            .await
            .unwrap();
    }
}
