pub type Result<T> = std::result::Result<T, Error>;
use std::collections::HashMap;

use thiserror::Error;

use super::{database_service::DatabaseReader, datamodel::now, edge_table::Edge, node_table::Node};

#[derive(Error, Debug)]
pub enum Error {
    #[error(transparent)]
    CryptoError(#[from] crate::cryptography::Error),
}

pub const POLICY_SCHEMA_NAME: &str = "$";
pub const WILDCARD_SCHEMA_NAME: &str = "*";

// WITH RECURSIVE
//   policy(from_id,name) AS (
// 	VALUES(5, "")
// 	UNION
// 	SELECT POLICY_EDGE.to_id, NPOLICY.name
// 	FROM policy JOIN edge POLICY_EDGE ON POLICY_EDGE.from_id =  policy.from_id
// 	JOIN node NPOLICY on POLICY_EDGE.to_id =  NPOLICY.id AND NPOLICY.TYPE='policy'
// )
// SELECT  policy.*, USER.name
//  from policy
// JOIN edge USER_EDGE on USER_EDGE.from_id =  policy.from_id
// JOIN node USER on USER_EDGE.TO_ID =  USER.id
// AND USER.TYPE='user'
// AND USER.id ='1'

struct policy {
    is_admin: bool,
    schema_policies: HashMap<String, i16>,
}
impl Default for policy {
    fn default() -> Self {
        Self {
            is_admin: false,
            schema_policies: HashMap::new(),
        }
    }
}

struct policy_node {
    node: Node,
    policy: policy,
}
impl Default for policy_node {
    fn default() -> Self {
        Self {
            node: Node {
                schema: POLICY_SCHEMA_NAME.to_string(),
                date: now(),
                ..Default::default()
            },
            policy: Default::default(),
        }
    }
}

fn validate_edge(edge: Edge, reader: DatabaseReader) {}
