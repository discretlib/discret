use std::thread;

use super::Result;
use crate::{
    database::{
        edge::{Edge, EdgeDeletionEntry},
        node::{Node, NodeDeletionEntry},
        room_node::RoomNode,
    },
    security::import_verifying_key,
};
//use ed25519_dalek::{verify_batch, Signature, Signer, SigningKey, VerifyingKey};

use tokio::sync::oneshot::{self};

pub enum VerificationMessage {
    RoomNode(Box<RoomNode>, oneshot::Sender<Result<RoomNode>>),
    Nodes(Vec<Node>, oneshot::Sender<Result<Vec<Node>>>),
    Edges(Vec<Edge>, oneshot::Sender<Result<Vec<Edge>>>),
    EdgeLog(
        Vec<EdgeDeletionEntry>,
        oneshot::Sender<Result<Vec<EdgeDeletionEntry>>>,
    ),
    NodeLog(
        Vec<NodeDeletionEntry>,
        oneshot::Sender<Result<Vec<NodeDeletionEntry>>>,
    ),
    Hash(Vec<u8>, [u8; 32], Vec<u8>, oneshot::Sender<bool>),
}
///
/// Signature verification consumes a lot of cpu ressources.
/// it is moved to real threads to avoid blocking Tokio processes
///
#[derive(Clone)]
pub struct SignatureVerificationService {
    pub sender: flume::Sender<VerificationMessage>,
}
impl SignatureVerificationService {
    pub fn start(verification_treads: usize) -> Self {
        let (sender, receiver) = flume::bounded::<VerificationMessage>(verification_treads * 2);
        for _ in 0..verification_treads {
            let local_receiver = receiver.clone();
            thread::spawn(move || {
                while let Ok(msg) = local_receiver.recv() {
                    match msg {
                        VerificationMessage::RoomNode(node, reply) => {
                            let _ = reply.send(Self::room_check(*node));
                        }
                        VerificationMessage::Nodes(nodes, reply) => {
                            let _ = reply.send(Self::nodes_check(nodes));
                        }
                        VerificationMessage::Edges(edges, reply) => {
                            let _ = reply.send(Self::edges_check(edges));
                        }
                        VerificationMessage::EdgeLog(log, reply) => {
                            let _ = reply.send(Self::edge_log_check(log));
                        }
                        VerificationMessage::NodeLog(log, reply) => {
                            let _ = reply.send(Self::node_log_check(log));
                        }
                        VerificationMessage::Hash(signature, hash, verifying_key, reply) => {
                            let pub_key = import_verifying_key(&verifying_key);
                            match pub_key {
                                Ok(pub_key) => match pub_key.verify(&hash, &signature) {
                                    Ok(_) => {
                                        let _ = reply.send(true);
                                    }
                                    Err(_) => {
                                        let _ = reply.send(false);
                                    }
                                },
                                Err(_) => {
                                    let _ = reply.send(false);
                                }
                            }
                        }
                    }
                }
            });
        }

        Self { sender }
    }

    pub fn nodes_check(nodes: Vec<Node>) -> Result<Vec<Node>> {
        //  verify_batch();

        for node in &nodes {
            node.verify()?;
        }
        Ok(nodes)
    }

    // pub fn nodes_check(nodes: Vec<Node>) -> Result<Vec<Node>> {
    //     //  verify_batch();
    //     let mut hashes = Vec::with_capacity(nodes.len());
    //     let mut signatures = Vec::with_capacity(nodes.len());
    //     let verifying_keys = Vec::with_capacity(nodes.len());
    //     for node in &nodes {
    //         let hash = node.hash()?;
    //         hashes.push(hash.as_bytes().to_owned());

    //         let sign = node._signature.clone();
    //         let sign: [u8; 64] = sign.try_into().unwrap();
    //         let sig = ed25519_dalek::Signature::from_bytes(&sign);
    //         signatures.push(sig);

    //         node.verify()?;
    //     }
    //     let mut messages: Vec<&[u8]> = Vec::with_capacity(nodes.len());
    //     for msg in &hashes {
    //         messages.push(msg);
    //     }
    //     verify_batch(&messages, &signatures, &verifying_keys).map_err(|e| crate::Error::);
    //     Ok(nodes)
    // }

    pub fn edges_check(edges: Vec<Edge>) -> Result<Vec<Edge>> {
        for edge in &edges {
            edge.verify()?;
        }
        Ok(edges)
    }

    pub fn edge_log_check(log: Vec<EdgeDeletionEntry>) -> Result<Vec<EdgeDeletionEntry>> {
        for edge_log in &log {
            edge_log.verify()?;
        }
        Ok(log)
    }

    pub fn node_log_check(log: Vec<NodeDeletionEntry>) -> Result<Vec<NodeDeletionEntry>> {
        for node_log in &log {
            node_log.verify()?;
        }
        Ok(log)
    }

    pub fn room_check(node: RoomNode) -> Result<RoomNode> {
        node.node.verify()?;

        for edge in &node.admin_edges {
            edge.verify()?;
        }

        for user in &node.admin_nodes {
            user.node.verify()?;
        }

        for edge in &node.auth_edges {
            edge.verify()?;
        }

        for auth in &node.auth_nodes {
            auth.node.verify()?;
            for edge in &auth.user_edges {
                edge.verify()?;
            }
            for user in &auth.user_nodes {
                user.node.verify()?;
            }

            for edge in &auth.right_edges {
                edge.verify()?;
            }
            for right in &auth.right_nodes {
                right.node.verify()?;
            }

            for edge in &auth.user_admin_edges {
                edge.verify()?;
            }

            for user in &auth.user_admin_nodes {
                user.node.verify()?;
            }
        }
        Ok(node)
    }

    pub async fn verify_room_node(&self, node: RoomNode) -> Result<RoomNode> {
        let (reply, receiver) = oneshot::channel::<Result<RoomNode>>();
        let _ = self
            .sender
            .send_async(VerificationMessage::RoomNode(Box::new(node), reply))
            .await;
        receiver.await.unwrap() //won't fail unless when stopping app
    }

    pub async fn verify_nodes(&self, nodes: Vec<Node>) -> Result<Vec<Node>> {
        let (reply, receiver) = oneshot::channel::<Result<Vec<Node>>>();
        let _ = self
            .sender
            .send_async(VerificationMessage::Nodes(nodes, reply))
            .await;
        receiver.await.unwrap() //won't fail unless when stopping app
    }

    pub async fn verify_edges(&self, nodes: Vec<Edge>) -> Result<Vec<Edge>> {
        let (reply, receiver) = oneshot::channel::<Result<Vec<Edge>>>();
        let _ = self
            .sender
            .send_async(VerificationMessage::Edges(nodes, reply))
            .await;
        receiver.await.unwrap() //won't fail unless when stopping app
    }

    pub async fn verify_edge_log(
        &self,
        log: Vec<EdgeDeletionEntry>,
    ) -> Result<Vec<EdgeDeletionEntry>> {
        let (reply, receiver) = oneshot::channel::<Result<Vec<EdgeDeletionEntry>>>();
        let _ = self
            .sender
            .send_async(VerificationMessage::EdgeLog(log, reply))
            .await;
        receiver.await.unwrap() //won't fail unless when stopping app
    }

    pub async fn verify_node_log(
        &self,
        log: Vec<NodeDeletionEntry>,
    ) -> Result<Vec<NodeDeletionEntry>> {
        let (reply, receiver) = oneshot::channel::<Result<Vec<NodeDeletionEntry>>>();
        let _ = self
            .sender
            .send_async(VerificationMessage::NodeLog(log, reply))
            .await;
        receiver.await.unwrap() //won't fail unless when stopping app
    }

    pub async fn verify_hash(
        &self,
        signature: Vec<u8>,
        hash: [u8; 32],
        verifying_key: Vec<u8>,
    ) -> bool {
        let (reply, receiver) = oneshot::channel::<bool>();
        let _ = self
            .sender
            .send_async(VerificationMessage::Hash(
                signature,
                hash,
                verifying_key,
                reply,
            ))
            .await;
        receiver.await.unwrap() //won't fail unless when stopping app
    }
}
