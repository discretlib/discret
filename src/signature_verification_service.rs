use std::thread;

use super::Result;
use crate::{
    database::{
        edge::EdgeDeletionEntry,
        node::{Node, NodeDeletionEntry},
        room_node::RoomNode,
    },
    synchronisation::node_full::FullNode,
};
use tokio::sync::oneshot::{self};

pub enum VerificationMessage {
    FullNodes(Vec<FullNode>, oneshot::Sender<Result<Vec<FullNode>>>),
    RoomNode(RoomNode, oneshot::Sender<Result<RoomNode>>),
    Nodes(Vec<Node>, oneshot::Sender<Result<Vec<Node>>>),
    EdgeLog(
        Vec<EdgeDeletionEntry>,
        oneshot::Sender<Result<Vec<EdgeDeletionEntry>>>,
    ),
    NodeLog(
        Vec<NodeDeletionEntry>,
        oneshot::Sender<Result<Vec<NodeDeletionEntry>>>,
    ),
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
                        VerificationMessage::FullNodes(nodes, reply) => {
                            let _ = reply.send(Self::nodes_full_check(nodes));
                        }
                        VerificationMessage::RoomNode(node, reply) => {
                            let _ = reply.send(Self::room_check(node));
                        }
                        VerificationMessage::Nodes(nodes, reply) => {
                            let _ = reply.send(Self::nodes_check(nodes));
                        }
                        VerificationMessage::EdgeLog(log, reply) => {
                            let _ = reply.send(Self::edge_log_check(log));
                        }
                        VerificationMessage::NodeLog(log, reply) => {
                            let _ = reply.send(Self::node_log_check(log));
                        }
                    }
                }
            });
        }

        Self { sender }
    }

    pub fn nodes_full_check(nodes: Vec<FullNode>) -> Result<Vec<FullNode>> {
        for node in &nodes {
            node.node.verify()?;
            for edge in &node.edges {
                edge.verify()?;
            }
        }
        Ok(nodes)
    }

    pub fn nodes_check(nodes: Vec<Node>) -> Result<Vec<Node>> {
        for node in &nodes {
            node.verify()?;
        }
        Ok(nodes)
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

        for edge in &node.user_admin_edges {
            edge.verify()?;
        }

        for user in &node.user_admin_nodes {
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
        }
        Ok(node)
    }

    pub async fn verify_full_nodes(&self, nodes: Vec<FullNode>) -> Result<Vec<FullNode>> {
        let (reply, receiver) = oneshot::channel::<Result<Vec<FullNode>>>();
        let _ = self
            .sender
            .send_async(VerificationMessage::FullNodes(nodes, reply))
            .await;
        receiver.await.unwrap() //won't fail unless when stopping app
    }

    pub async fn verify_room_node(&self, node: RoomNode) -> Result<RoomNode> {
        let (reply, receiver) = oneshot::channel::<Result<RoomNode>>();
        let _ = self
            .sender
            .send_async(VerificationMessage::RoomNode(node, reply))
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
}
