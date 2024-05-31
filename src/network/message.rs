use serde::{Deserialize, Serialize};

use crate::network::multicast;
use std::net::IpAddr;

#[derive(Serialize, Deserialize, Debug, PartialEq, Eq)]
pub enum Message {
    MulticastCandidates {
        ip: IpAddr,
        announce: Box<multicast::Announce>,
    },
}
