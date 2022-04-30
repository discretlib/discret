use serde::{Deserialize, Serialize};

use crate::network::{beacon_server, multicast};
use std::net::IpAddr;

#[derive(Serialize, Deserialize, Debug, PartialEq, Eq)]
pub enum Message {
    MulticastCandidates {
        ip: IpAddr,
        announce: Box<multicast::Announce>,
    },
    BeaconCandidate {
        peer_info: Box<beacon_server::PeerInfo>,
        connection_token: Vec<u8>,
    },
}
#[cfg(test)]
mod test {

    use super::*;
    #[test]
    fn test_size() {
        // if cfg!(debug_assertions) {
        //     println!("Debugging enabled");
        // } else {
        //     println!("Debugging disabled");
        // }

        println!("Size is {}", std::mem::size_of::<Message>());
    }
}
