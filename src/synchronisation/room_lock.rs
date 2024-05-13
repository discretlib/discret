use std::collections::{HashMap, HashSet, VecDeque};

use tokio::sync::mpsc;

use crate::cryptography::base64_encode;

pub enum SyncLockMessage {
    RequestLock(usize, VecDeque<Vec<u8>>, mpsc::Sender<Vec<u8>>),
    Unlock(Vec<u8>),
}

struct PeerLockRequest {
    rooms: VecDeque<Vec<u8>>,
    reply: mpsc::Sender<Vec<u8>>,
}

static LOCK_CHANNEL_SIZE: usize = 2;
///
/// peer trying to synchronize room must first acquire a lock on the room to avoid having several peers trying to synchronize the same room at the same time
/// also limits the maximum number of rooms that can be synchronized at the same time.
///
#[derive(Clone)]
pub struct RoomLockService {
    sender: mpsc::Sender<SyncLockMessage>,
}
impl RoomLockService {
    pub fn new(max_lock: usize) -> Self {
        let (sender, mut receiver) = mpsc::channel::<SyncLockMessage>(LOCK_CHANNEL_SIZE);
        tokio::spawn(async move {
            let mut peer_lock_request: HashMap<usize, PeerLockRequest> = HashMap::new();
            let mut peer_queue: VecDeque<usize> = VecDeque::new();
            let mut locked: HashSet<Vec<u8>> = HashSet::new();
            let mut avalaible = max_lock;

            while let Some(msg) = receiver.recv().await {
                match msg {
                    SyncLockMessage::RequestLock(peer, mut rooms, reply) => {
                        if let Some(lock_request) = peer_lock_request.get_mut(&peer) {
                            lock_request.reply = reply;
                            lock_request.rooms.append(&mut rooms);
                        } else {
                            peer_lock_request.insert(peer, PeerLockRequest { reply, rooms });
                            peer_queue.push_front(peer);
                        }
                        for _ in 0..avalaible.clone() {
                            Self::acquire_lock(
                                &mut peer_lock_request,
                                &mut peer_queue,
                                &mut locked,
                                &mut avalaible,
                            )
                            .await;
                        }
                    }
                    SyncLockMessage::Unlock(room) => {
                        if locked.remove(&room) == true {
                            avalaible += 1;
                            Self::acquire_lock(
                                &mut peer_lock_request,
                                &mut peer_queue,
                                &mut locked,
                                &mut avalaible,
                            )
                            .await;
                        }
                    }
                }
            }
        });

        Self { sender }
    }

    async fn acquire_lock(
        peer_lock_request: &mut HashMap<usize, PeerLockRequest>,
        peer_queue: &mut VecDeque<usize>,
        locked: &mut HashSet<Vec<u8>>,
        avalaible: &mut usize,
    ) {
        for _ in 0..peer_queue.len().clone() {
            if let Some(peer) = peer_queue.pop_back() {
                if let Some(mut lock_request) = peer_lock_request.remove(&peer) {
                    let mut lock_aquired = false;
                    for _ in 0..lock_request.rooms.len().clone() {
                        if let Some(room) = lock_request.rooms.pop_back() {
                            if locked.contains(&room) {
                                //  println!("{} locked by {}", base64_encode(&room), peer);
                                lock_request.rooms.push_front(room);
                            } else {
                                if let Ok(_) = lock_request.reply.send(room.clone()).await {
                                    locked.insert(room);
                                    *avalaible -= 1;
                                    lock_aquired = true;
                                    break;
                                };
                            }
                        }
                    }
                    if !lock_request.rooms.is_empty() {
                        peer_lock_request.insert(peer, lock_request);
                        peer_queue.push_front(peer);
                    }
                    if lock_aquired {
                        break;
                    }
                }
            }
        }
    }

    pub async fn request_locks(
        &self,
        peer_id: usize,
        rooms: VecDeque<Vec<u8>>,
        reply: mpsc::Sender<Vec<u8>>,
    ) {
        let _ = self
            .sender
            .send(SyncLockMessage::RequestLock(peer_id, rooms, reply))
            .await;
    }

    pub async fn unlock(&self, room: Vec<u8>) {
        let _ = self.sender.send(SyncLockMessage::Unlock(room)).await;
    }
}
#[cfg(test)]
mod tests {

    use super::*;
    use crate::cryptography::{base64_encode, random32};
    use tokio::time::{sleep, Duration};

    #[tokio::test(flavor = "multi_thread")]
    async fn one_room_one_peer() {
        let lock_service = RoomLockService::new(1);

        let peer_id = 1;

        let rooms: VecDeque<Vec<u8>> = vec![random32().to_vec()].into();
        let (sender, mut receiver) = mpsc::channel::<Vec<u8>>(100);

        lock_service
            .request_locks(peer_id, rooms.clone(), sender.clone())
            .await;
        let room = receiver.recv().await.unwrap();

        lock_service.unlock(room).await;

        lock_service
            .request_locks(peer_id, rooms, sender.clone())
            .await;

        let room = receiver.recv().await.unwrap();

        lock_service.unlock(room).await;
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn some_rooms_some_peers() {
        let num_entries = 32;
        let lock_service = RoomLockService::new(num_entries);
        let mut rooms = VecDeque::new();

        for _ in 0..num_entries {
            rooms.push_back(random32().to_vec());
        }

        let mut tasks = Vec::with_capacity(num_entries);
        for peer_id in 0..num_entries {
            let service = lock_service.clone();
            let local_rooms = rooms.clone();
            tasks.push(tokio::spawn(async move {
                //  println!("Peer {} started", peer_id);
                let (sender, mut receiver) = mpsc::channel::<Vec<u8>>(num_entries);
                service
                    .clone()
                    .request_locks(peer_id, local_rooms, sender.clone())
                    .await;
                for _ in 0..num_entries {
                    let room = receiver.recv().await.unwrap();
                    // sleep(Duration::from_millis(10)).await;
                    // println!("Peer {} acquired {}", peer_id, base64_encode(&room));
                    service.unlock(room).await;
                }
                format!("---------peer {} finished", peer_id)
            }));
        }
        for task in tasks {
            //println!("{}", task.await.unwrap());
            task.await.unwrap();
        }
    }
}
