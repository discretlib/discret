use std::collections::{HashMap, HashSet, VecDeque};

use tokio::sync::mpsc;

use crate::security::Uid;

pub enum SyncLockMessage {
    RequestLock(Vec<u8>, VecDeque<Uid>, mpsc::UnboundedSender<Uid>),
    Unlock(Uid),
}

struct PeerLockRequest {
    rooms: VecDeque<Uid>,
    reply: mpsc::UnboundedSender<Uid>,
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
    pub fn start(max_lock: usize) -> Self {
        let (sender, mut receiver) = mpsc::channel::<SyncLockMessage>(LOCK_CHANNEL_SIZE);
        tokio::spawn(async move {
            let mut peer_lock_request: HashMap<Vec<u8>, PeerLockRequest> = HashMap::new();
            let mut peer_queue: VecDeque<Vec<u8>> = VecDeque::new();
            let mut locked: HashSet<Uid> = HashSet::new();
            let mut avalaible = max_lock;

            while let Some(msg) = receiver.recv().await {
                match msg {
                    SyncLockMessage::RequestLock(peer, rooms, reply) => {
                        if let Some(lock_request) = peer_lock_request.get_mut(&peer) {
                            lock_request.reply = reply;
                            for room in rooms {
                                if lock_request.rooms.iter().find(|e| room.eq(*e)).is_none() {
                                    lock_request.rooms.push_back(room); //"hot" rooms are updated first
                                }
                            }
                        } else {
                            peer_lock_request
                                .insert(peer.clone(), PeerLockRequest { reply, rooms });
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
        peer_lock_request: &mut HashMap<Vec<u8>, PeerLockRequest>,
        peer_queue: &mut VecDeque<Vec<u8>>,
        locked: &mut HashSet<Uid>,
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
                                if let Ok(_) = lock_request.reply.send(room.clone()) {
                                    locked.insert(room);
                                    *avalaible -= 1;
                                    lock_aquired = true;
                                    break;
                                };
                            }
                        }
                    }
                    if !lock_request.rooms.is_empty() {
                        peer_lock_request.insert(peer.clone(), lock_request);
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
        peer_id: Vec<u8>,
        rooms: VecDeque<Uid>,
        reply: mpsc::UnboundedSender<Uid>,
    ) {
        let _ = self
            .sender
            .send(SyncLockMessage::RequestLock(peer_id, rooms, reply))
            .await;
    }

    pub async fn unlock(&self, room: Uid) {
        let _ = self.sender.send(SyncLockMessage::Unlock(room)).await;
    }
}
#[cfg(test)]
mod tests {

    use super::*;
    use crate::security::{base64_encode, new_uid, random32};

    #[tokio::test(flavor = "multi_thread")]
    async fn one_room_one_peer() {
        let lock_service = RoomLockService::start(1);

        let peer_id = random32().to_vec();

        let rooms: VecDeque<Uid> = vec![new_uid()].into();
        let (sender, mut receiver) = mpsc::unbounded_channel::<Uid>();

        lock_service
            .request_locks(peer_id.clone(), rooms.clone(), sender.clone())
            .await;
        let room = receiver.recv().await.unwrap();

        lock_service.unlock(room).await;

        lock_service
            .request_locks(peer_id.clone(), rooms, sender.clone())
            .await;

        let room = receiver.recv().await.unwrap();

        lock_service.unlock(room).await;
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn some_rooms_some_peers() {
        let num_entries = 32;
        let lock_service = RoomLockService::start(num_entries);
        let mut rooms = VecDeque::new();

        for _ in 0..num_entries {
            rooms.push_back(new_uid());
        }

        let mut tasks = Vec::with_capacity(num_entries);
        for _ in 0..num_entries {
            let service = lock_service.clone();
            let local_rooms = rooms.clone();
            let peer = random32().to_vec();
            tasks.push(tokio::spawn(async move {
                //  println!("Peer {} started", peer_id);
                let (sender, mut receiver) = mpsc::unbounded_channel::<Uid>();
                service
                    .clone()
                    .request_locks(peer.clone(), local_rooms, sender.clone())
                    .await;
                for _ in 0..num_entries {
                    let room = receiver.recv().await.unwrap();
                    // sleep(Duration::from_millis(10)).await;
                    // println!("Peer {} acquired {}", peer_id, base64_encode(&room));
                    service.unlock(room).await;
                }
                format!("---------peer {} finished", base64_encode(&peer))
            }));
        }
        for task in tasks {
            //println!("{}", task.await.unwrap());
            task.await.unwrap();
        }
    }
}
