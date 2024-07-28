use std::sync::Arc;

use tokio::sync::{broadcast, mpsc, oneshot};

use crate::{
    base64_encode,
    database::{room::Room, DataModification},
    security::Uid,
};

pub enum EventServiceMessage {
    Subscribe(oneshot::Sender<broadcast::Receiver<Event>>),
    DataChanged(DataModification),
    RoomModified(Room),
    PeerConnected(Vec<u8>, i64, Uid),
    PeerDisconnected(Vec<u8>, i64, Uid),
    RoomSynchronized(Uid),
    PendingPeer(),
    PendingHardware(),
}

///
/// The list of events that are sent by Discret
///
#[derive(Clone)]
pub enum Event {
    ///
    /// This event is triggered whenever data is modified or inserted. Data is inserted/deleted in batches and this events describes each batch.
    /// **data_modification** constains a *HashMap*:
    /// - the key is the identifier of the *Rooms* that have been modified
    /// - the data contains the modified Entity name and the mutation days (date without hour:minutes:second).
    DataChanged(Arc<DataModification>),

    ///
    /// This event is triggered when a *Room* is modified.
    ///
    RoomModified(Arc<Room>),

    /// This event is triggered when a peer has connected successfully to your device.
    /// - **verifying_key**: the peer verifying key,
    /// - **date**: the connection date,
    ///- **connection_id**: the unique identifier of the connection
    PeerConnected(Vec<u8>, i64, String),

    /// This event is triggered when a peer have been disconnected
    /// - **verifying_key**: the peer verifying key,
    /// - **date**: the connection date,
    /// - **connection_id**: the unique identifier of the connection
    PeerDisconnected(Vec<u8>, i64, String),

    /// This event is triggered when a *Room* has been synchronized.
    /// - **room_id**: the *Room* identifier
    RoomSynchronized(String),

    /// This event is triggered when a new peer is found when synchronising a **Room**.
    PendingPeer(),

    /// This event is triggered when a new device is detected.
    PendingHardware(),
}

#[derive(Clone)]
pub struct EventService {
    pub sender: mpsc::Sender<EventServiceMessage>,
}
impl EventService {
    pub fn new() -> Self {
        let (sender, mut receiver) = mpsc::channel(100);

        let (broadcast, _) = broadcast::channel(16);

        tokio::spawn(async move {
            while let Some(msg) = receiver.recv().await {
                match msg {
                    EventServiceMessage::Subscribe(reply) => {
                        let _ = reply.send(broadcast.subscribe());
                    }
                    EventServiceMessage::DataChanged(res) => {
                        let _ = broadcast.send(Event::DataChanged(Arc::new(res)));
                    }
                    EventServiceMessage::RoomModified(room) => {
                        let _ = broadcast.send(Event::RoomModified(Arc::new(room)));
                    }
                    EventServiceMessage::PeerConnected(verifying_key, date, connection_id) => {
                        let _ = broadcast.send(Event::PeerConnected(
                            verifying_key,
                            date,
                            base64_encode(&connection_id),
                        ));
                    }
                    EventServiceMessage::PeerDisconnected(verifying_key, date, connection_id) => {
                        let _ = broadcast.send(Event::PeerDisconnected(
                            verifying_key,
                            date,
                            base64_encode(&connection_id),
                        ));
                    }
                    EventServiceMessage::RoomSynchronized(room) => {
                        let _ = broadcast.send(Event::RoomSynchronized(base64_encode(&room)));
                    }
                    EventServiceMessage::PendingPeer() => {
                        let _ = broadcast.send(Event::PendingPeer());
                    }
                    EventServiceMessage::PendingHardware() => {
                        let _ = broadcast.send(Event::PendingHardware());
                    }
                };
            }
        });

        Self { sender }
    }

    pub async fn subcribe(&self) -> broadcast::Receiver<Event> {
        let (sender, receiver) = oneshot::channel::<broadcast::Receiver<Event>>();
        let _ = self
            .sender
            .send(EventServiceMessage::Subscribe(sender))
            .await;

        receiver.await.unwrap()
    }

    pub async fn notify(&self, msg: EventServiceMessage) {
        let _ = self.sender.send(msg).await;
    }
}
