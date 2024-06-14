use std::sync::Arc;

use tokio::sync::{broadcast, mpsc, oneshot};

use crate::{
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
}

#[derive(Clone)]
pub enum Event {
    DataChanged(Arc<DataModification>),
    RoomModified(Arc<Room>),
    PeerConnected(Vec<u8>, i64, Uid),
    PeerDisconnected(Vec<u8>, i64, Uid),
    RoomSynchronized(Uid),
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
                            connection_id,
                        ));
                    }
                    EventServiceMessage::PeerDisconnected(verifying_key, date, connection_id) => {
                        let _ = broadcast.send(Event::PeerDisconnected(
                            verifying_key,
                            date,
                            connection_id,
                        ));
                    }
                    EventServiceMessage::RoomSynchronized(room) => {
                        let _ = broadcast.send(Event::RoomSynchronized(room));
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
