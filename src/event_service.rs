use tokio::sync::{broadcast, mpsc, oneshot};

use crate::database::{daily_log::DailyLogsUpdate, room::Room};

pub enum EventServiceMessage {
    Subscribe(oneshot::Sender<broadcast::Receiver<EventMessage>>),
    ComputedDailyLog(Result<DailyLogsUpdate, crate::Error>),
    RoomModified(Room),
    PeerConnected(Vec<u8>, i64, i64),
    PeerDisconnected(Vec<u8>, i64, i64),
}

#[derive(Clone)]
pub enum EventMessage {
    ComputedDailyLog(Result<DailyLogsUpdate, String>),
    RoomModified(Room),
    PeerConnected(Vec<u8>, i64, i64),
    PeerDisconnected(Vec<u8>, i64, i64),
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
                    EventServiceMessage::ComputedDailyLog(res) => {
                        let _ = match res {
                            Ok(e) => broadcast.send(EventMessage::ComputedDailyLog(Ok(e))),
                            Err(e) => {
                                broadcast.send(EventMessage::ComputedDailyLog(Err(e.to_string())))
                            }
                        };
                    }
                    EventServiceMessage::Subscribe(reply) => {
                        let _ = reply.send(broadcast.subscribe());
                    }
                    EventServiceMessage::RoomModified(room) => {
                        let _ = broadcast.send(EventMessage::RoomModified(room));
                    }
                    EventServiceMessage::PeerConnected(verifying_key, date, id) => {
                        let _ =
                            broadcast.send(EventMessage::PeerConnected(verifying_key, date, id));
                    }
                    EventServiceMessage::PeerDisconnected(verifying_key, date, id) => {
                        let _ =
                            broadcast.send(EventMessage::PeerDisconnected(verifying_key, date, id));
                    }
                };
            }
        });

        Self { sender }
    }

    pub async fn subcribe_for_events(&self) -> broadcast::Receiver<EventMessage> {
        let (sender, receiver) = oneshot::channel::<broadcast::Receiver<EventMessage>>();
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
