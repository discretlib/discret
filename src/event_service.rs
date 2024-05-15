use tokio::sync::{broadcast, mpsc, oneshot};

use crate::database::{daily_log::DailyLogsUpdate, room::Room};

pub enum EventServiceMessage {
    Subscribe(oneshot::Sender<broadcast::Receiver<Event>>),
    ComputedDailyLog(Result<DailyLogsUpdate, crate::Error>),
    RoomModified(Room),
    PeerConnected(Vec<u8>, i64, Vec<u8>),
    PeerDisconnected(Vec<u8>, i64, Vec<u8>),
}

#[derive(Clone)]
pub enum Event {
    ComputedDailyLog(Result<DailyLogsUpdate, String>),
    RoomModified(Room),
    PeerConnected(Vec<u8>, i64, Vec<u8>),
    PeerDisconnected(Vec<u8>, i64, Vec<u8>),
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
                    EventServiceMessage::ComputedDailyLog(res) => {
                        let _ = match res {
                            Ok(e) => broadcast.send(Event::ComputedDailyLog(Ok(e))),
                            Err(e) => broadcast.send(Event::ComputedDailyLog(Err(e.to_string()))),
                        };
                    }
                    EventServiceMessage::RoomModified(room) => {
                        let _ = broadcast.send(Event::RoomModified(room));
                    }
                    EventServiceMessage::PeerConnected(verifying_key, date, hardware_key) => {
                        let _ =
                            broadcast.send(Event::PeerConnected(verifying_key, date, hardware_key));
                    }
                    EventServiceMessage::PeerDisconnected(verifying_key, date, hardware_key) => {
                        let _ = broadcast.send(Event::PeerDisconnected(
                            verifying_key,
                            date,
                            hardware_key,
                        ));
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
