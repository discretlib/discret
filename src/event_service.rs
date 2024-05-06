use tokio::sync::{broadcast, mpsc, oneshot};

use crate::database::{authorisation_service::Room, daily_log::DailyLogsUpdate};

pub enum EventServiceMessage {
    Subscribe(oneshot::Sender<broadcast::Receiver<EventMessage>>),
    ComputedDailyLog(Result<DailyLogsUpdate, crate::Error>),
    RoomModified(Room),
}

#[derive(Clone)]
pub enum EventMessage {
    ComputedDailyLog(Result<DailyLogsUpdate, String>),
    RoomModified(Room),
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
}
