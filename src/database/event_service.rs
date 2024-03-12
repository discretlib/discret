use tokio::sync::{broadcast, mpsc, oneshot};

use super::{daily_log::DailyLogsUpdate, Error};

pub enum EventServiceMessage {
    Subscribe(oneshot::Sender<broadcast::Receiver<EventMessage>>),
    ComputedDailyLog(Result<DailyLogsUpdate, Error>),
}

#[derive(Clone)]
pub enum EventMessage {
    ComputedDailyLog(Result<DailyLogsUpdate, String>),
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
                };
            }
        });

        Self { sender }
    }
}
