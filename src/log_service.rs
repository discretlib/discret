use tokio::sync::{broadcast, mpsc, oneshot};

use crate::date_utils::now;
use crate::Error;

pub enum LogMessage {
    Subscribe(oneshot::Sender<broadcast::Receiver<Log>>),
    Info(i64, String),
    Error(i64, Error),
}

#[derive(Clone)]
pub enum Log {
    Info(i64, String),
    Error(i64, String),
}

#[derive(Clone)]
pub struct LogService {
    pub sender: mpsc::UnboundedSender<LogMessage>,
}
impl LogService {
    pub fn new() -> Self {
        let (sender, mut receiver) = mpsc::unbounded_channel();

        let (broadcast, _) = broadcast::channel(16);

        tokio::spawn(async move {
            while let Some(msg) = receiver.recv().await {
                match msg {
                    LogMessage::Subscribe(reply) => {
                        let _ = reply.send(broadcast.subscribe());
                    }
                    LogMessage::Info(date, s) => {
                        let _ = broadcast.send(Log::Info(date, s));
                    }
                    LogMessage::Error(date, e) => {
                        let _ = broadcast.send(Log::Error(date, e.to_string()));
                    }
                };
            }
        });
        Self { sender }
    }

    pub async fn subcribe_for_events(&self) -> broadcast::Receiver<Log> {
        let (sender, receiver) = oneshot::channel::<broadcast::Receiver<Log>>();
        let _ = self.sender.send(LogMessage::Subscribe(sender));
        receiver.await.unwrap()
    }

    pub fn info(&self, str: String) {
        let _ = self.sender.send(LogMessage::Info(now(), str));
    }

    pub fn error(&self, err: Error) {
        let _ = self.sender.send(LogMessage::Error(now(), err));
    }
}
