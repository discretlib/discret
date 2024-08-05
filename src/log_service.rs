use tokio::sync::{broadcast, mpsc, oneshot};

use crate::date_utils::now;
use crate::Error;

pub enum LogMessage {
    Subscribe(oneshot::Sender<broadcast::Receiver<Log>>),
    Info(i64, String),
    Error(i64, String, Error),
}

#[derive(Clone)]
///The Log event types
pub enum Log {
    //info level the first parameter is the log date
    Info(i64, String),
    //error level the first parameter is the log date, the second is the source of the error, the third is the error message
    Error(i64, String, String),
}
///
/// The service that is receiving the logs sent by Discret and broadcast them to listeners
///
#[derive(Clone)]
pub struct LogService {
    pub sender: mpsc::UnboundedSender<LogMessage>,
}
impl LogService {
    ///starts the service
    pub fn start() -> Self {
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
                    LogMessage::Error(date, src, e) => {
                        let _ = broadcast.send(Log::Error(date, src, e.to_string()));
                    }
                };
            }
        });
        Self { sender }
    }

    /// subsribe to the event stream
    pub async fn subcribe(&self) -> broadcast::Receiver<Log> {
        let (sender, receiver) = oneshot::channel::<broadcast::Receiver<Log>>();
        let _ = self.sender.send(LogMessage::Subscribe(sender));
        receiver.await.unwrap()
    }

    ///write a log with the info level
    pub fn info(&self, str: String) {
        println!("{}: {}", now(), str);
        let _ = self.sender.send(LogMessage::Info(now(), str));
    }
    ///write a log with the error level
    pub fn error(&self, src: String, err: Error) {
        println!("{}: {} - {}", now(), src, err.to_string());
        let _ = self.sender.send(LogMessage::Error(now(), src, err));
    }
}
