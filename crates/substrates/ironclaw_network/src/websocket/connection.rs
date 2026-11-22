use std::{fmt, sync::Arc, time::Duration};

use futures_util::{
    SinkExt, StreamExt,
    stream::{SplitSink, SplitStream},
};
use tokio::{net::TcpStream, sync::Mutex, time::Instant};
use tokio_tungstenite::{MaybeTlsStream, WebSocketStream, tungstenite::Message};

use super::{
    error::WebSocketError,
    types::{WebSocketLimits, WebSocketMessage},
};

type Socket = WebSocketStream<MaybeTlsStream<TcpStream>>;
type SocketSink = SplitSink<Socket, Message>;
type SocketStream = SplitStream<Socket>;

const RATE_WINDOW: Duration = Duration::from_secs(1);

/// An open outbound WebSocket.
///
/// Use [`WebSocketConnection::split`] to send (for example ACK frames) while a
/// receive is pending. Control frames never surface: pings are answered,
/// pongs are consumed, and a close frame ends the stream.
pub struct WebSocketConnection {
    sender: WebSocketSender,
    receiver: WebSocketReceiver,
}

/// Cloneable write half. Writes are serialized and bounded by the idle timeout.
#[derive(Clone)]
pub struct WebSocketSender {
    sink: Arc<Mutex<SocketSink>>,
    limits: WebSocketLimits,
}

/// Read half. Also owns keepalive: it pings on the configured interval and
/// fails with [`WebSocketError::IdleTimeout`] when nothing arrives in time.
pub struct WebSocketReceiver {
    stream: SocketStream,
    sender: WebSocketSender,
    limits: WebSocketLimits,
    last_activity: Instant,
    ping: tokio::time::Interval,
    window_start: Instant,
    window_count: u32,
    state: ReceiverState,
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum ReceiverState {
    Open,
    Ended,
    Failed,
}

enum Event {
    Frame(Option<Result<Message, tokio_tungstenite::tungstenite::Error>>),
    PingDue,
    Idle,
}

impl WebSocketConnection {
    pub(crate) fn new(socket: Socket, limits: WebSocketLimits) -> Self {
        let (sink, stream) = socket.split();
        let sender = WebSocketSender {
            sink: Arc::new(Mutex::new(sink)),
            limits,
        };
        let now = Instant::now();
        let mut ping = tokio::time::interval_at(now + limits.ping_interval, limits.ping_interval);
        ping.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
        let receiver = WebSocketReceiver {
            stream,
            sender: sender.clone(),
            limits,
            last_activity: now,
            ping,
            window_start: now,
            window_count: 0,
            state: ReceiverState::Open,
        };
        Self { sender, receiver }
    }

    pub fn split(self) -> (WebSocketSender, WebSocketReceiver) {
        (self.sender, self.receiver)
    }

    pub async fn send(&self, message: WebSocketMessage) -> Result<(), WebSocketError> {
        self.sender.send(message).await
    }

    pub async fn recv(&mut self) -> Result<Option<WebSocketMessage>, WebSocketError> {
        self.receiver.recv().await
    }

    pub async fn close(&self) -> Result<(), WebSocketError> {
        self.sender.close().await
    }
}

impl fmt::Debug for WebSocketConnection {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("WebSocketConnection")
            .finish_non_exhaustive()
    }
}

impl WebSocketSender {
    /// Sends one data message as a single frame. Messages larger than
    /// `max_frame_bytes` are refused locally.
    pub async fn send(&self, message: WebSocketMessage) -> Result<(), WebSocketError> {
        if message.len() > self.limits.max_frame_bytes {
            return Err(WebSocketError::FrameTooLarge {
                limit: self.limits.max_frame_bytes,
            });
        }
        let frame = match message {
            WebSocketMessage::Text(text) => Message::Text(text.into()),
            WebSocketMessage::Binary(bytes) => Message::Binary(bytes.into()),
        };
        self.write(frame).await
    }

    /// Sends a close frame. A connection that is already closed reports
    /// [`WebSocketError::Closed`].
    pub async fn close(&self) -> Result<(), WebSocketError> {
        self.write(Message::Close(None)).await
    }

    async fn write(&self, frame: Message) -> Result<(), WebSocketError> {
        let mut sink = self.sink.lock().await;
        match tokio::time::timeout(self.limits.idle_timeout, sink.send(frame)).await {
            Ok(Ok(())) => Ok(()),
            Ok(Err(error)) => Err(WebSocketError::from_tungstenite(error, &self.limits)),
            Err(_elapsed) => Err(WebSocketError::SendTimeout),
        }
    }
}

impl fmt::Debug for WebSocketSender {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("WebSocketSender").finish_non_exhaustive()
    }
}

impl WebSocketReceiver {
    /// Next data message. `Ok(None)` means the peer closed the connection
    /// cleanly. Any error ends the connection; later calls return
    /// [`WebSocketError::Closed`].
    pub async fn recv(&mut self) -> Result<Option<WebSocketMessage>, WebSocketError> {
        match self.state {
            ReceiverState::Ended => return Ok(None),
            ReceiverState::Failed => return Err(WebSocketError::Closed),
            ReceiverState::Open => {}
        }
        let result = self.recv_open().await;
        match &result {
            Ok(None) => self.state = ReceiverState::Ended,
            Err(_) => self.state = ReceiverState::Failed,
            Ok(Some(_)) => {}
        }
        result
    }

    async fn recv_open(&mut self) -> Result<Option<WebSocketMessage>, WebSocketError> {
        loop {
            let deadline = self.last_activity + self.limits.idle_timeout;
            let event = tokio::select! {
                biased;
                frame = self.stream.next() => Event::Frame(frame),
                _ = self.ping.tick() => Event::PingDue,
                _ = tokio::time::sleep_until(deadline) => Event::Idle,
            };
            match event {
                Event::Idle => return Err(WebSocketError::IdleTimeout),
                Event::PingDue => self.sender.write(Message::Ping(Vec::new().into())).await?,
                Event::Frame(None) => return Ok(None),
                Event::Frame(Some(Err(error))) => {
                    return match WebSocketError::from_tungstenite(error, &self.limits) {
                        WebSocketError::Closed => Ok(None),
                        other => Err(other),
                    };
                }
                Event::Frame(Some(Ok(frame))) => {
                    self.last_activity = Instant::now();
                    match frame {
                        Message::Text(text) => {
                            self.admit_data(text.len())?;
                            return Ok(Some(WebSocketMessage::Text(text.to_string())));
                        }
                        Message::Binary(bytes) => {
                            self.admit_data(bytes.len())?;
                            return Ok(Some(WebSocketMessage::Binary(bytes.to_vec())));
                        }
                        Message::Ping(payload) => {
                            self.sender.write(Message::Pong(payload)).await?;
                        }
                        Message::Pong(_) | Message::Frame(_) => {}
                        Message::Close(_) => return Ok(None),
                    }
                }
            }
        }
    }

    /// Enforces the per-message size and per-second rate ceilings.
    fn admit_data(&mut self, len: usize) -> Result<(), WebSocketError> {
        if len > self.limits.max_message_bytes {
            return Err(WebSocketError::FrameTooLarge {
                limit: self.limits.max_message_bytes,
            });
        }
        let now = Instant::now();
        if now.duration_since(self.window_start) >= RATE_WINDOW {
            self.window_start = now;
            self.window_count = 0;
        }
        self.window_count = self.window_count.saturating_add(1);
        if self.window_count > self.limits.max_messages_per_second {
            return Err(WebSocketError::RateLimitExceeded {
                limit: self.limits.max_messages_per_second,
            });
        }
        Ok(())
    }
}

impl fmt::Debug for WebSocketReceiver {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("WebSocketReceiver").finish_non_exhaustive()
    }
}
