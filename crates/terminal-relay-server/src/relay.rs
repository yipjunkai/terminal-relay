use std::{sync::Arc, time::Duration};

use axum::{
    Json,
    extract::{State, WebSocketUpgrade, ws::Message},
    response::IntoResponse,
};
use dashmap::DashMap;
use futures_util::{SinkExt, StreamExt};
use rand::{Rng, distributions::Alphanumeric, thread_rng};
use semver::Version;
use tokio::{sync::mpsc, time::Instant};
use tracing::{debug, info, warn};

use terminal_relay_core::protocol::{
    PROTOCOL_VERSION, PeerRole, PeerStatus, RegisterRequest, RegisterResponse, RelayError,
    RelayMessage, RelayRoute, decode_relay, encode_relay,
};

#[derive(Clone)]
struct PeerSlot {
    sender: Option<mpsc::UnboundedSender<RelayMessage>>,
    resume_token: String,
    connected: bool,
    last_seen: Instant,
}

impl PeerSlot {
    fn new() -> Self {
        Self {
            sender: None,
            resume_token: generate_resume_token(),
            connected: false,
            last_seen: Instant::now(),
        }
    }
}

#[derive(Clone)]
struct SessionSlot {
    pairing_code: String,
    host: PeerSlot,
    client: PeerSlot,
    last_activity: Instant,
}

impl SessionSlot {
    fn new(pairing_code: String) -> Self {
        Self {
            pairing_code,
            host: PeerSlot::new(),
            client: PeerSlot::new(),
            last_activity: Instant::now(),
        }
    }

    fn slot_mut(&mut self, role: PeerRole) -> &mut PeerSlot {
        match role {
            PeerRole::Host => &mut self.host,
            PeerRole::Client => &mut self.client,
        }
    }

    fn slot(&self, role: PeerRole) -> &PeerSlot {
        match role {
            PeerRole::Host => &self.host,
            PeerRole::Client => &self.client,
        }
    }
}

pub struct RelayState {
    sessions: DashMap<String, SessionSlot>,
    min_version: Version,
    session_ttl: Duration,
}

impl RelayState {
    pub fn new(min_version: String, session_ttl: Duration) -> Self {
        let parsed_version = Version::parse(&min_version).unwrap_or_else(|_| Version::new(0, 1, 0));
        Self {
            sessions: DashMap::new(),
            min_version: parsed_version,
            session_ttl,
        }
    }

    pub async fn cleanup_loop(self: Arc<Self>) {
        let mut ticker = tokio::time::interval(Duration::from_secs(60));
        loop {
            ticker.tick().await;
            let now = Instant::now();
            self.sessions.retain(|session_id, session| {
                let keep = now.duration_since(session.last_activity) <= self.session_ttl;
                if !keep {
                    info!(session_id = %session_id, "expired stale session");
                }
                keep
            });
        }
    }

    fn validate_version(&self, value: &str) -> Result<(), String> {
        let parsed =
            Version::parse(value).map_err(|_| format!("invalid client version string: {value}"))?;
        if parsed < self.min_version {
            return Err(format!(
                "client version {parsed} is not supported, minimum required is {}",
                self.min_version
            ));
        }
        Ok(())
    }

    fn register(
        &self,
        request: &RegisterRequest,
        sender: mpsc::UnboundedSender<RelayMessage>,
    ) -> Result<RegisterResponse, String> {
        if request.protocol_version != PROTOCOL_VERSION {
            return Err(format!(
                "unsupported protocol version {}, expected {}",
                request.protocol_version, PROTOCOL_VERSION
            ));
        }
        self.validate_version(&request.client_version)?;

        if request.role == PeerRole::Host {
            let mut session = self
                .sessions
                .entry(request.session_id.clone())
                .or_insert_with(|| SessionSlot::new(request.pairing_code.clone()));

            if session.pairing_code != request.pairing_code {
                return Err("invalid pairing code".into());
            }

            let resume_token = {
                let host = session.slot_mut(PeerRole::Host);
                if host.connected {
                    let can_resume = request.resume_token.as_ref() == Some(&host.resume_token);
                    if !can_resume {
                        return Err("host already connected for session".into());
                    }
                }

                if let Some(token) = &request.resume_token {
                    if token != &host.resume_token {
                        return Err("invalid host resume token".into());
                    }
                }

                host.sender = Some(sender);
                host.connected = true;
                host.last_seen = Instant::now();
                host.resume_token.clone()
            };

            let peer_online = session.client.connected;
            session.last_activity = Instant::now();

            return Ok(RegisterResponse {
                resume_token,
                peer_online,
                session_ttl_secs: self.session_ttl.as_secs(),
            });
        }

        let mut session = self
            .sessions
            .get_mut(&request.session_id)
            .ok_or_else(|| "unknown session id".to_string())?;

        if session.pairing_code != request.pairing_code {
            return Err("invalid pairing code".into());
        }

        let resume_token = {
            let client = session.slot_mut(PeerRole::Client);
            if client.connected {
                let can_resume = request.resume_token.as_ref() == Some(&client.resume_token);
                if !can_resume {
                    return Err("client already connected for session".into());
                }
            }

            if let Some(token) = &request.resume_token {
                if token != &client.resume_token {
                    return Err("invalid client resume token".into());
                }
            }

            client.sender = Some(sender);
            client.connected = true;
            client.last_seen = Instant::now();
            client.resume_token.clone()
        };

        let peer_online = session.host.connected;
        session.last_activity = Instant::now();

        Ok(RegisterResponse {
            resume_token,
            peer_online,
            session_ttl_secs: self.session_ttl.as_secs(),
        })
    }

    fn set_disconnected(&self, session_id: &str, role: PeerRole) -> Option<PeerRole> {
        let mut session = self.sessions.get_mut(session_id)?;
        let slot = session.slot_mut(role);
        slot.connected = false;
        slot.sender = None;
        slot.last_seen = Instant::now();
        session.last_activity = Instant::now();
        Some(role.opposite())
    }

    fn peer_online(&self, session_id: &str, role: PeerRole) -> bool {
        self.sessions
            .get(session_id)
            .map(|session| session.slot(role).connected)
            .unwrap_or(false)
    }

    fn route(&self, source_role: PeerRole, route: RelayRoute) -> Result<(), String> {
        let mut session = self
            .sessions
            .get_mut(&route.session_id)
            .ok_or_else(|| "session not found".to_string())?;

        let target_role = source_role.opposite();
        let target = session.slot(target_role);
        if let Some(sender) = &target.sender {
            sender
                .send(RelayMessage::Route(route))
                .map_err(|_| "failed forwarding payload to peer".to_string())?;
            session.last_activity = Instant::now();
            return Ok(());
        }

        Err("peer is offline".to_string())
    }

    fn notify_peer_status(&self, session_id: &str, role: PeerRole, online: bool) {
        let Some(session) = self.sessions.get(session_id) else {
            return;
        };

        let target_role = role.opposite();
        let target = session.slot(target_role);
        if let Some(sender) = &target.sender {
            let message = RelayMessage::PeerStatus(PeerStatus {
                session_id: session_id.to_string(),
                role,
                online,
            });
            if sender.send(message).is_err() {
                debug!(session_id = %session_id, "peer status delivery failed");
            }
        }
    }
}

pub async fn health_handler() -> Json<&'static str> {
    Json("ok")
}

pub async fn ws_handler(
    ws: WebSocketUpgrade,
    State(state): State<Arc<RelayState>>,
) -> impl IntoResponse {
    ws.on_upgrade(move |socket| handle_socket(socket, state))
}

async fn handle_socket(socket: axum::extract::ws::WebSocket, state: Arc<RelayState>) {
    let (mut sink, mut stream) = socket.split();

    let Some(first_message) = stream.next().await else {
        return;
    };

    let register_request = match first_message {
        Ok(Message::Binary(bytes)) => match decode_relay(&bytes) {
            Ok(RelayMessage::Register(req)) => req,
            Ok(_) => {
                let _ = send_error(&mut sink, "first frame must be Register").await;
                return;
            }
            Err(err) => {
                let _ = send_error(&mut sink, &format!("decode error: {err}")).await;
                return;
            }
        },
        Ok(_) => {
            let _ = send_error(&mut sink, "websocket frame must be binary").await;
            return;
        }
        Err(err) => {
            warn!(error = %err, "failed receiving first websocket frame");
            return;
        }
    };

    let (tx, mut rx) = mpsc::unbounded_channel::<RelayMessage>();
    let register_response = match state.register(&register_request, tx.clone()) {
        Ok(registered) => registered,
        Err(message) => {
            let _ = send_error(&mut sink, &message).await;
            return;
        }
    };

    let registered_message = RelayMessage::Registered(register_response.clone());
    if send_wire(&mut sink, &registered_message).await.is_err() {
        return;
    }

    info!(
        session_id = %register_request.session_id,
        role = ?register_request.role,
        "peer connected"
    );

    state.notify_peer_status(&register_request.session_id, register_request.role, true);
    if state.peer_online(
        &register_request.session_id,
        register_request.role.opposite(),
    ) {
        let _ = tx.send(RelayMessage::PeerStatus(PeerStatus {
            session_id: register_request.session_id.clone(),
            role: register_request.role.opposite(),
            online: true,
        }));
    }

    loop {
        tokio::select! {
            incoming = stream.next() => {
                let Some(frame) = incoming else {
                    break;
                };
                match frame {
                    Ok(Message::Binary(bytes)) => {
                        match decode_relay(&bytes) {
                            Ok(RelayMessage::Route(route)) => {
                                if let Err(message) = state.route(register_request.role, route) {
                                    let _ = tx.send(RelayMessage::Error(RelayError { message }));
                                }
                            }
                            Ok(RelayMessage::Ping(value)) => {
                                let _ = tx.send(RelayMessage::Pong(value));
                            }
                            Ok(_) => {
                                let _ = tx.send(RelayMessage::Error(RelayError {
                                    message: "unsupported relay frame".into(),
                                }));
                            }
                            Err(err) => {
                                let _ = tx.send(RelayMessage::Error(RelayError {
                                    message: format!("decode error: {err}"),
                                }));
                            }
                        }
                    }
                    Ok(Message::Ping(payload)) => {
                        if sink.send(Message::Pong(payload)).await.is_err() {
                            break;
                        }
                    }
                    Ok(Message::Pong(_)) => {}
                    Ok(Message::Close(_)) => break,
                    Ok(_) => {}
                    Err(err) => {
                        warn!(session_id = %register_request.session_id, error = %err, "websocket read failed");
                        break;
                    }
                }
            }
            outbound = rx.recv() => {
                let Some(message) = outbound else {
                    break;
                };
                if send_wire(&mut sink, &message).await.is_err() {
                    break;
                }
            }
        }
    }

    state.set_disconnected(&register_request.session_id, register_request.role);
    state.notify_peer_status(&register_request.session_id, register_request.role, false);
    info!(
        session_id = %register_request.session_id,
        role = ?register_request.role,
        "peer disconnected"
    );
}

async fn send_wire(
    sink: &mut futures_util::stream::SplitSink<axum::extract::ws::WebSocket, Message>,
    message: &RelayMessage,
) -> Result<(), ()> {
    let bytes = encode_relay(message).map_err(|_| ())?;
    sink.send(Message::Binary(bytes.into()))
        .await
        .map_err(|_| ())
}

async fn send_error(
    sink: &mut futures_util::stream::SplitSink<axum::extract::ws::WebSocket, Message>,
    message: &str,
) -> Result<(), ()> {
    send_wire(
        sink,
        &RelayMessage::Error(RelayError {
            message: message.to_string(),
        }),
    )
    .await
}

fn generate_resume_token() -> String {
    thread_rng()
        .sample_iter(&Alphanumeric)
        .map(char::from)
        .take(40)
        .collect()
}
