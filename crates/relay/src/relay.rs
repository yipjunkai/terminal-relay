use std::{net::IpAddr, sync::Arc, time::Duration};

use axum::{
    Json,
    extract::{ConnectInfo, Query, State, WebSocketUpgrade, ws::Message},
    http::StatusCode,
    response::IntoResponse,
};
use dashmap::DashMap;
use futures_util::{SinkExt, StreamExt};
use rand::{Rng, distributions::Alphanumeric, thread_rng};
use semver::Version;
use tokio::{sync::mpsc, time::Instant};
use tracing::{debug, info, warn};

use protocol::protocol::{
    PROTOCOL_VERSION, PROTOCOL_VERSION_MIN, PeerRole, PeerStatus, RegisterRequest,
    RegisterResponse, RelayError, RelayMessage, RelayRoute, decode_relay, encode_relay,
};

use crate::auth::{ApiKeyPayload, AuthState};

/// Typed error for relay-internal operations, replacing ad-hoc `Result<_, String>`.
#[derive(Debug)]
pub enum SessionError {
    /// Global session capacity reached.
    AtCapacity { current: usize, max: usize },
    /// Per-IP session limit reached.
    #[allow(dead_code)] // ip kept for future logging/metrics
    IpLimitReached { ip: IpAddr, current: usize, max: usize },
    /// Per-user (tier-based) session limit reached.
    UserLimitReached { tier: String, current: usize, max: usize },
    /// No compatible protocol version between client and server.
    ProtocolMismatch { client_range: String, server_range: String },
    /// Client version string is unparseable or too old.
    ClientVersionInvalid(String),
    /// Request field validation failure.
    InvalidRequest(String),
    /// Session locked after too many failed pairing attempts.
    SessionLocked,
    /// Pairing code does not match.
    PairingMismatch,
    /// Session not found.
    SessionNotFound,
    /// Peer role slot already occupied and resume token doesn't match.
    AlreadyConnected { role: PeerRole },
    /// Resume token doesn't match.
    InvalidResumeToken { role: PeerRole },
    /// Target peer is offline, cannot forward.
    PeerOffline,
    /// Bounded channel full, peer is slow to consume.
    ChannelFull,
}

impl std::fmt::Display for SessionError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::AtCapacity { current, max } => {
                write!(f, "server at capacity ({current}/{max}), try again later")
            }
            Self::IpLimitReached { current, max, .. } => {
                write!(f, "too many sessions from this IP ({current}/{max})")
            }
            Self::UserLimitReached { tier, current, max } => {
                write!(f, "session limit reached ({current}/{max} for {tier} tier). Upgrade your plan for more sessions.")
            }
            Self::ProtocolMismatch { client_range, server_range } => {
                write!(f, "no compatible protocol version: client supports {client_range}, server supports {server_range}")
            }
            Self::ClientVersionInvalid(msg) => write!(f, "{msg}"),
            Self::InvalidRequest(msg) => write!(f, "{msg}"),
            Self::SessionLocked => {
                write!(f, "session locked: too many failed pairing attempts")
            }
            Self::PairingMismatch => write!(f, "invalid pairing code"),
            Self::SessionNotFound => write!(f, "session not found"),
            Self::AlreadyConnected { role } => {
                write!(f, "{role:?} already connected for session")
            }
            Self::InvalidResumeToken { role } => {
                write!(f, "invalid {role:?} resume token")
            }
            Self::PeerOffline => write!(f, "peer is offline"),
            Self::ChannelFull => write!(f, "failed forwarding payload to peer"),
        }
    }
}

/// Channel capacity for per-peer relay message queues. Provides backpressure
/// instead of unbounded memory growth when a peer is slow to consume.
const PEER_CHANNEL_CAPACITY: usize = 1024;

/// Interval for the stale session cleanup loop.
const CLEANUP_INTERVAL_SECS: u64 = 60;

/// Length of generated resume tokens (alphanumeric characters).
const RESUME_TOKEN_LENGTH: usize = 40;

#[derive(Clone)]
struct PeerSlot {
    sender: Option<mpsc::Sender<RelayMessage>>,
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

/// Maximum failed pairing-code attempts before a session is locked out.
const MAX_PAIRING_FAILURES: u32 = 5;

#[derive(Clone)]
struct SessionSlot {
    pairing_code: String,
    host: PeerSlot,
    client: PeerSlot,
    last_activity: Instant,
    failed_pairing_attempts: u32,
    /// IP address of the host that created this session (for per-IP limits).
    host_ip: Option<IpAddr>,
    /// User ID of the host (from API key payload, for per-user limits).
    host_user_id: Option<String>,
}

impl SessionSlot {
    fn new(pairing_code: String) -> Self {
        Self {
            pairing_code,
            host: PeerSlot::new(),
            client: PeerSlot::new(),
            last_activity: Instant::now(),
            failed_pairing_attempts: 0,
            host_ip: None,
            host_user_id: None,
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

/// Per-tier session limits. Configurable via CLI args.
#[derive(Debug, Clone)]
pub struct TierLimits {
    pub free: usize,
    pub pro: usize,
}

impl Default for TierLimits {
    fn default() -> Self {
        Self { free: 3, pro: 20 }
    }
}

pub struct RelayState {
    sessions: DashMap<String, SessionSlot>,
    /// Tracks how many sessions each IP address owns (as host).
    ip_sessions: DashMap<IpAddr, usize>,
    /// Tracks how many sessions each user owns (by user ID from API key).
    user_sessions: DashMap<String, usize>,
    min_version: Version,
    session_ttl: Duration,
    /// Maximum total concurrent sessions (0 = unlimited).
    pub max_sessions: usize,
    /// Maximum concurrent sessions per IP (0 = unlimited).
    pub max_sessions_per_ip: usize,
    /// Per-tier session limits.
    tier_limits: TierLimits,
    /// Auth state for API key verification and control API communication.
    auth: Arc<AuthState>,
}

impl RelayState {
    pub fn new(
        min_version: String,
        session_ttl: Duration,
        max_sessions: usize,
        max_sessions_per_ip: usize,
        tier_limits: TierLimits,
        auth: Arc<AuthState>,
    ) -> anyhow::Result<Self> {
        let parsed_version = Version::parse(&min_version)
            .map_err(|e| anyhow::anyhow!("invalid --min-version \"{min_version}\": {e}"))?;
        Ok(Self {
            sessions: DashMap::new(),
            ip_sessions: DashMap::new(),
            user_sessions: DashMap::new(),
            min_version: parsed_version,
            session_ttl,
            max_sessions,
            max_sessions_per_ip,
            tier_limits,
            auth,
        })
    }

    pub fn session_count(&self) -> usize {
        self.sessions.len()
    }

    /// Get the session limit for a tier.
    fn tier_limit(&self, tier: &str) -> usize {
        match tier {
            "pro" => self.tier_limits.pro,
            _ => self.tier_limits.free, // "free" and any unknown tier
        }
    }

    /// Check whether a new session from this user is allowed.
    fn check_user_limit(&self, user_id: &str, tier: &str) -> Result<(), SessionError> {
        let limit = self.tier_limit(tier);
        if limit == 0 {
            return Ok(()); // unlimited
        }
        let count = self.user_sessions.get(user_id).map(|v| *v).unwrap_or(0);
        if count >= limit {
            warn!(
                %user_id,
                %tier,
                current = count,
                max = limit,
                "per-user session limit reached"
            );
            return Err(SessionError::UserLimitReached {
                tier: tier.to_string(),
                current: count,
                max: limit,
            });
        }
        Ok(())
    }

    /// Increment the user session counter.
    fn track_user(&self, user_id: &str) {
        *self.user_sessions.entry(user_id.to_string()).or_insert(0) += 1;
    }

    /// Decrement the user session counter.
    fn untrack_user(&self, user_id: &str) {
        if let Some(mut count) = self.user_sessions.get_mut(user_id) {
            *count = count.saturating_sub(1);
            if *count == 0 {
                drop(count);
                self.user_sessions.remove(user_id);
            }
        }
    }

    /// Check whether a new session from this IP is allowed.
    fn check_limits(&self, ip: IpAddr) -> Result<(), SessionError> {
        if self.max_sessions > 0 && self.sessions.len() >= self.max_sessions {
            warn!(
                current = self.sessions.len(),
                max = self.max_sessions,
                "global session limit reached"
            );
            return Err(SessionError::AtCapacity {
                current: self.sessions.len(),
                max: self.max_sessions,
            });
        }

        if self.max_sessions_per_ip > 0 {
            let count = self.ip_sessions.get(&ip).map(|v| *v).unwrap_or(0);
            if count >= self.max_sessions_per_ip {
                warn!(
                    %ip,
                    current = count,
                    max = self.max_sessions_per_ip,
                    "per-IP session limit reached"
                );
                return Err(SessionError::IpLimitReached {
                    ip,
                    current: count,
                    max: self.max_sessions_per_ip,
                });
            }
        }

        Ok(())
    }

    /// Increment the IP session counter.
    fn track_ip(&self, ip: IpAddr) {
        *self.ip_sessions.entry(ip).or_insert(0) += 1;
    }

    /// Decrement the IP session counter.
    fn untrack_ip(&self, ip: IpAddr) {
        if let Some(mut count) = self.ip_sessions.get_mut(&ip) {
            *count = count.saturating_sub(1);
            if *count == 0 {
                drop(count);
                self.ip_sessions.remove(&ip);
            }
        }
    }

    pub async fn cleanup_loop(self: Arc<Self>) {
        let mut ticker = tokio::time::interval(Duration::from_secs(CLEANUP_INTERVAL_SECS));
        loop {
            ticker.tick().await;
            let now = Instant::now();
            self.sessions.retain(|session_id, session| {
                let keep = now.duration_since(session.last_activity) <= self.session_ttl;
                if !keep {
                    info!(session_id = %session_id, "expiring stale session, notifying peers");
                    let expiry_msg = RelayMessage::Error(RelayError {
                        message: "session expired due to inactivity".to_string(),
                    });
                    for slot in [&session.host, &session.client] {
                        if let Some(sender) = &slot.sender {
                            let _ = sender.send(expiry_msg.clone());
                        }
                    }
                    // Clean up IP and user tracking for expired sessions.
                    if let Some(ip) = session.host_ip {
                        self.untrack_ip(ip);
                    }
                    if let Some(ref user_id) = session.host_user_id {
                        self.untrack_user(user_id);
                    }
                }
                keep
            });
        }
    }

    fn validate_version(&self, value: &str) -> Result<(), SessionError> {
        let parsed = Version::parse(value).map_err(|_| {
            SessionError::ClientVersionInvalid(format!("invalid client version string: {value}"))
        })?;
        if parsed < self.min_version {
            return Err(SessionError::ClientVersionInvalid(format!(
                "client version {parsed} is not supported, minimum required is {}",
                self.min_version
            )));
        }
        Ok(())
    }

    fn register(
        &self,
        request: &RegisterRequest,
        sender: mpsc::Sender<RelayMessage>,
        ip: IpAddr,
    ) -> Result<RegisterResponse, SessionError> {
        validate_register_request(request)?;

        // Protocol version range negotiation:
        // Client advertises [min..max], server supports [PROTOCOL_VERSION_MIN..PROTOCOL_VERSION].
        // The negotiated version is the highest version both sides support.
        let client_max = request.protocol_version;
        let client_min = request.protocol_version_min.unwrap_or(client_max);
        let server_max = PROTOCOL_VERSION;
        let server_min = PROTOCOL_VERSION_MIN;

        let negotiated = std::cmp::min(client_max, server_max);
        if negotiated < client_min || negotiated < server_min {
            return Err(SessionError::ProtocolMismatch {
                client_range: format!("{client_min}-{client_max}"),
                server_range: format!("{server_min}-{server_max}"),
            });
        }

        self.validate_version(&request.client_version)?;

        if request.role == PeerRole::Host {
            // Enforce limits only for new sessions (not resumes).
            let is_new = !self.sessions.contains_key(&request.session_id);
            if is_new {
                self.check_limits(ip)?;
            }

            let mut session = self
                .sessions
                .entry(request.session_id.clone())
                .or_insert_with(|| {
                    let mut slot = SessionSlot::new(request.pairing_code.clone());
                    slot.host_ip = Some(ip);
                    slot
                });

            if is_new {
                self.track_ip(ip);
            }

            let resume_token = Self::connect_peer_slot(
                &mut session,
                PeerRole::Host,
                &request.session_id,
                &request.pairing_code,
                request.resume_token.as_ref(),
                sender,
            )?;
            let peer_online = session.client.connected;

            return Ok(RegisterResponse {
                server_version: env!("CARGO_PKG_VERSION").to_string(),
                negotiated_protocol_version: negotiated,
                resume_token,
                peer_online,
                session_ttl_secs: self.session_ttl.as_secs(),
            });
        }

        // Client registration — session must already exist.
        let mut session = self
            .sessions
            .get_mut(&request.session_id)
            .ok_or(SessionError::SessionNotFound)?;

        let resume_token = Self::connect_peer_slot(
            &mut session,
            PeerRole::Client,
            &request.session_id,
            &request.pairing_code,
            request.resume_token.as_ref(),
            sender,
        )?;
        let peer_online = session.host.connected;

        Ok(RegisterResponse {
            server_version: env!("CARGO_PKG_VERSION").to_string(),
            negotiated_protocol_version: negotiated,
            resume_token,
            peer_online,
            session_ttl_secs: self.session_ttl.as_secs(),
        })
    }

    /// Validate pairing code and connect a peer slot. Shared by host and client registration.
    /// Returns the resume token on success.
    fn connect_peer_slot(
        session: &mut SessionSlot,
        role: PeerRole,
        session_id: &str,
        request_pairing_code: &str,
        request_resume_token: Option<&String>,
        sender: mpsc::Sender<RelayMessage>,
    ) -> Result<String, SessionError> {
        if session.failed_pairing_attempts >= MAX_PAIRING_FAILURES {
            warn!(session_id = %session_id, "session locked out after too many failed pairing attempts");
            return Err(SessionError::SessionLocked);
        }

        if session.pairing_code != request_pairing_code {
            session.failed_pairing_attempts += 1;
            warn!(
                session_id = %session_id,
                attempts = session.failed_pairing_attempts,
                "invalid pairing code"
            );
            return Err(SessionError::PairingMismatch);
        }

        let slot = session.slot_mut(role);
        if slot.connected {
            let can_resume = request_resume_token == Some(&slot.resume_token);
            if !can_resume {
                return Err(SessionError::AlreadyConnected { role });
            }
        }

        if let Some(token) = request_resume_token
            && token != &slot.resume_token
        {
            return Err(SessionError::InvalidResumeToken { role });
        }

        slot.sender = Some(sender);
        slot.connected = true;
        slot.last_seen = Instant::now();
        let resume_token = slot.resume_token.clone();

        session.last_activity = Instant::now();
        Ok(resume_token)
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

    fn route(&self, source_role: PeerRole, route: RelayRoute) -> Result<(), SessionError> {
        let mut session = self
            .sessions
            .get_mut(&route.session_id)
            .ok_or(SessionError::SessionNotFound)?;

        let target_role = source_role.opposite();
        let target = session.slot(target_role);
        if let Some(sender) = &target.sender {
            sender
                .try_send(RelayMessage::Route(route))
                .map_err(|_| SessionError::ChannelFull)?;
            session.last_activity = Instant::now();
            return Ok(());
        }

        Err(SessionError::PeerOffline)
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
            if sender.try_send(message).is_err() {
                debug!(session_id = %session_id, "peer status delivery failed");
            }
        }
    }
}

/// Maximum allowed length for string fields in `RegisterRequest`.
const MAX_SESSION_ID_LEN: usize = 64;
const MAX_PAIRING_CODE_LEN: usize = 32;
const MAX_CLIENT_VERSION_LEN: usize = 32;
const MAX_RESUME_TOKEN_LEN: usize = 64;

/// Validate format and length constraints on `RegisterRequest` fields.
fn validate_register_request(request: &RegisterRequest) -> Result<(), SessionError> {
    // session_id: must be valid UUID v4 format (36 chars: 8-4-4-4-12 hex)
    if request.session_id.len() > MAX_SESSION_ID_LEN {
        return Err(SessionError::InvalidRequest("session_id exceeds maximum length".into()));
    }
    if uuid::Uuid::parse_str(&request.session_id).is_err() {
        return Err(SessionError::InvalidRequest("session_id is not a valid UUID".into()));
    }

    // pairing_code: expected format XXXXXX-XXXXXX-XXXXXX (20 chars, uppercase alphanumeric + dashes)
    if request.pairing_code.len() > MAX_PAIRING_CODE_LEN {
        return Err(SessionError::InvalidRequest("pairing_code exceeds maximum length".into()));
    }
    if !is_valid_pairing_code(&request.pairing_code) {
        return Err(SessionError::InvalidRequest("pairing_code has invalid format".into()));
    }

    // client_version
    if request.client_version.len() > MAX_CLIENT_VERSION_LEN {
        return Err(SessionError::InvalidRequest("client_version exceeds maximum length".into()));
    }

    // resume_token (optional)
    if let Some(token) = &request.resume_token
        && token.len() > MAX_RESUME_TOKEN_LEN
    {
        return Err(SessionError::InvalidRequest("resume_token exceeds maximum length".into()));
    }

    Ok(())
}

/// Check that a pairing code matches the expected `XXXXXX-XXXXXX-XXXXXX` format.
fn is_valid_pairing_code(code: &str) -> bool {
    let parts: Vec<&str> = code.split('-').collect();
    if parts.len() != 3 {
        return false;
    }
    parts.iter().all(|part| {
        part.len() == 6
            && part
                .chars()
                .all(|c| c.is_ascii_uppercase() || c.is_ascii_digit())
    })
}

pub async fn health_handler(State(state): State<Arc<RelayState>>) -> Json<serde_json::Value> {
    Json(serde_json::json!({
        "status": "ok",
        "version": env!("CARGO_PKG_VERSION"),
        "sessions": state.session_count(),
        "max_sessions": state.max_sessions,
        "max_sessions_per_ip": state.max_sessions_per_ip,
    }))
}

#[derive(serde::Deserialize)]
pub struct WsQueryParams {
    api_key: Option<String>,
}

pub async fn ws_handler(
    ws: WebSocketUpgrade,
    ConnectInfo(addr): ConnectInfo<std::net::SocketAddr>,
    Query(params): Query<WsQueryParams>,
    State(state): State<Arc<RelayState>>,
) -> impl IntoResponse {
    if !state.auth.is_enabled() {
        // Open relay mode — no auth required.
        return ws
            .on_upgrade(move |socket| handle_socket(socket, state, addr.ip(), None))
            .into_response();
    }

    // Auth is enabled. If an API key is provided, validate it (hosts must provide one).
    // If no key is provided, allow the upgrade — the connection will be checked in
    // handle_socket after we know the role. Clients can join authenticated sessions
    // without their own key (the host already paid for the session).
    if let Some(api_key) = params.api_key {
        match state.auth.verify_api_key(&api_key).await {
            Some(payload) => {
                if let Err(err) = state.check_user_limit(&payload.uid, &payload.tier) {
                    return (StatusCode::TOO_MANY_REQUESTS, err.to_string()).into_response();
                }
                info!(
                    user_id = %payload.uid,
                    key_id = %payload.kid,
                    tier = %payload.tier,
                    ip = %addr.ip(),
                    "authenticated WebSocket upgrade"
                );
                ws.on_upgrade(move |socket| {
                    handle_socket(socket, state, addr.ip(), Some(payload))
                })
                .into_response()
            }
            None => {
                warn!(ip = %addr.ip(), "WebSocket upgrade rejected: invalid or revoked API key");
                (StatusCode::FORBIDDEN, "invalid or revoked API key").into_response()
            }
        }
    } else {
        // No API key — allow upgrade, enforce role-based auth in handle_socket.
        info!(ip = %addr.ip(), "unauthenticated WebSocket upgrade (pending role check)");
        ws.on_upgrade(move |socket| handle_socket(socket, state, addr.ip(), None))
            .into_response()
    }
}

async fn handle_socket(
    socket: axum::extract::ws::WebSocket,
    state: Arc<RelayState>,
    ip: IpAddr,
    api_key_payload: Option<ApiKeyPayload>,
) {
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

    // Track bytes for usage reporting
    let mut bytes_up: u64 = 0;
    let mut bytes_down: u64 = 0;
    let connected_at = Instant::now();

    // Role-based auth enforcement: hosts must be authenticated, clients can join
    // existing sessions that were created by an authenticated host.
    if state.auth.is_enabled() && api_key_payload.is_none() {
        match register_request.role {
            PeerRole::Host => {
                warn!(
                    session_id = %register_request.session_id,
                    ip = %ip,
                    "rejecting unauthenticated host"
                );
                let _ = send_error(&mut sink, "authentication required for host connections").await;
                return;
            }
            PeerRole::Client => {
                // Allow if the session exists and was created by an authenticated host.
                let session_authenticated = state
                    .sessions
                    .get(&register_request.session_id)
                    .map(|s| s.host_user_id.is_some())
                    .unwrap_or(false);
                if !session_authenticated {
                    warn!(
                        session_id = %register_request.session_id,
                        ip = %ip,
                        "rejecting unauthenticated client: session not found or host not authenticated"
                    );
                    let _ = send_error(&mut sink, "session not found or requires authentication").await;
                    return;
                }
                info!(
                    session_id = %register_request.session_id,
                    ip = %ip,
                    "client joining authenticated session without API key"
                );
            }
        }
    }

    // Report session start to control API (fire-and-forget)
    if let Some(ref payload) = api_key_payload {
        let auth = Arc::clone(&state.auth);
        let session_id = register_request.session_id.clone();
        let user_id = payload.uid.clone();
        tokio::spawn(async move {
            auth.report_session_started(&session_id, &user_id, None)
                .await;
        });
    }

    let (tx, mut rx) = mpsc::channel::<RelayMessage>(PEER_CHANNEL_CAPACITY);
    let register_response = match state.register(&register_request, tx.clone(), ip) {
        Ok(registered) => registered,
        Err(err) => {
            let _ = send_error(&mut sink, &err.to_string()).await;
            return;
        }
    };

    // Track per-user session count (host role only, since hosts create sessions)
    if register_request.role == PeerRole::Host
        && let Some(ref payload) = api_key_payload {
            state.track_user(&payload.uid);
            // Store user_id on the session slot for cleanup
            if let Some(mut session) = state.sessions.get_mut(&register_request.session_id) {
                session.host_user_id = Some(payload.uid.clone());
            }
        }

    let registered_message = RelayMessage::Registered(register_response.clone());
    if send_wire(&mut sink, &registered_message).await.map(|_| ()).is_err() {
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
        let _ = tx.try_send(RelayMessage::PeerStatus(PeerStatus {
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
                        bytes_up += bytes.len() as u64;
                        match decode_relay(&bytes) {
                            Ok(RelayMessage::Route(route)) => {
                                // Validate the Route targets the sender's own session,
                                // preventing cross-session message injection.
                                if route.session_id != register_request.session_id {
                                    let _ = tx.try_send(RelayMessage::Error(RelayError {
                                        message: "route session_id does not match registered session".into(),
                                    }));
                                } else if let Err(err) = state.route(register_request.role, route) {
                                    let _ = tx.try_send(RelayMessage::Error(RelayError { message: err.to_string() }));
                                }
                            }
                            Ok(RelayMessage::Ping(value)) => {
                                let _ = tx.try_send(RelayMessage::Pong(value));
                            }
                            Ok(_) => {
                                let _ = tx.try_send(RelayMessage::Error(RelayError {
                                    message: "unsupported relay frame".into(),
                                }));
                            }
                            Err(err) => {
                                let _ = tx.try_send(RelayMessage::Error(RelayError {
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
                match send_wire(&mut sink, &message).await {
                    Ok(len) => bytes_down += len as u64,
                    Err(()) => break,
                }
            }
        }
    }

    state.set_disconnected(&register_request.session_id, register_request.role);
    state.notify_peer_status(&register_request.session_id, register_request.role, false);

    // Untrack per-user session count
    if register_request.role == PeerRole::Host
        && let Some(ref payload) = api_key_payload {
            state.untrack_user(&payload.uid);
        }

    let duration_ms = connected_at.elapsed().as_millis() as u64;
    info!(
        session_id = %register_request.session_id,
        role = ?register_request.role,
        bytes_up,
        bytes_down,
        duration_ms,
        "peer disconnected"
    );

    // Report session end to control API (fire-and-forget)
    if let Some(ref payload) = api_key_payload {
        let auth = Arc::clone(&state.auth);
        let session_id = register_request.session_id.clone();
        let user_id = payload.uid.clone();
        tokio::spawn(async move {
            auth.report_session_ended(&session_id, &user_id, bytes_up, bytes_down, duration_ms)
                .await;
        });
    }
}

/// Encode and send a relay message. Returns the number of bytes sent on success.
async fn send_wire(
    sink: &mut futures_util::stream::SplitSink<axum::extract::ws::WebSocket, Message>,
    message: &RelayMessage,
) -> Result<usize, ()> {
    let bytes = encode_relay(message).map_err(|_| ())?;
    let len = bytes.len();
    sink.send(Message::Binary(bytes.into()))
        .await
        .map_err(|_| ())?;
    Ok(len)
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
    .map(|_| ())
}

fn generate_resume_token() -> String {
    thread_rng()
        .sample_iter(&Alphanumeric)
        .map(char::from)
        .take(RESUME_TOKEN_LENGTH)
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn valid_register_request() -> RegisterRequest {
        RegisterRequest {
            session_id: "550e8400-e29b-41d4-a716-446655440000".to_string(),
            pairing_code: "ABCDEF-GHIJKL-MNOPQR".to_string(),
            role: PeerRole::Host,
            protocol_version: PROTOCOL_VERSION,
            protocol_version_min: Some(PROTOCOL_VERSION_MIN),
            client_version: "0.1.0".to_string(),
            resume_token: None,
        }
    }

    // ── is_valid_pairing_code ────────────────────────────────────────

    #[test]
    fn pairing_code_valid_uppercase() {
        assert!(is_valid_pairing_code("ABCDEF-GHIJKL-MNOPQR"));
    }

    #[test]
    fn pairing_code_valid_with_digits() {
        assert!(is_valid_pairing_code("ABC123-DEF456-GHI789"));
    }

    #[test]
    fn pairing_code_lowercase_rejected() {
        assert!(!is_valid_pairing_code("abcdef-ghijkl-mnopqr"));
    }

    #[test]
    fn pairing_code_wrong_segment_count() {
        assert!(!is_valid_pairing_code("ABCDEF-GHIJKL"));
    }

    #[test]
    fn pairing_code_wrong_segment_length() {
        assert!(!is_valid_pairing_code("ABCDE-FGHIJK-LMNOPQ"));
    }

    #[test]
    fn pairing_code_empty() {
        assert!(!is_valid_pairing_code(""));
    }

    #[test]
    fn pairing_code_special_chars() {
        assert!(!is_valid_pairing_code("ABC!EF-GHI@KL-MNO#QR"));
    }

    // ── validate_register_request ────────────────────────────────────

    #[test]
    fn register_request_valid() {
        assert!(validate_register_request(&valid_register_request()).is_ok());
    }

    #[test]
    fn register_request_invalid_uuid() {
        let mut req = valid_register_request();
        req.session_id = "not-a-uuid".to_string();
        let err = validate_register_request(&req).unwrap_err();
        assert!(matches!(err, SessionError::InvalidRequest(_)));
    }

    #[test]
    fn register_request_long_session_id() {
        let mut req = valid_register_request();
        req.session_id = "a".repeat(MAX_SESSION_ID_LEN + 1);
        assert!(validate_register_request(&req).is_err());
    }

    #[test]
    fn register_request_long_pairing_code() {
        let mut req = valid_register_request();
        req.pairing_code = "A".repeat(MAX_PAIRING_CODE_LEN + 1);
        assert!(validate_register_request(&req).is_err());
    }

    #[test]
    fn register_request_bad_pairing_format() {
        let mut req = valid_register_request();
        req.pairing_code = "invalid-format".to_string();
        assert!(validate_register_request(&req).is_err());
    }

    #[test]
    fn register_request_long_client_version() {
        let mut req = valid_register_request();
        req.client_version = "x".repeat(MAX_CLIENT_VERSION_LEN + 1);
        assert!(validate_register_request(&req).is_err());
    }

    #[test]
    fn register_request_long_resume_token() {
        let mut req = valid_register_request();
        req.resume_token = Some("t".repeat(MAX_RESUME_TOKEN_LEN + 1));
        assert!(validate_register_request(&req).is_err());
    }

    #[test]
    fn register_request_valid_with_resume_token() {
        let mut req = valid_register_request();
        req.resume_token = Some("valid-token-123".to_string());
        assert!(validate_register_request(&req).is_ok());
    }

    // ── SessionError Display ─────────────────────────────────────────

    #[test]
    fn session_error_display_contains_relevant_info() {
        let err = SessionError::UserLimitReached { tier: "free".into(), current: 3, max: 3 };
        let msg = err.to_string();
        assert!(msg.contains("free"), "should mention tier: {msg}");
        assert!(msg.contains("3"), "should mention count: {msg}");

        let err = SessionError::ProtocolMismatch { client_range: "1-2".into(), server_range: "1-2".into() };
        assert!(err.to_string().contains("1-2"));

        let err = SessionError::AlreadyConnected { role: PeerRole::Host };
        assert!(err.to_string().contains("Host"));

        // Verify all variants produce non-empty messages
        let all_errors: Vec<SessionError> = vec![
            SessionError::AtCapacity { current: 10, max: 10 },
            SessionError::IpLimitReached { ip: "127.0.0.1".parse().unwrap(), current: 5, max: 5 },
            SessionError::SessionLocked,
            SessionError::PairingMismatch,
            SessionError::SessionNotFound,
            SessionError::InvalidResumeToken { role: PeerRole::Client },
            SessionError::PeerOffline,
            SessionError::ChannelFull,
            SessionError::ClientVersionInvalid("bad".into()),
            SessionError::InvalidRequest("bad".into()),
        ];
        for err in &all_errors {
            assert!(!err.to_string().is_empty(), "empty Display for {:?}", err);
        }
    }

    #[test]
    fn session_error_at_capacity_contains_counts() {
        let err = SessionError::AtCapacity { current: 42, max: 50 };
        let msg = err.to_string();
        assert!(msg.contains("42"), "missing current count: {msg}");
        assert!(msg.contains("50"), "missing max count: {msg}");
    }

    // ── tier_limit / TierLimits ──────────────────────────────────────

    #[test]
    fn tier_limits_default() {
        let limits = TierLimits::default();
        assert_eq!(limits.free, 3);
        assert_eq!(limits.pro, 20);
    }

    #[test]
    fn tier_limit_returns_correct_values() {
        let state = test_relay_state();
        assert_eq!(state.tier_limit("free"), 3);
        assert_eq!(state.tier_limit("pro"), 20);
    }

    #[test]
    fn tier_limit_unknown_defaults_to_free() {
        let state = test_relay_state();
        assert_eq!(state.tier_limit("enterprise"), state.tier_limit("free"));
    }

    // ── generate_resume_token ────────────────────────────────────────

    #[test]
    fn resume_token_correct_length() {
        let token = generate_resume_token();
        assert_eq!(token.len(), RESUME_TOKEN_LENGTH);
    }

    #[test]
    fn resume_token_alphanumeric() {
        let token = generate_resume_token();
        assert!(token.chars().all(|c| c.is_ascii_alphanumeric()));
    }

    #[test]
    fn resume_tokens_are_unique() {
        let tokens: std::collections::HashSet<String> =
            (0..100).map(|_| generate_resume_token()).collect();
        assert_eq!(tokens.len(), 100);
    }

    // ── Helper ───────────────────────────────────────────────────────

    fn test_relay_state() -> RelayState {
        RelayState::new(
            "0.1.0".to_string(),
            Duration::from_secs(300),
            100,
            10,
            TierLimits::default(),
            Arc::new(
                AuthState::new("test-secret".to_string(), None, None, None)
                    .expect("test AuthState"),
            ),
        )
        .expect("test RelayState")
    }
}
