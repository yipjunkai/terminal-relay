/// Production relay server URL. Users connect here by default.
pub const DEFAULT_RELAY_URL: &str = "wss://farwatch-relay.fly.dev/ws";

/// Production control API URL for registration and key management.
#[cfg(feature = "hosted")]
pub const DEFAULT_CONTROL_API_URL: &str = "https://farwatch-control.fly.dev";

/// Environment variable name to override the relay URL.
pub const RELAY_URL_ENV: &str = "FARWATCH_URL";

/// Environment variable name to override the control API URL.
#[cfg(feature = "hosted")]
pub const CONTROL_API_URL_ENV: &str = "FARWATCH_CONTROL_URL";

/// Environment variable name for the API key.
#[cfg(feature = "hosted")]
pub const API_KEY_ENV: &str = "FARWATCH_API_KEY";

/// Directory name for local state (under user's home directory).
pub const STATE_DIR_NAME: &str = ".farwatch";

/// Application name used in CLI help and metadata.
pub const APP_NAME: &str = "farwatch";

/// Client version sent during relay registration.
pub const CLIENT_VERSION: &str = env!("CARGO_PKG_VERSION");

// ── Shared timing constants ─────────────────────────────────────────────

/// Heartbeat interval for relay keepalive pings.
pub const HEARTBEAT_INTERVAL_SECS: u64 = 10;

/// TUI redraw interval in milliseconds.
pub const REDRAW_INTERVAL_MS: u64 = 250;

/// Double-tap Esc timeout for exiting takeover mode (milliseconds).
pub const DOUBLE_TAP_ESC_MS: u128 = 300;

// ── Shared size constants ───────────────────────────────────────────────

/// Default terminal size fallback (cols, rows) when detection fails.
pub const DEFAULT_TERMINAL_SIZE: (u16, u16) = (120, 40);

/// Read buffer size for PTY output and stdin readers.
pub const READ_BUFFER_SIZE: usize = 4096;

/// Output backlog cap in bytes (1 MB). Oldest entries are evicted when exceeded.
pub const OUTPUT_BACKLOG_CAP: usize = 1024 * 1024;

// ── OpenCode adapter constants ──────────────────────────────────────────

/// Default port for the OpenCode serve HTTP server.
pub const OPENCODE_DEFAULT_PORT: u16 = 18923;

/// Timeout for OpenCode server health check during startup (seconds).
pub const OPENCODE_HEALTH_TIMEOUT_SECS: u64 = 30;

/// Polling interval while waiting for OpenCode server to become healthy (ms).
pub const OPENCODE_HEALTH_POLL_MS: u64 = 200;

/// Maximum tool result content length before truncation (32 KB).
pub const OPENCODE_MAX_RESULT_LEN: usize = 32 * 1024;
