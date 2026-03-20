/// Production relay server URL. Users connect here by default.
pub const DEFAULT_RELAY_URL: &str = "wss://terminal-relay.fly.dev/ws";

/// Environment variable name to override the relay URL.
pub const RELAY_URL_ENV: &str = "TERMINAL_RELAY_URL";

/// Directory name for local state (under user's home directory).
pub const STATE_DIR_NAME: &str = ".terminal-relay";

/// Application name used in CLI help and metadata.
pub const APP_NAME: &str = "terminal-relay";

/// Client version sent during relay registration.
pub const CLIENT_VERSION: &str = env!("CARGO_PKG_VERSION");
