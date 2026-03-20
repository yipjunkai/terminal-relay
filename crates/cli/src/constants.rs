/// Production relay server URL. Users connect here by default.
pub const DEFAULT_RELAY_URL: &str = "wss://terminal-relay.fly.dev/ws";

/// Production control API URL for registration and key management.
pub const DEFAULT_CONTROL_API_URL: &str = "https://terminal-relay-control.fly.dev";

/// Environment variable name to override the relay URL.
pub const RELAY_URL_ENV: &str = "TERMINAL_RELAY_URL";

/// Environment variable name to override the control API URL.
pub const CONTROL_API_URL_ENV: &str = "TERMINAL_RELAY_CONTROL_URL";

/// Environment variable name for the API key.
pub const API_KEY_ENV: &str = "TERMINAL_RELAY_API_KEY";

/// Directory name for local state (under user's home directory).
pub const STATE_DIR_NAME: &str = ".terminal-relay";

/// Application name used in CLI help and metadata.
pub const APP_NAME: &str = "terminal-relay";

/// Client version sent during relay registration.
pub const CLIENT_VERSION: &str = env!("CARGO_PKG_VERSION");
