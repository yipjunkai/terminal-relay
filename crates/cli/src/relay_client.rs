use std::time::Duration;

use anyhow::Context;
use futures_util::{SinkExt, StreamExt};
use tokio::sync::mpsc;
use tokio_tungstenite::{connect_async, tungstenite::Message};
use tracing::{debug, warn};

use protocol::protocol::{
    RegisterRequest, RegisterResponse, RelayMessage, decode_relay, encode_relay,
};

/// Timeout for the initial WebSocket connect + registration exchange.
const CONNECT_TIMEOUT: Duration = Duration::from_secs(15);

pub struct RelayConnection {
    sender: mpsc::UnboundedSender<RelayMessage>,
    receiver: mpsc::UnboundedReceiver<RelayMessage>,
}

impl RelayConnection {
    pub async fn connect(
        url: &str,
        register: RegisterRequest,
        api_key: Option<&str>,
    ) -> anyhow::Result<(Self, RegisterResponse)> {
        tokio::time::timeout(CONNECT_TIMEOUT, Self::connect_inner(url, register, api_key))
            .await
            .map_err(|_| {
                anyhow::anyhow!("connection to relay timed out after {CONNECT_TIMEOUT:?}")
            })?
    }

    async fn connect_inner(
        url: &str,
        register: RegisterRequest,
        api_key: Option<&str>,
    ) -> anyhow::Result<(Self, RegisterResponse)> {
        // Append API key as query parameter if provided
        let connect_url = match api_key {
            Some(key) => {
                let separator = if url.contains('?') { '&' } else { '?' };
                format!("{url}{separator}api_key={key}")
            }
            None => url.to_string(),
        };

        let (ws, _) = connect_async(&connect_url).await.map_err(|e| {
            let msg = e.to_string();
            if msg.contains("401") || msg.contains("403") {
                anyhow::anyhow!(
                    "relay rejected authentication ({}). Your API key may be invalid or revoked.\n\
                     Run `terminal-relay auth` to re-authenticate.",
                    msg
                )
            } else {
                anyhow::anyhow!("failed connecting to relay url {url}: {e}")
            }
        })?;
        let (mut sink, mut stream) = ws.split();

        let bytes = encode_relay(&RelayMessage::Register(register))?;
        sink.send(Message::Binary(bytes.into()))
            .await
            .context("failed to send register frame")?;

        let first = stream
            .next()
            .await
            .ok_or_else(|| anyhow::anyhow!("relay disconnected during registration"))??;

        let response = match first {
            Message::Binary(bytes) => match decode_relay(&bytes)? {
                RelayMessage::Registered(registered) => registered,
                RelayMessage::Error(err) => {
                    return Err(anyhow::anyhow!(
                        "relay registration rejected: {}",
                        err.message
                    ));
                }
                other => {
                    return Err(anyhow::anyhow!(
                        "unexpected relay response during registration: {other:?}"
                    ));
                }
            },
            _ => {
                return Err(anyhow::anyhow!(
                    "unexpected non-binary relay response during registration"
                ));
            }
        };

        let (outbound_tx, mut outbound_rx) = mpsc::unbounded_channel::<RelayMessage>();
        let (inbound_tx, inbound_rx) = mpsc::unbounded_channel::<RelayMessage>();

        tokio::spawn(async move {
            while let Some(message) = outbound_rx.recv().await {
                match encode_relay(&message) {
                    Ok(bytes) => {
                        if sink.send(Message::Binary(bytes.into())).await.is_err() {
                            break;
                        }
                    }
                    Err(err) => {
                        warn!(error = %err, "failed encoding relay frame");
                    }
                }
            }
        });

        tokio::spawn(async move {
            while let Some(frame) = stream.next().await {
                match frame {
                    Ok(Message::Binary(bytes)) => match decode_relay(&bytes) {
                        Ok(message) => {
                            if inbound_tx.send(message).is_err() {
                                break;
                            }
                        }
                        Err(err) => {
                            warn!(error = %err, "failed decoding relay frame");
                        }
                    },
                    Ok(Message::Ping(_)) | Ok(Message::Pong(_)) => {}
                    Ok(Message::Close(_)) => break,
                    Ok(_) => {}
                    Err(err) => {
                        debug!(error = %err, "relay stream terminated");
                        break;
                    }
                }
            }
        });

        Ok((
            Self {
                sender: outbound_tx,
                receiver: inbound_rx,
            },
            response,
        ))
    }

    pub fn sender(&self) -> mpsc::UnboundedSender<RelayMessage> {
        self.sender.clone()
    }

    pub async fn recv(&mut self) -> Option<RelayMessage> {
        self.receiver.recv().await
    }
}
