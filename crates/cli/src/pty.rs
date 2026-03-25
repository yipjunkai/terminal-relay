use std::{
    io::{Read, Write},
    sync::mpsc,
    thread,
};

use anyhow::Context;
use portable_pty::{CommandBuilder, PtySize, native_pty_system};
use tokio::sync::{mpsc as tokio_mpsc, oneshot};
use tracing::{debug, warn};

/// Channel capacity for PTY output chunks.
const PTY_OUTPUT_CHANNEL_CAPACITY: usize = 512;

pub struct PtySession {
    input_tx: mpsc::Sender<Vec<u8>>,
    resize_tx: mpsc::Sender<(u16, u16)>,
}

pub struct PtyStreams {
    pub output_rx: tokio_mpsc::Receiver<Vec<u8>>,
    pub exit_rx: oneshot::Receiver<i32>,
}

impl PtySession {
    pub fn spawn(
        command: &str,
        args: &[String],
        rows: u16,
        cols: u16,
    ) -> anyhow::Result<(Self, PtyStreams)> {
        let pty_system = native_pty_system();
        let pair = pty_system
            .openpty(PtySize {
                rows,
                cols,
                pixel_width: 0,
                pixel_height: 0,
            })
            .context("failed to allocate PTY")?;

        let mut cmd = CommandBuilder::new(command);
        for arg in args {
            cmd.arg(arg);
        }
        // Inherit the current working directory so the spawned tool
        // runs in the same directory the user started farwatch from.
        if let Ok(cwd) = std::env::current_dir() {
            cmd.cwd(cwd);
        }

        let mut child = pair
            .slave
            .spawn_command(cmd)
            .context("failed to spawn PTY child")?;
        drop(pair.slave);

        let mut reader = pair
            .master
            .try_clone_reader()
            .context("failed to clone PTY reader")?;
        let mut writer = pair
            .master
            .take_writer()
            .context("failed taking PTY writer")?;
        let master = pair.master;

        let (output_tx, output_rx) = tokio_mpsc::channel::<Vec<u8>>(PTY_OUTPUT_CHANNEL_CAPACITY);
        let (input_tx, input_rx) = mpsc::channel::<Vec<u8>>();
        let (resize_tx, resize_rx) = mpsc::channel::<(u16, u16)>();
        let (exit_tx, exit_rx) = oneshot::channel::<i32>();

        thread::spawn(move || {
            let mut buffer = [0_u8; crate::constants::READ_BUFFER_SIZE];
            loop {
                match reader.read(&mut buffer) {
                    Ok(0) => {
                        debug!("PTY reader got EOF");
                        break;
                    }
                    Ok(n) => {
                        if output_tx.blocking_send(buffer[..n].to_vec()).is_err() {
                            debug!("PTY output channel closed");
                            break;
                        }
                    }
                    Err(err) => {
                        warn!(error = %err, "PTY read failed");
                        break;
                    }
                }
            }
        });

        thread::spawn(move || {
            while let Ok(bytes) = input_rx.recv() {
                if let Err(err) = writer.write_all(&bytes) {
                    warn!(error = %err, "PTY write failed");
                    break;
                }
                if let Err(err) = writer.flush() {
                    warn!(error = %err, "PTY flush failed");
                    break;
                }
            }
        });

        // The master handle is only needed for resize — move it directly
        // into the resize thread. No Arc/Mutex needed since no sharing occurs.
        thread::spawn(move || {
            while let Ok((rows, cols)) = resize_rx.recv() {
                if master
                    .resize(PtySize {
                        rows,
                        cols,
                        pixel_width: 0,
                        pixel_height: 0,
                    })
                    .is_err()
                {
                    warn!(rows, cols, "failed resizing PTY");
                }
            }
        });

        thread::spawn(move || {
            let status = child.wait();
            let code = status
                .ok()
                .map(|s| s.exit_code())
                .and_then(|s| i32::try_from(s).ok())
                .unwrap_or(1);
            let _ = exit_tx.send(code);
        });

        Ok((
            Self {
                input_tx,
                resize_tx,
            },
            PtyStreams { output_rx, exit_rx },
        ))
    }

    pub fn send_input(&self, data: Vec<u8>) -> anyhow::Result<()> {
        self.input_tx
            .send(data)
            .map_err(|_| anyhow::anyhow!("PTY input channel closed"))
    }

    pub fn resize(&self, cols: u16, rows: u16) -> anyhow::Result<()> {
        self.resize_tx
            .send((rows, cols))
            .map_err(|_| anyhow::anyhow!("PTY resize channel closed"))
    }
}
