use std::{
    io::{Read, Write},
    sync::{Arc, Mutex, mpsc},
    thread,
};

use anyhow::Context;
use portable_pty::{CommandBuilder, MasterPty, PtySize, native_pty_system};
use tokio::sync::{mpsc as tokio_mpsc, oneshot};
use tracing::warn;

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
        let master: Arc<Mutex<Box<dyn MasterPty + Send>>> = Arc::new(Mutex::new(pair.master));

        let (output_tx, output_rx) = tokio_mpsc::channel::<Vec<u8>>(512);
        let (input_tx, input_rx) = mpsc::channel::<Vec<u8>>();
        let (resize_tx, resize_rx) = mpsc::channel::<(u16, u16)>();
        let (exit_tx, exit_rx) = oneshot::channel::<i32>();

        thread::spawn(move || {
            let mut buffer = [0_u8; 4096];
            loop {
                match reader.read(&mut buffer) {
                    Ok(0) => break,
                    Ok(n) => {
                        if output_tx.blocking_send(buffer[..n].to_vec()).is_err() {
                            break;
                        }
                    }
                    Err(_) => break,
                }
            }
        });

        thread::spawn(move || {
            while let Ok(bytes) = input_rx.recv() {
                if writer.write_all(&bytes).is_err() {
                    break;
                }
                if writer.flush().is_err() {
                    break;
                }
            }
        });

        let resize_master = Arc::clone(&master);
        thread::spawn(move || {
            while let Ok((rows, cols)) = resize_rx.recv() {
                let Ok(guard) = resize_master.lock() else {
                    break;
                };
                if guard
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
