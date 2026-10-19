// SPDX-FileCopyrightText: Copyright Logically Magic Inc. <hello@logicallymagic.com>
// SPDX-FileCopyrightText: Copyright Hamid Jahanzad <Hamid@Jahanzad.com>
// SPDX-FileCopyrightText: Copyright Contributors to the Sentin8:Proxy
// SPDX-License-Identifier: Apache-2.0

//! Bidirectional TCP pipe — copies bytes between client and backend
//! in both directions until either side closes.

use tokio::io::AsyncWriteExt;
use tokio::net::TcpStream;

/// Pipe bytes bidirectionally between `client` and `backend`.
///
/// Uses `tokio::io::copy` in both directions via `tokio::join!`. When
/// either direction completes (EOF or error), both halves are shut down.
/// No timeout — long-lived connections (SSE, WebSocket) are supported.
pub async fn pipe_bidirectional(mut client: TcpStream, mut backend: TcpStream) {
    let (mut client_rd, mut client_wr) = client.split();
    let (mut backend_rd, mut backend_wr) = backend.split();

    let c2b = tokio::io::copy(&mut client_rd, &mut backend_wr);
    let b2c = tokio::io::copy(&mut backend_rd, &mut client_wr);

    tokio::select! {
        _ = c2b => {
            let _ = client_wr.shutdown().await;
            let _ = backend_wr.shutdown().await;
        }
        _ = b2c => {
            let _ = client_wr.shutdown().await;
            let _ = backend_wr.shutdown().await;
        }
    }
}
