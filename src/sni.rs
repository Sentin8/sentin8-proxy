// SPDX-FileCopyrightText: Copyright Logically Magic Inc. <hello@logicallymagic.com>
// SPDX-FileCopyrightText: Copyright Hamid Jahanzad <Hamid@Jahanzad.com>
// SPDX-FileCopyrightText: Copyright Contributors to the Sentin8:Proxy
// SPDX-License-Identifier: Apache-2.0

//! SNI peeking - extract the SNI hostname from the plaintext TLS ClientHello.
//!
//! The TLS `ClientHello` is the first record of a TLS handshake and is
//! **not encrypted** - it contains the `server_name` extension (SNI) in
//! plaintext. Prox reads just enough of the first record to extract the
//! SNI hostname, then pipes the entire stream (including the already-read
//! bytes) verbatim to the target.
//!
//! Uses `TcpStream::peek` (non-destructive) so the full `ClientHello`
//! remains in the socket buffer for the pipe to forward verbatim.

use std::io;

use tokio::net::TcpStream;

/// The maximum size of a TLS ClientHello we'll buffer for SNI parsing.
/// TLS records have a 5-byte header with a 16-bit length, so the max
/// record is 16K+5. But ClientHello is typically a few hundred bytes.
const MAX_CLIENT_HELLO: usize = 4096;

/// Peek the SNI hostname from the TLS ClientHello without consuming bytes.
///
/// Returns `Ok(Some(hostname))` if SNI is present, `Ok(None)` if the
/// ClientHello has no SNI extension, or `Err` if the data is not a valid
/// TLS ClientHello.
pub async fn peek_sni(stream: &TcpStream) -> io::Result<Option<String>> {
    // Peek up to MAX_CLIENT_HELLO bytes (non-destructive).
    let mut buf = vec![0u8; MAX_CLIENT_HELLO];
    let n = stream.peek(&mut buf).await?;

    if n < 5 {
        return Err(io::Error::new(
            io::ErrorKind::UnexpectedEof,
            "not enough bytes for TLS record header",
        ));
    }

    // TLS record header: 1 byte type (0x16 = Handshake), 2 bytes version,
    // 2 bytes length.
    if buf[0] != 0x16 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "not a TLS handshake record",
        ));
    }

    parse_sni_from_record(&buf[..n])
}

/// Parse the SNI from a TLS record buffer.
fn parse_sni_from_record(buf: &[u8]) -> io::Result<Option<String>> {
    // TLS record: type(1) + version(2) + length(2) + handshake...
    if buf.len() < 5 {
        return Err(io::Error::new(
            io::ErrorKind::UnexpectedEof,
            "TLS record too short",
        ));
    }

    // Handshake: type(1) + length(3) + ...
    let handshake_start = 5;
    if buf.len() < handshake_start + 4 {
        return Err(io::Error::new(
            io::ErrorKind::UnexpectedEof,
            "handshake header too short",
        ));
    }

    // Handshake type must be ClientHello (0x01)
    if buf[handshake_start] != 0x01 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "not a ClientHello",
        ));
    }

    // Parse the ClientHello body. We need to navigate:
    // HandshakeType(1) + Length(3) + ClientVersion(2) + Random(32) +
    // SessionID(1+n) + CipherSuites(2+n) + CompressionMethods(1+n) +
    // Extensions(2+n)
    let mut pos = handshake_start + 4; // skip handshake type + length
    if pos + 2 + 32 >= buf.len() {
        return Ok(None); // Not enough data to parse further.
    }
    pos += 2; // client version
    pos += 32; // random

    // Session ID
    if pos >= buf.len() {
        return Ok(None);
    }
    let session_id_len = buf[pos] as usize;
    pos += 1 + session_id_len;
    if pos + 2 > buf.len() {
        return Ok(None);
    }

    // Cipher suites
    let cipher_suites_len = u16::from_be_bytes([buf[pos], buf[pos + 1]]) as usize;
    pos += 2 + cipher_suites_len;
    if pos + 1 > buf.len() {
        return Ok(None);
    }

    // Compression methods
    let compression_len = buf[pos] as usize;
    pos += 1 + compression_len;
    if pos + 2 > buf.len() {
        return Ok(None); // No extensions.
    }

    // Extensions
    let extensions_len = u16::from_be_bytes([buf[pos], buf[pos + 1]]) as usize;
    pos += 2;

    let extensions_end = pos + extensions_len;
    if extensions_end > buf.len() {
        // We don't have the full extensions block, but we can still try
        // to find the SNI extension in what we have.
    }

    // Iterate extensions.
    while pos + 4 <= buf.len() && pos < extensions_end.min(buf.len()) {
        let ext_type = u16::from_be_bytes([buf[pos], buf[pos + 1]]);
        let ext_len = u16::from_be_bytes([buf[pos + 2], buf[pos + 3]]) as usize;
        pos += 4;

        let ext_data_end = pos + ext_len;
        if ext_type == 0x0000 {
            // SNI extension (server_name)
            // SNI list: length(2) + entries...
            if pos + 2 > buf.len() {
                return Ok(None);
            }
            let _sni_list_len = u16::from_be_bytes([buf[pos], buf[pos + 1]]);
            let mut sni_pos = pos + 2;
            while sni_pos + 3 <= ext_data_end.min(buf.len()) {
                let name_type = buf[sni_pos];
                let name_len = u16::from_be_bytes([buf[sni_pos + 1], buf[sni_pos + 2]]) as usize;
                sni_pos += 3;
                if name_type == 0x00 {
                    // host_name
                    if sni_pos + name_len > buf.len() {
                        return Ok(None);
                    }
                    let hostname = String::from_utf8_lossy(&buf[sni_pos..sni_pos + name_len]);
                    return Ok(Some(hostname.to_string()));
                }
                sni_pos += name_len;
            }
            return Ok(None);
        }
        pos = ext_data_end;
    }

    Ok(None)
}

#[cfg(test)]
mod tests {
    use super::*;

    // SNI extension payload: a server_name list of host_name entries.
    fn sni_extension(names: &[&str]) -> Vec<u8> {
        let mut list = Vec::new();
        for name in names {
            list.push(0x00); // host_name
            list.extend_from_slice(&(name.len() as u16).to_be_bytes());
            list.extend_from_slice(name.as_bytes());
        }
        let mut ext = Vec::new();
        ext.extend_from_slice(&(list.len() as u16).to_be_bytes());
        ext.extend_from_slice(&list);
        ext
    }

    // Build a full TLS record wrapping a ClientHello with the given
    // (extension_type, extension_data) pairs in wire order.
    fn client_hello_record(extensions: &[(u16, Vec<u8>)]) -> Vec<u8> {
        let mut body = Vec::new();
        body.extend_from_slice(&[0x03, 0x03]); // client version TLS 1.2
        body.extend_from_slice(&[0x5a; 32]); // random
        body.push(0x00); // empty session id
        body.extend_from_slice(&[0x00, 0x02]); // cipher_suites length
        body.extend_from_slice(&[0x13, 0x01]); // one cipher suite
        body.push(0x01); // compression methods length
        body.push(0x00); // null compression
        let mut ext_block = Vec::new();
        for (ext_type, data) in extensions {
            ext_block.extend_from_slice(&ext_type.to_be_bytes());
            ext_block.extend_from_slice(&(data.len() as u16).to_be_bytes());
            ext_block.extend_from_slice(data);
        }
        body.extend_from_slice(&(ext_block.len() as u16).to_be_bytes());
        body.extend_from_slice(&ext_block);
        let mut handshake = vec![0x01]; // ClientHello
        handshake.extend_from_slice(&(body.len() as u32).to_be_bytes()[1..4]);
        handshake.extend_from_slice(&body);
        let mut record = vec![0x16, 0x03, 0x01]; // handshake record, TLS 1.2
        record.extend_from_slice(&(handshake.len() as u16).to_be_bytes());
        record.extend_from_slice(&handshake);
        record
    }

    #[test]
    fn sni_valid_record() {
        let name = "auth.ops.sys.local.sentin8.dev";
        let buf = client_hello_record(&[(0x0000, sni_extension(&[name]))]);
        assert_eq!(parse_sni_from_record(&buf).unwrap(), Some(name.to_string()));
    }

    #[test]
    fn sni_after_other_extensions() {
        // SNI must be found even when it is not the first extension.
        let name = "dash.ops.sys.local.sentin8.dev";
        let buf = client_hello_record(&[
            (0x0017, Vec::new()), // extended_master_secret
            (0xff01, vec![0x00]), // renegotiation_info (1 byte payload)
            (0x0000, sni_extension(&[name])),
        ]);
        assert_eq!(parse_sni_from_record(&buf).unwrap(), Some(name.to_string()));
    }

    #[test]
    fn sni_no_server_name_extension() {
        let buf = client_hello_record(&[(0x0017, Vec::new())]);
        assert_eq!(parse_sni_from_record(&buf).unwrap(), None);
    }

    #[test]
    fn sni_empty_extension_list() {
        let buf = client_hello_record(&[]);
        assert_eq!(parse_sni_from_record(&buf).unwrap(), None);
    }

    #[test]
    fn sni_multiple_names_uses_first() {
        let buf = client_hello_record(&[(
            0x0000,
            sni_extension(&[
                "first.ops.sys.local.sentin8.dev",
                "second.ops.sys.local.sentin8.dev",
            ]),
        )]);
        assert_eq!(
            parse_sni_from_record(&buf).unwrap(),
            Some("first.ops.sys.local.sentin8.dev".to_string())
        );
    }

    #[test]
    fn sni_skips_non_host_name_entries() {
        // First entry carries name_type 0x01 (not host_name); the parser
        // must skip it and use the following host_name entry.
        let mut list = vec![0x01, 0x00, 0x05];
        list.extend_from_slice(b"other");
        list.extend_from_slice(&[0x00, 0x00, 0x05]);
        list.extend_from_slice(b"final");
        let mut ext = (list.len() as u16).to_be_bytes().to_vec();
        ext.extend_from_slice(&list);
        let buf = client_hello_record(&[(0x0000, ext)]);
        assert_eq!(
            parse_sni_from_record(&buf).unwrap(),
            Some("final".to_string())
        );
    }

    #[test]
    fn sni_empty_buffer() {
        let err = parse_sni_from_record(&[]).unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::UnexpectedEof);
    }

    #[test]
    fn sni_record_header_too_short() {
        let err = parse_sni_from_record(&[0x16, 0x03]).unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::UnexpectedEof);
    }

    #[test]
    fn sni_handshake_header_too_short() {
        let buf = vec![0x16, 0x03, 0x01, 0x00, 0x10, 0x01, 0x00];
        let err = parse_sni_from_record(&buf).unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::UnexpectedEof);
    }

    #[test]
    fn sni_not_a_client_hello() {
        // Handshake type 0x02 (ServerHello) in the handshake header.
        let buf = vec![0x16, 0x03, 0x01, 0x00, 0x10, 0x02, 0x00, 0x00, 0x0c];
        let err = parse_sni_from_record(&buf).unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::InvalidData);
    }

    #[test]
    fn sni_truncated_body_returns_none() {
        // Record cut before the ClientHello body finishes: unparseable, but
        // the parser bails with Ok(None) rather than an error.
        let full = client_hello_record(&[(0x0000, sni_extension(&["auth.ops.sys.local.sentin8.dev"]))]);
        assert_eq!(parse_sni_from_record(&full[..40]).unwrap(), None);
    }

    #[test]
    fn sni_truncated_host_name_returns_none() {
        // Record cut 17 bytes short - inside the host_name bytes: the length
        // field promises more than the buffer holds → Ok(None).
        let full = client_hello_record(&[(0x0000, sni_extension(&["auth.ops.sys.local.sentin8.dev"]))]);
        assert_eq!(
            parse_sni_from_record(&full[..full.len() - 17]).unwrap(),
            None
        );
    }

    #[test]
    fn sni_bogus_cipher_suites_length_returns_none() {
        // A cipher_suites length that points past the record: parse bails
        // with Ok(None).
        let mut buf =
            client_hello_record(&[(0x0000, sni_extension(&["auth.ops.sys.local.sentin8.dev"]))]);
        // cipher_suites_len sits at offset 5 (record hdr) + 4 (handshake
        // hdr) + 2 (client version) + 32 (random) + 1 (session id len) = 44.
        buf[44] = 0xff;
        buf[45] = 0xff;
        assert_eq!(parse_sni_from_record(&buf).unwrap(), None);
    }
}
