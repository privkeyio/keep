// SPDX-FileCopyrightText: © 2026 PrivKey LLC
// SPDX-License-Identifier: AGPL-3.0-or-later

#![forbid(unsafe_code)]

use crate::error::{EnclaveError, Result};
use serde::{Deserialize, Serialize};
use std::io::{Read, Write};
use std::time::Duration;
use vsock::{VsockAddr, VsockStream};

const PARENT_CID: u32 = 3;
const CREDENTIALS_PORT: u32 = 8003;
const READ_TIMEOUT_SECS: u64 = 30;
const MAX_RESPONSE_SIZE: usize = 64 * 1024;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AwsCredentials {
    #[serde(rename = "AccessKeyId")]
    pub access_key_id: String,
    #[serde(rename = "SecretAccessKey")]
    pub secret_access_key: String,
    #[serde(rename = "Token")]
    pub token: String,
    #[serde(rename = "Region")]
    pub region: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct CredentialRequest {
    request_type: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct ParentResponse {
    response_type: String,
    response_value: serde_json::Value,
}

pub fn fetch_credentials() -> Result<AwsCredentials> {
    let sock_addr = VsockAddr::new(PARENT_CID, CREDENTIALS_PORT);
    let mut stream = VsockStream::connect(&sock_addr)
        .map_err(|e| EnclaveError::Vsock(format!("Failed to connect to parent: {}", e)))?;

    stream
        .set_read_timeout(Some(Duration::from_secs(READ_TIMEOUT_SECS)))
        .map_err(|e| EnclaveError::Vsock(format!("Failed to set timeout: {}", e)))?;

    let request = CredentialRequest {
        request_type: "credentials".to_string(),
    };
    let request_json = serde_json::to_string(&request)
        .map_err(|e| EnclaveError::Kms(format!("Failed to serialize request: {}", e)))?;

    stream
        .write_all(request_json.as_bytes())
        .map_err(|e| EnclaveError::Vsock(format!("Failed to write request: {}", e)))?;

    let mut response = Vec::with_capacity(4096);
    let mut buf = [0u8; 4096];
    loop {
        match stream.read(&mut buf) {
            Ok(0) => break,
            Ok(n) => {
                response.extend_from_slice(&buf[..n]);
                if response.len() > MAX_RESPONSE_SIZE {
                    return Err(EnclaveError::Vsock("Response too large".into()));
                }
            }
            Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => break,
            Err(e) if e.kind() == std::io::ErrorKind::TimedOut => break,
            Err(e) => {
                return Err(EnclaveError::Vsock(format!("Failed to read response: {}", e)));
            }
        }
    }

    let response_str = String::from_utf8(response)
        .map_err(|e| EnclaveError::Kms(format!("Invalid UTF-8 response: {}", e)))?;

    let parent_response: ParentResponse = serde_json::from_str(&response_str)
        .map_err(|e| EnclaveError::Kms(format!("Failed to parse response: {}", e)))?;

    if parent_response.response_type != "credentials" {
        return Err(EnclaveError::Kms("Invalid response type".into()));
    }

    serde_json::from_value(parent_response.response_value)
        .map_err(|e| EnclaveError::Kms(format!("Failed to parse credentials: {}", e)))
}
