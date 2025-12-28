#![forbid(unsafe_code)]

use anyhow::{anyhow, Context, Result};
use serde::{Deserialize, Serialize};
use serialport::SerialPort;
use std::io::{BufRead, BufReader, Write};
use std::time::Duration;

#[derive(Debug, Serialize)]
struct RpcRequest {
    id: u32,
    method: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    params: Option<serde_json::Value>,
}

#[derive(Debug, Deserialize)]
struct RpcResponse {
    id: u32,
    #[serde(default)]
    result: Option<serde_json::Value>,
    #[serde(default)]
    error: Option<RpcError>,
}

#[derive(Debug, Deserialize)]
struct RpcError {
    code: i32,
    message: String,
}

pub struct HardwareSigner {
    port: Box<dyn SerialPort>,
    reader: BufReader<Box<dyn SerialPort>>,
    request_id: u32,
}

impl HardwareSigner {
    pub fn new(device: &str) -> Result<Self> {
        let port = serialport::new(device, 115200)
            .timeout(Duration::from_secs(30))
            .open()
            .with_context(|| format!("Failed to open serial port: {}", device))?;

        let reader_port = port
            .try_clone()
            .context("Failed to clone serial port for reading")?;
        let reader = BufReader::new(reader_port);

        Ok(Self {
            port,
            reader,
            request_id: 0,
        })
    }

    fn call(
        &mut self,
        method: &str,
        params: Option<serde_json::Value>,
    ) -> Result<serde_json::Value> {
        self.request_id += 1;

        let request = RpcRequest {
            id: self.request_id,
            method: method.to_string(),
            params,
        };

        let request_json = serde_json::to_string(&request)?;
        writeln!(self.port, "{}", request_json)?;
        self.port.flush()?;

        let mut response_line = String::new();
        self.reader.read_line(&mut response_line)?;

        let response: RpcResponse = serde_json::from_str(response_line.trim())
            .context("Failed to parse hardware response")?;

        if response.id != self.request_id {
            return Err(anyhow!(
                "Mismatched response id: expected {} got {}",
                self.request_id,
                response.id
            ));
        }

        if let Some(err) = response.error {
            return Err(anyhow!("Hardware error {}: {}", err.code, err.message));
        }

        response
            .result
            .ok_or_else(|| anyhow!("No result in response"))
    }

    pub fn ping(&mut self) -> Result<String> {
        let result = self.call("ping", None)?;
        let version = result["version"].as_str().unwrap_or("unknown");
        Ok(version.to_string())
    }

    pub fn list_shares(&mut self) -> Result<Vec<String>> {
        let result = self.call("list_shares", None)?;
        let shares = result["shares"]
            .as_array()
            .map(|arr| {
                arr.iter()
                    .filter_map(|v| v.as_str().map(String::from))
                    .collect()
            })
            .unwrap_or_default();
        Ok(shares)
    }

    pub fn import_share(&mut self, group: &str, share_hex: &str) -> Result<()> {
        let params = serde_json::json!({
            "group": group,
            "share": share_hex,
        });
        self.call("import_share", Some(params))?;
        Ok(())
    }

    pub fn delete_share(&mut self, group: &str) -> Result<()> {
        let params = serde_json::json!({
            "group": group,
        });
        self.call("delete_share", Some(params))?;
        Ok(())
    }

    #[allow(dead_code)]
    pub fn get_share_pubkey(&mut self, group: &str) -> Result<(String, u16)> {
        let params = serde_json::json!({
            "group": group,
        });
        let result = self.call("get_share_pubkey", Some(params))?;
        let pubkey = result["pubkey"]
            .as_str()
            .ok_or_else(|| anyhow!("Missing pubkey in response"))?
            .to_string();
        let index_u64 = result["index"]
            .as_u64()
            .ok_or_else(|| anyhow!("Missing index in response"))?;
        let index: u16 = index_u64
            .try_into()
            .map_err(|_| anyhow!("index out of range: {}", index_u64))?;
        Ok((pubkey, index))
    }

    pub fn frost_commit(
        &mut self,
        group: &str,
        session_id: &[u8; 32],
        message: &[u8; 32],
    ) -> Result<(Vec<u8>, u16)> {
        let params = serde_json::json!({
            "group": group,
            "session_id": hex::encode(session_id),
            "message": hex::encode(message),
        });

        let result = self.call("frost_commit", Some(params))?;

        let commitment_hex = result["commitment"]
            .as_str()
            .ok_or_else(|| anyhow!("Missing commitment in response"))?;
        let commitment =
            hex::decode(commitment_hex).context("Invalid commitment hex from hardware")?;

        let index_u64 = result["index"]
            .as_u64()
            .ok_or_else(|| anyhow!("Missing index in response"))?;
        let index: u16 = index_u64
            .try_into()
            .map_err(|_| anyhow!("index out of range: {}", index_u64))?;

        Ok((commitment, index))
    }

    pub fn frost_sign(
        &mut self,
        group: &str,
        session_id: &[u8; 32],
        commitments_hex: &str,
    ) -> Result<(Vec<u8>, u16)> {
        let params = serde_json::json!({
            "group": group,
            "session_id": hex::encode(session_id),
            "commitments": commitments_hex,
        });

        let result = self.call("frost_sign", Some(params))?;

        let sig_share_hex = result["signature_share"]
            .as_str()
            .ok_or_else(|| anyhow!("Missing signature_share in response"))?;
        let sig_share =
            hex::decode(sig_share_hex).context("Invalid signature_share hex from hardware")?;

        let index_u64 = result["index"]
            .as_u64()
            .ok_or_else(|| anyhow!("Missing index in response"))?;
        let index: u16 = index_u64
            .try_into()
            .map_err(|_| anyhow!("index out of range: {}", index_u64))?;

        Ok((sig_share, index))
    }
}

pub fn serialize_share_for_hardware(
    secret: &[u8; 32],
    pubkey_compressed: &[u8; 33],
    group_pubkey_compressed: &[u8; 33],
    index: u16,
    max_participants: u16,
    threshold: u16,
) -> Vec<u8> {
    let mut buf = Vec::with_capacity(104);
    buf.extend_from_slice(secret);
    buf.extend_from_slice(pubkey_compressed);
    buf.extend_from_slice(group_pubkey_compressed);
    buf.extend_from_slice(&index.to_le_bytes());
    buf.extend_from_slice(&max_participants.to_le_bytes());
    buf.extend_from_slice(&threshold.to_le_bytes());
    buf
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_serialize_share_for_hardware() {
        let secret = [1u8; 32];
        let pubkey = [2u8; 33];
        let group_pubkey = [3u8; 33];
        let index = 1u16;
        let max_participants = 3u16;
        let threshold = 2u16;

        let serialized = serialize_share_for_hardware(
            &secret,
            &pubkey,
            &group_pubkey,
            index,
            max_participants,
            threshold,
        );

        assert_eq!(serialized.len(), 104);
        assert_eq!(&serialized[0..32], &secret);
        assert_eq!(&serialized[32..65], &pubkey);
        assert_eq!(&serialized[65..98], &group_pubkey);
        assert_eq!(&serialized[98..100], &1u16.to_le_bytes());
        assert_eq!(&serialized[100..102], &3u16.to_le_bytes());
        assert_eq!(&serialized[102..104], &2u16.to_le_bytes());
    }

    #[test]
    #[ignore]
    fn test_ping_hardware() {
        let mut signer = HardwareSigner::new("/dev/ttyUSB0").unwrap();
        let version = signer.ping().unwrap();
        assert!(!version.is_empty());
    }
}
