// SPDX-FileCopyrightText: © 2026 PrivKey LLC
// SPDX-License-Identifier: AGPL-3.0-or-later

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
        for _ in 0..10 {
            response_line.clear();
            self.reader.read_line(&mut response_line)?;
            let trimmed = response_line.trim();
            if trimmed.starts_with('{') && trimmed.contains("\"id\"") {
                break;
            }
        }

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

    pub fn get_share_info(&mut self, group: &str) -> Result<ShareInfo> {
        let params = serde_json::json!({
            "group": group,
        });
        let result = self.call("get_share_info", Some(params))?;
        let pubkey = result["pubkey"]
            .as_str()
            .ok_or_else(|| anyhow!("Missing pubkey in response"))?
            .to_string();
        let index = result["index"]
            .as_u64()
            .ok_or_else(|| anyhow!("Missing index in response"))?
            .try_into()
            .map_err(|_| anyhow!("index out of range"))?;
        let threshold = result["threshold"]
            .as_u64()
            .ok_or_else(|| anyhow!("Missing threshold in response"))?
            .try_into()
            .map_err(|_| anyhow!("threshold out of range"))?;
        let participants = result["participants"]
            .as_u64()
            .ok_or_else(|| anyhow!("Missing participants in response"))?
            .try_into()
            .map_err(|_| anyhow!("participants out of range"))?;
        Ok(ShareInfo {
            pubkey,
            index,
            threshold,
            participants,
        })
    }

    pub fn export_share(&mut self, group: &str, passphrase: &str) -> Result<ExportedShare> {
        let params = serde_json::json!({
            "group": group,
            "passphrase": passphrase,
        });
        let result = self.call("export_share", Some(params))?;
        let version: u8 = result["version"]
            .as_u64()
            .ok_or_else(|| anyhow!("Missing version"))?
            .try_into()
            .map_err(|_| anyhow!("version out of range"))?;
        let group_name = result["group"]
            .as_str()
            .ok_or_else(|| anyhow!("Missing group"))?
            .to_string();
        let share_index: u16 = result["share_index"]
            .as_u64()
            .ok_or_else(|| anyhow!("Missing share_index"))?
            .try_into()
            .map_err(|_| anyhow!("share_index out of range"))?;
        let threshold: u16 = result["threshold"]
            .as_u64()
            .ok_or_else(|| anyhow!("Missing threshold"))?
            .try_into()
            .map_err(|_| anyhow!("threshold out of range"))?;
        let participants: u16 = result["participants"]
            .as_u64()
            .ok_or_else(|| anyhow!("Missing participants"))?
            .try_into()
            .map_err(|_| anyhow!("participants out of range"))?;
        let group_pubkey = result["group_pubkey"]
            .as_str()
            .ok_or_else(|| anyhow!("Missing group_pubkey"))?
            .to_string();
        let encrypted_share = result["encrypted_share"]
            .as_str()
            .ok_or_else(|| anyhow!("Missing encrypted_share"))?
            .to_string();
        let nonce = result["nonce"]
            .as_str()
            .ok_or_else(|| anyhow!("Missing nonce"))?
            .to_string();
        let salt = result["salt"]
            .as_str()
            .ok_or_else(|| anyhow!("Missing salt"))?
            .to_string();
        let checksum = result["checksum"]
            .as_str()
            .ok_or_else(|| anyhow!("Missing checksum"))?
            .to_string();
        Ok(ExportedShare {
            version,
            group: group_name,
            share_index,
            threshold,
            participants,
            group_pubkey,
            encrypted_share,
            nonce,
            salt,
            checksum,
        })
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

    pub fn dkg_init(
        &mut self,
        group: &str,
        threshold: u8,
        participant_count: u8,
        our_index: u8,
    ) -> Result<()> {
        let params = serde_json::json!({
            "group": group,
            "threshold": threshold,
            "participant_count": participant_count,
            "our_index": our_index,
        });
        self.call("dkg_init", Some(params))?;
        Ok(())
    }

    pub fn dkg_round1(&mut self) -> Result<DkgRound1Data> {
        let result = self.call("dkg_round1", None)?;
        let participant_index: u8 = result["participant_index"]
            .as_u64()
            .ok_or_else(|| anyhow!("Missing participant_index"))?
            .try_into()
            .map_err(|_| anyhow!("participant_index out of range"))?;
        let num_coefficients: u8 = result["num_coefficients"]
            .as_u64()
            .ok_or_else(|| anyhow!("Missing num_coefficients"))?
            .try_into()
            .map_err(|_| anyhow!("num_coefficients out of range"))?;
        let coefficient_commitments = result["coefficient_commitments"]
            .as_str()
            .ok_or_else(|| anyhow!("Missing coefficient_commitments"))?
            .to_string();
        let zkp_r = result["zkp_r"]
            .as_str()
            .ok_or_else(|| anyhow!("Missing zkp_r"))?
            .to_string();
        let zkp_z = result["zkp_z"]
            .as_str()
            .ok_or_else(|| anyhow!("Missing zkp_z"))?
            .to_string();

        Ok(DkgRound1Data {
            participant_index,
            num_coefficients,
            coefficient_commitments,
            zkp_r,
            zkp_z,
        })
    }

    pub fn dkg_round1_peer(&mut self, peer_index: u8, dkg_data: &str) -> Result<bool> {
        let params = serde_json::json!({
            "peer_index": peer_index,
            "dkg_data": dkg_data,
        });
        let result = self.call("dkg_round1_peer", Some(params))?;
        let validated = result["validated"].as_bool().unwrap_or(false);
        Ok(validated)
    }

    pub fn dkg_round2(&mut self) -> Result<Vec<DkgShare>> {
        let result = self.call("dkg_round2", None)?;
        let shares_arr = result["shares"]
            .as_array()
            .ok_or_else(|| anyhow!("Missing shares array"))?;

        let mut shares = Vec::new();
        for s in shares_arr {
            let recipient_index: u8 = s["recipient_index"]
                .as_u64()
                .ok_or_else(|| anyhow!("Missing recipient_index"))?
                .try_into()
                .map_err(|_| anyhow!("recipient_index out of range"))?;
            let share = s["share"]
                .as_str()
                .ok_or_else(|| anyhow!("Missing share"))?
                .to_string();
            shares.push(DkgShare {
                recipient_index,
                share,
            });
        }
        Ok(shares)
    }

    pub fn dkg_receive_share(&mut self, peer_index: u8, share: &str) -> Result<()> {
        let params = serde_json::json!({
            "peer_index": peer_index,
            "share": share,
        });
        self.call("dkg_receive_share", Some(params))?;
        Ok(())
    }

    pub fn dkg_finalize(&mut self) -> Result<DkgFinalizeResult> {
        let result = self.call("dkg_finalize", None)?;
        let group_pubkey = result["group_pubkey"]
            .as_str()
            .ok_or_else(|| anyhow!("Missing group_pubkey"))?
            .to_string();
        let our_index: u8 = result["our_index"]
            .as_u64()
            .ok_or_else(|| anyhow!("Missing our_index"))?
            .try_into()
            .map_err(|_| anyhow!("our_index out of range"))?;
        Ok(DkgFinalizeResult {
            group_pubkey,
            our_index,
        })
    }
}

#[derive(Debug, Clone)]
#[allow(dead_code)]
pub struct ShareInfo {
    pub pubkey: String,
    pub index: u16,
    pub threshold: u16,
    pub participants: u16,
}

#[derive(Debug, Clone)]
pub struct DkgRound1Data {
    pub participant_index: u8,
    pub num_coefficients: u8,
    pub coefficient_commitments: String,
    pub zkp_r: String,
    pub zkp_z: String,
}

impl DkgRound1Data {
    pub fn to_json(&self) -> String {
        serde_json::json!({
            "participant_index": self.participant_index,
            "num_coefficients": self.num_coefficients,
            "coefficient_commitments": self.coefficient_commitments,
            "zkp_r": self.zkp_r,
            "zkp_z": self.zkp_z,
        })
        .to_string()
    }
}

#[derive(Debug, Clone)]
pub struct DkgShare {
    pub recipient_index: u8,
    pub share: String,
}

#[derive(Debug, Clone)]
pub struct DkgFinalizeResult {
    pub group_pubkey: String,
    pub our_index: u8,
}

#[derive(Debug, Clone)]
pub struct ExportedShare {
    pub version: u8,
    pub group: String,
    pub share_index: u16,
    pub threshold: u16,
    pub participants: u16,
    pub group_pubkey: String,
    pub encrypted_share: String,
    pub nonce: String,
    pub salt: String,
    pub checksum: String,
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
        let mut signer = HardwareSigner::new("/dev/ttyACM0").unwrap();
        let version = signer.ping().unwrap();
        assert!(!version.is_empty());
    }
}
