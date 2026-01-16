// SPDX-FileCopyrightText: © 2026 PrivKey LLC
// SPDX-License-Identifier: AGPL-3.0-or-later

#![forbid(unsafe_code)]

use crate::aws_credentials::AwsCredentials;
use crate::error::{EnclaveError, Result};
use base64::{engine::general_purpose::STANDARD, Engine};
use std::process::Command;

const KMS_PROXY_PORT: &str = "8000";
const KMSTOOL_PATH: &str = "/app/kmstool_enclave_cli";

pub struct KmsTool {
    credentials: AwsCredentials,
}

impl KmsTool {
    pub fn new(credentials: AwsCredentials) -> Self {
        Self { credentials }
    }

    pub fn decrypt(&self, ciphertext_b64: &str) -> Result<Vec<u8>> {
        let output = Command::new(KMSTOOL_PATH)
            .arg("decrypt")
            .arg("--region")
            .arg(&self.credentials.region)
            .arg("--proxy-port")
            .arg(KMS_PROXY_PORT)
            .arg("--ciphertext")
            .arg(ciphertext_b64)
            .env("AWS_ACCESS_KEY_ID", &self.credentials.access_key_id)
            .env("AWS_SECRET_ACCESS_KEY", &self.credentials.secret_access_key)
            .env("AWS_SESSION_TOKEN", &self.credentials.token)
            .output()
            .map_err(|e| EnclaveError::Kms(format!("Failed to execute kmstool: {}", e)))?;

        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr);
            return Err(EnclaveError::Kms(format!("KMS decrypt failed: {}", stderr)));
        }

        let output_str = String::from_utf8(output.stdout)
            .map_err(|e| EnclaveError::Kms(format!("Invalid UTF-8: {}", e)))?;

        let plaintext_b64 = output_str
            .strip_prefix("PLAINTEXT: ")
            .ok_or_else(|| EnclaveError::Kms("Failed to parse plaintext".into()))?
            .trim();

        STANDARD
            .decode(plaintext_b64)
            .map_err(|e| EnclaveError::Kms(format!("Base64 decode failed: {}", e)))
    }

    pub fn generate_data_key(&self, key_id: &str) -> Result<(Vec<u8>, Vec<u8>)> {
        let output = Command::new(KMSTOOL_PATH)
            .arg("genkey")
            .arg("--region")
            .arg(&self.credentials.region)
            .arg("--proxy-port")
            .arg(KMS_PROXY_PORT)
            .arg("--key-id")
            .arg(key_id)
            .arg("--key-spec")
            .arg("AES-256")
            .env("AWS_ACCESS_KEY_ID", &self.credentials.access_key_id)
            .env("AWS_SECRET_ACCESS_KEY", &self.credentials.secret_access_key)
            .env("AWS_SESSION_TOKEN", &self.credentials.token)
            .output()
            .map_err(|e| EnclaveError::Kms(format!("Failed to execute kmstool: {}", e)))?;

        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr);
            return Err(EnclaveError::Kms(format!("KMS genkey failed: {}", stderr)));
        }

        let output_str = String::from_utf8(output.stdout)
            .map_err(|e| EnclaveError::Kms(format!("Invalid UTF-8: {}", e)))?;

        let lines: Vec<&str> = output_str.lines().collect();
        if lines.len() < 2 {
            return Err(EnclaveError::Kms("Invalid genkey output".into()));
        }

        let encrypted_b64 = lines[0]
            .split(": ")
            .nth(1)
            .ok_or_else(|| EnclaveError::Kms("Failed to parse encrypted key".into()))?;

        let plaintext_b64 = lines[1]
            .split(": ")
            .nth(1)
            .ok_or_else(|| EnclaveError::Kms("Failed to parse plaintext key".into()))?;

        let encrypted = STANDARD
            .decode(encrypted_b64)
            .map_err(|e| EnclaveError::Kms(format!("Base64 decode failed: {}", e)))?;

        let plaintext = STANDARD
            .decode(plaintext_b64)
            .map_err(|e| EnclaveError::Kms(format!("Base64 decode failed: {}", e)))?;

        Ok((encrypted, plaintext))
    }

    pub fn generate_random(&self, length: usize) -> Result<Vec<u8>> {
        let output = Command::new(KMSTOOL_PATH)
            .arg("genrandom")
            .arg("--region")
            .arg(&self.credentials.region)
            .arg("--proxy-port")
            .arg(KMS_PROXY_PORT)
            .arg("--length")
            .arg(length.to_string())
            .env("AWS_ACCESS_KEY_ID", &self.credentials.access_key_id)
            .env("AWS_SECRET_ACCESS_KEY", &self.credentials.secret_access_key)
            .env("AWS_SESSION_TOKEN", &self.credentials.token)
            .output()
            .map_err(|e| EnclaveError::Kms(format!("Failed to execute kmstool: {}", e)))?;

        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr);
            return Err(EnclaveError::Kms(format!(
                "KMS genrandom failed: {}",
                stderr
            )));
        }

        let output_str = String::from_utf8(output.stdout)
            .map_err(|e| EnclaveError::Kms(format!("Invalid UTF-8: {}", e)))?;

        let plaintext_b64 = output_str
            .strip_prefix("PLAINTEXT: ")
            .ok_or_else(|| EnclaveError::Kms("Failed to parse plaintext".into()))?
            .trim();

        STANDARD
            .decode(plaintext_b64)
            .map_err(|e| EnclaveError::Kms(format!("Base64 decode failed: {}", e)))
    }
}
