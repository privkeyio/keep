use std::path::{Path, PathBuf};

use serde::{Deserialize, Deserializer};

use keep_core::error::{KeepError, Result};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Argon2Profile {
    Testing,
    #[default]
    Default,
    High,
}

impl std::fmt::Display for Argon2Profile {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let s = match self {
            Self::Testing => "testing",
            Self::Default => "default",
            Self::High => "high",
        };
        f.write_str(s)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum LogLevel {
    Error,
    Warn,
    #[default]
    Info,
    Debug,
    Trace,
}

impl std::fmt::Display for LogLevel {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let s = match self {
            Self::Error => "error",
            Self::Warn => "warn",
            Self::Info => "info",
            Self::Debug => "debug",
            Self::Trace => "trace",
        };
        f.write_str(s)
    }
}

fn deserialize_path<'de, D>(deserializer: D) -> std::result::Result<Option<PathBuf>, D::Error>
where
    D: Deserializer<'de>,
{
    Option::<String>::deserialize(deserializer)
        .map(|opt| opt.map(|s| PathBuf::from(shellexpand::tilde(&s).as_ref())))
}

fn deserialize_relays<'de, D>(deserializer: D) -> std::result::Result<Vec<String>, D::Error>
where
    D: Deserializer<'de>,
{
    let relays: Vec<String> = Vec::deserialize(deserializer)?;
    for relay in &relays {
        if !relay.starts_with("wss://") && !relay.starts_with("ws://") {
            return Err(serde::de::Error::custom(format!(
                "Invalid relay URL: '{}'. Must start with wss:// or ws://",
                relay
            )));
        }
    }
    Ok(relays)
}

fn deserialize_timeout<'de, D>(deserializer: D) -> std::result::Result<Option<u64>, D::Error>
where
    D: Deserializer<'de>,
{
    let opt = Option::<u64>::deserialize(deserializer)?;
    if opt == Some(0) {
        return Err(serde::de::Error::custom("timeout must be greater than 0"));
    }
    Ok(opt)
}

#[derive(Debug, Clone, Default, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Config {
    #[serde(default, deserialize_with = "deserialize_path")]
    pub vault_path: Option<PathBuf>,
    #[serde(default)]
    pub argon2_profile: Argon2Profile,
    #[serde(default)]
    pub log_level: LogLevel,
    #[serde(default, deserialize_with = "deserialize_relays")]
    pub relays: Vec<String>,
    #[serde(default, deserialize_with = "deserialize_timeout")]
    pub timeout: Option<u64>,
}

impl Config {
    pub fn load() -> Result<Self> {
        let path = Self::default_path()?;
        if path.exists() {
            Self::from_file(&path)
        } else {
            Ok(Self::default())
        }
    }

    pub fn from_file(path: &Path) -> Result<Self> {
        const MAX_CONFIG_SIZE: u64 = 1024 * 1024; // 1 MB
        let metadata = std::fs::metadata(path).map_err(|e| {
            KeepError::Other(format!(
                "Failed to read config file {}: {}",
                path.display(),
                e
            ))
        })?;
        if metadata.len() > MAX_CONFIG_SIZE {
            return Err(KeepError::Other("Config file too large".into()));
        }
        let content = std::fs::read_to_string(path).map_err(|e| {
            KeepError::Other(format!(
                "Failed to read config file {}: {}",
                path.display(),
                e
            ))
        })?;
        Self::parse(&content)
    }

    pub fn parse(content: &str) -> Result<Self> {
        toml::from_str(content).map_err(|e| KeepError::Other(format!("Invalid config: {}", e)))
    }

    pub fn default_path() -> Result<PathBuf> {
        dirs::config_dir()
            .map(|p| p.join("keep").join("config.toml"))
            .ok_or(KeepError::HomeNotFound)
    }

    pub fn vault_path(&self) -> Result<PathBuf> {
        match &self.vault_path {
            Some(p) => Ok(p.clone()),
            None => keep_core::default_keep_path(),
        }
    }

    pub fn default_relay(&self) -> &str {
        self.relays
            .first()
            .map(|s| s.as_str())
            .unwrap_or("wss://nos.lol")
    }

    pub fn timeout_secs(&self) -> u64 {
        self.timeout.unwrap_or(30)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_full_config() {
        let content = r#"
vault_path = "~/.keep"
argon2_profile = "high"
log_level = "debug"
relays = ["wss://relay.damus.io", "wss://nos.lol"]
timeout = 60
"#;
        let config = Config::parse(content).unwrap();
        assert!(config.vault_path.is_some());
        assert_eq!(config.argon2_profile, Argon2Profile::High);
        assert_eq!(config.log_level, LogLevel::Debug);
        assert_eq!(config.relays.len(), 2);
        assert_eq!(config.timeout, Some(60));
    }

    #[test]
    fn test_parse_empty_config() {
        let config = Config::parse("").unwrap();
        assert_eq!(config.argon2_profile, Argon2Profile::Default);
        assert_eq!(config.log_level, LogLevel::Info);
        assert!(config.relays.is_empty());
    }

    #[test]
    fn test_parse_partial_config() {
        let content = r#"
argon2_profile = "testing"
"#;
        let config = Config::parse(content).unwrap();
        assert_eq!(config.argon2_profile, Argon2Profile::Testing);
        assert!(config.vault_path.is_none());
    }

    #[test]
    fn test_invalid_relay() {
        let content = r#"
relays = ["https://invalid.com"]
"#;
        let result = Config::parse(content);
        assert!(result.is_err());
    }

    #[test]
    fn test_invalid_argon2_profile() {
        let content = r#"
argon2_profile = "extreme"
"#;
        let result = Config::parse(content);
        assert!(result.is_err());
    }

    #[test]
    fn test_unknown_field_rejected() {
        let content = r#"
unknown_field = "value"
"#;
        let result = Config::parse(content);
        assert!(result.is_err());
    }

    #[test]
    fn test_zero_timeout_rejected() {
        let content = r#"
timeout = 0
"#;
        let result = Config::parse(content);
        assert!(result.is_err());
    }

    #[test]
    fn test_tilde_expansion() {
        let content = r#"
vault_path = "~/custom/keep"
"#;
        let config = Config::parse(content).unwrap();
        let path = config.vault_path.unwrap();
        assert!(!path.to_string_lossy().contains('~'));
    }
}
