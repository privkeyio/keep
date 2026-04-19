// SPDX-FileCopyrightText: © 2026 PrivKey LLC
// SPDX-License-Identifier: MIT

use std::collections::HashMap;

use iced::widget::{button, column, container, row, scrollable, text, text_input, Space};
use iced::{Alignment, Element, Length};
use keep_frost_net::AnnouncedXpub;
use keep_frost_net::PsbtSessionSnapshot;
use keep_frost_net::{
    MAX_PSBT_SIZE, MAX_XPUB_LABEL_LENGTH, MAX_XPUB_LENGTH, PSBT_SESSION_MAX_TIMEOUT_SECS,
    VALID_XPUB_PREFIXES,
};

use crate::screen::shares::ShareEntry;
use crate::theme;

const MAX_DEVICE_URI_LEN: usize = 2048;

fn truncate_to_bytes(s: &str, max_bytes: usize) -> String {
    let mut out = String::with_capacity(s.len().min(max_bytes));
    for c in s.chars() {
        if out.len() + c.len_utf8() > max_bytes {
            break;
        }
        out.push(c);
    }
    out
}

fn parse_psbt_text(input: &str) -> Result<Vec<u8>, String> {
    let trimmed = input.trim();
    if trimmed.is_empty() {
        return Err("PSBT cannot be empty".into());
    }
    let cleaned: String = trimmed.chars().filter(|c| !c.is_whitespace()).collect();

    use base64::{engine::general_purpose, Engine};
    let bytes = if let Ok(b) = general_purpose::STANDARD.decode(cleaned.as_bytes()) {
        b
    } else if let Ok(b) = general_purpose::STANDARD_NO_PAD.decode(cleaned.as_bytes()) {
        b
    } else if let Ok(b) = hex::decode(&cleaned) {
        b
    } else {
        return Err("PSBT must be valid base64 or hex".into());
    };

    if bytes.is_empty() {
        return Err("PSBT cannot be empty".into());
    }
    if bytes.len() > MAX_PSBT_SIZE {
        return Err(format!(
            "PSBT is {} bytes, exceeds maximum {MAX_PSBT_SIZE}",
            bytes.len()
        ));
    }
    if !bytes.starts_with(b"psbt\xff") {
        return Err("Decoded data does not start with PSBT magic bytes".into());
    }
    Ok(bytes)
}

#[derive(Debug, Clone)]
pub struct WalletEntry {
    #[allow(dead_code)]
    pub group_pubkey: [u8; 32],
    pub group_hex: String,
    pub external_descriptor: String,
    pub internal_descriptor: String,
    pub network: String,
    pub created_at: u64,
}

impl WalletEntry {
    pub fn from_descriptor(d: &keep_core::WalletDescriptor) -> Self {
        let group_hex = hex::encode(d.group_pubkey);
        Self {
            group_pubkey: d.group_pubkey,
            group_hex,
            external_descriptor: d.external_descriptor.clone(),
            internal_descriptor: d.internal_descriptor.clone(),
            network: d.network.clone(),
            created_at: d.created_at,
        }
    }

    fn truncated_hex(&self) -> &str {
        self.group_hex.get(..16).unwrap_or(&self.group_hex)
    }
}

#[derive(Debug, Clone)]
pub struct TierConfig {
    pub threshold: String,
    pub timelock_months: String,
}

impl Default for TierConfig {
    fn default() -> Self {
        Self {
            threshold: "2".into(),
            timelock_months: "6".into(),
        }
    }
}

#[derive(Debug, Clone)]
pub enum DescriptorProgress {
    WaitingContributions { received: usize, expected: usize },
    Contributed,
    Finalizing,
    WaitingAcks { received: usize, expected: usize },
    Complete,
    Failed(String),
}

#[derive(Debug, Clone)]
pub enum SetupPhase {
    Configure,
    Coordinating(DescriptorProgress),
}

pub struct AnnounceState {
    pub xpub: String,
    pub fingerprint: String,
    pub label: String,
    pub error: Option<String>,
    pub submitting: bool,
}

pub struct RegisterState {
    pub group_pubkey: [u8; 32],
    pub external_descriptor: String,
    pub default_wallet_name: String,
    pub device_uri: String,
    pub wallet_name: String,
    pub error: Option<String>,
    pub submitting: bool,
}

const MAX_SPEND_FIELD_LEN: usize = 256;
const MAX_PSBT_TEXT_LEN: usize = MAX_PSBT_SIZE * 2 + 16;

#[derive(Debug, Clone)]
pub enum SpendPhase {
    Compose,
    InFlight { received: usize, threshold: u32 },
    Finalized { txid: Option<[u8; 32]> },
    Failed(String),
}

pub struct SpendState {
    pub wallet_idx: usize,
    pub group_pubkey: [u8; 32],
    pub network: String,
    pub tier: String,
    pub psbt_text: String,
    pub fee: String,
    pub threshold: String,
    pub signer_shares: String,
    pub signer_fingerprints: String,
    pub timeout_secs: String,
    pub phase: SpendPhase,
    pub session_id: Option<[u8; 32]>,
    pub error: Option<String>,
}

#[derive(Clone)]
pub enum Message {
    ToggleDetails(usize),
    StartSetup,
    SelectShare(usize),
    NetworkChanged(String),
    ThresholdChanged(String),
    TimelockChanged(String),
    AddTier,
    RemoveTier(usize),
    BeginCoordination,
    CancelSetup,
    StartAnnounce,
    XpubChanged(String),
    FingerprintChanged(String),
    LabelChanged(String),
    CancelAnnounce,
    SubmitAnnounce,
    CopyDescriptor(String),
    StartRegister(usize),
    RegisterDeviceUriChanged(String),
    RegisterNameChanged(String),
    CancelRegister,
    SubmitRegister,
    RejectPsbt([u8; 32]),
    StartSpend(usize),
    SpendTierChanged(String),
    SpendPsbtChanged(String),
    SpendFeeChanged(String),
    SpendThresholdChanged(String),
    SpendSignerSharesChanged(String),
    SpendSignerFingerprintsChanged(String),
    SpendTimeoutChanged(String),
    SubmitSpend,
    CancelSpend,
}

impl std::fmt::Debug for Message {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::ToggleDetails(i) => f.debug_tuple("ToggleDetails").field(i).finish(),
            Self::StartSetup => write!(f, "StartSetup"),
            Self::SelectShare(i) => f.debug_tuple("SelectShare").field(i).finish(),
            Self::NetworkChanged(n) => f.debug_tuple("NetworkChanged").field(n).finish(),
            Self::ThresholdChanged(t) => f.debug_tuple("ThresholdChanged").field(t).finish(),
            Self::TimelockChanged(t) => f.debug_tuple("TimelockChanged").field(t).finish(),
            Self::AddTier => write!(f, "AddTier"),
            Self::RemoveTier(i) => f.debug_tuple("RemoveTier").field(i).finish(),
            Self::BeginCoordination => write!(f, "BeginCoordination"),
            Self::CancelSetup => write!(f, "CancelSetup"),
            Self::StartAnnounce => write!(f, "StartAnnounce"),
            Self::XpubChanged(_) => write!(f, "XpubChanged(<redacted>)"),
            Self::FingerprintChanged(_) => write!(f, "FingerprintChanged(<redacted>)"),
            Self::LabelChanged(l) => f.debug_tuple("LabelChanged").field(l).finish(),
            Self::CancelAnnounce => write!(f, "CancelAnnounce"),
            Self::SubmitAnnounce => write!(f, "SubmitAnnounce"),
            Self::CopyDescriptor(_) => write!(f, "CopyDescriptor(<redacted>)"),
            Self::StartRegister(i) => f.debug_tuple("StartRegister").field(i).finish(),
            Self::RegisterDeviceUriChanged(_) => {
                write!(f, "RegisterDeviceUriChanged(<redacted>)")
            }
            Self::RegisterNameChanged(n) => f.debug_tuple("RegisterNameChanged").field(n).finish(),
            Self::CancelRegister => write!(f, "CancelRegister"),
            Self::SubmitRegister => write!(f, "SubmitRegister"),
            Self::RejectPsbt(id) => f.debug_tuple("RejectPsbt").field(&hex::encode(id)).finish(),
            Self::StartSpend(i) => f.debug_tuple("StartSpend").field(i).finish(),
            Self::SpendTierChanged(v) => f.debug_tuple("SpendTierChanged").field(v).finish(),
            Self::SpendPsbtChanged(_) => write!(f, "SpendPsbtChanged(<redacted>)"),
            Self::SpendFeeChanged(v) => f.debug_tuple("SpendFeeChanged").field(v).finish(),
            Self::SpendThresholdChanged(v) => {
                f.debug_tuple("SpendThresholdChanged").field(v).finish()
            }
            Self::SpendSignerSharesChanged(v) => {
                f.debug_tuple("SpendSignerSharesChanged").field(v).finish()
            }
            Self::SpendSignerFingerprintsChanged(v) => f
                .debug_tuple("SpendSignerFingerprintsChanged")
                .field(v)
                .finish(),
            Self::SpendTimeoutChanged(v) => f.debug_tuple("SpendTimeoutChanged").field(v).finish(),
            Self::SubmitSpend => write!(f, "SubmitSpend"),
            Self::CancelSpend => write!(f, "CancelSpend"),
        }
    }
}

pub enum Event {
    StartSetup,
    BeginCoordination,
    CancelSetup {
        session_id: Option<[u8; 32]>,
    },
    StartAnnounce,
    SubmitAnnounce {
        xpub: String,
        fingerprint: String,
        label: String,
    },
    CopyDescriptor(String),
    SubmitRegister {
        group_pubkey: [u8; 32],
        external_descriptor: String,
        device_uri: String,
        wallet_name: String,
    },
    RejectPsbt([u8; 32]),
    StartSpend {
        wallet_idx: usize,
    },
    SubmitSpend {
        #[allow(dead_code)]
        wallet_idx: usize,
        group_pubkey: [u8; 32],
        #[allow(dead_code)]
        network: String,
        tier: u32,
        psbt_bytes: Vec<u8>,
        fee: u64,
        threshold: u32,
        signer_shares: Vec<u16>,
        signer_fingerprints: Vec<String>,
        timeout_secs: Option<u64>,
    },
    CancelSpend {
        session_id: Option<[u8; 32]>,
    },
}

/// Display entry for a pending PSBT signature request awaiting the user's
/// review. The UI only ever exposes a Reject action, no approval control of
/// any kind is rendered, so there is no way for a misrouted message to trigger
/// an approve-equivalent action from this card.
#[derive(Debug, Clone)]
pub struct PsbtPendingDisplay {
    pub session_id: [u8; 32],
    pub tier_index: u32,
    pub initiator_pubkey: nostr_sdk::PublicKey,
    pub snapshot: Option<PsbtSessionSnapshot>,
}

pub struct State {
    pub descriptors: Vec<WalletEntry>,
    pub expanded: Option<usize>,
    pub setup: Option<SetupState>,
    pub announce: Option<AnnounceState>,
    pub register: Option<RegisterState>,
    pub peer_xpubs: HashMap<u16, Vec<AnnouncedXpub>>,
    pub pending_psbt_signatures: Vec<PsbtPendingDisplay>,
    pub spend: Option<Box<SpendState>>,
}

pub struct SetupState {
    pub shares: Vec<ShareEntry>,
    pub selected_share: Option<usize>,
    pub network: String,
    pub tiers: Vec<TierConfig>,
    pub phase: SetupPhase,
    pub error: Option<String>,
    pub session_id: Option<[u8; 32]>,
}

impl State {
    pub fn new(descriptors: Vec<WalletEntry>) -> Self {
        Self {
            descriptors,
            expanded: None,
            setup: None,
            announce: None,
            register: None,
            peer_xpubs: HashMap::new(),
            pending_psbt_signatures: Vec::new(),
            spend: None,
        }
    }

    pub fn update(&mut self, message: Message) -> Option<Event> {
        match message {
            Message::ToggleDetails(i) => {
                self.expanded = if self.expanded == Some(i) {
                    None
                } else {
                    Some(i)
                };
                None
            }
            Message::StartSetup => Some(Event::StartSetup),
            Message::SelectShare(i) => {
                if let Some(s) = &mut self.setup {
                    s.selected_share = Some(i);
                }
                None
            }
            Message::NetworkChanged(n) => {
                if keep_frost_net::VALID_NETWORKS.contains(&n.as_str()) {
                    if let Some(s) = &mut self.setup {
                        s.network = n;
                    }
                }
                None
            }
            Message::ThresholdChanged(encoded) => {
                self.update_tier_field(&encoded, |tier, val| tier.threshold = val);
                None
            }
            Message::TimelockChanged(encoded) => {
                self.update_tier_field(&encoded, |tier, val| tier.timelock_months = val);
                None
            }
            Message::AddTier => {
                if let Some(s) = &mut self.setup {
                    if s.tiers.len() < 5 {
                        s.tiers.push(TierConfig::default());
                    }
                }
                None
            }
            Message::RemoveTier(i) => {
                if let Some(s) = &mut self.setup {
                    if s.tiers.len() > 1 && i < s.tiers.len() {
                        s.tiers.remove(i);
                    }
                }
                None
            }
            Message::BeginCoordination => Some(Event::BeginCoordination),
            Message::CancelSetup => {
                let session_id = self.setup.as_ref().and_then(|s| s.session_id);
                self.setup = None;
                Some(Event::CancelSetup { session_id })
            }
            Message::StartAnnounce => Some(Event::StartAnnounce),
            Message::XpubChanged(v) => {
                if let Some(a) = &mut self.announce {
                    a.xpub = v.chars().take(MAX_XPUB_LENGTH).collect();
                }
                None
            }
            Message::FingerprintChanged(v) => {
                if let Some(a) = &mut self.announce {
                    a.fingerprint = v
                        .chars()
                        .filter(|c| c.is_ascii_hexdigit())
                        .take(8)
                        .collect();
                }
                None
            }
            Message::LabelChanged(v) => {
                if let Some(a) = &mut self.announce {
                    a.label = v.chars().take(MAX_XPUB_LABEL_LENGTH).collect();
                }
                None
            }
            Message::CancelAnnounce => {
                self.announce = None;
                None
            }
            Message::SubmitAnnounce => {
                let Some(a) = &mut self.announce else {
                    return None;
                };
                let xpub = a.xpub.trim().to_string();
                let fingerprint = a.fingerprint.trim().to_string();
                let label = a.label.trim().to_string();
                if xpub.is_empty() || fingerprint.is_empty() || label.is_empty() {
                    a.error = Some("All fields are required".into());
                    return None;
                }
                a.submitting = true;
                a.error = None;
                Some(Event::SubmitAnnounce {
                    xpub,
                    fingerprint,
                    label,
                })
            }
            Message::CopyDescriptor(desc) => Some(Event::CopyDescriptor(desc)),
            Message::RejectPsbt(id) => Some(Event::RejectPsbt(id)),
            Message::StartRegister(i) => {
                if let Some(entry) = self.descriptors.get(i) {
                    let default_name = hex::encode(&entry.group_pubkey[..4]);
                    self.register = Some(RegisterState {
                        group_pubkey: entry.group_pubkey,
                        external_descriptor: entry.external_descriptor.clone(),
                        default_wallet_name: format!("keep-{default_name}"),
                        device_uri: String::new(),
                        wallet_name: String::new(),
                        error: None,
                        submitting: false,
                    });
                }
                None
            }
            Message::RegisterDeviceUriChanged(v) => {
                if let Some(r) = &mut self.register {
                    r.device_uri = truncate_to_bytes(&v, MAX_DEVICE_URI_LEN);
                }
                None
            }
            Message::RegisterNameChanged(v) => {
                if let Some(r) = &mut self.register {
                    r.wallet_name = truncate_to_bytes(&v, keep_nip46::MAX_WALLET_NAME_LEN);
                }
                None
            }
            Message::CancelRegister => {
                self.register = None;
                None
            }
            Message::StartSpend(i) => Some(Event::StartSpend { wallet_idx: i }),
            Message::SpendTierChanged(v) => {
                if let Some(s) = &mut self.spend {
                    s.tier = v.chars().take(MAX_SPEND_FIELD_LEN).collect();
                }
                None
            }
            Message::SpendPsbtChanged(v) => {
                if let Some(s) = &mut self.spend {
                    s.psbt_text = v.chars().take(MAX_PSBT_TEXT_LEN).collect();
                }
                None
            }
            Message::SpendFeeChanged(v) => {
                if let Some(s) = &mut self.spend {
                    s.fee = v.chars().take(MAX_SPEND_FIELD_LEN).collect();
                }
                None
            }
            Message::SpendThresholdChanged(v) => {
                if let Some(s) = &mut self.spend {
                    s.threshold = v.chars().take(MAX_SPEND_FIELD_LEN).collect();
                }
                None
            }
            Message::SpendSignerSharesChanged(v) => {
                if let Some(s) = &mut self.spend {
                    s.signer_shares = v.chars().take(MAX_SPEND_FIELD_LEN).collect();
                }
                None
            }
            Message::SpendSignerFingerprintsChanged(v) => {
                if let Some(s) = &mut self.spend {
                    s.signer_fingerprints = v.chars().take(MAX_SPEND_FIELD_LEN).collect();
                }
                None
            }
            Message::SpendTimeoutChanged(v) => {
                if let Some(s) = &mut self.spend {
                    s.timeout_secs = v.chars().take(MAX_SPEND_FIELD_LEN).collect();
                }
                None
            }
            Message::SubmitSpend => self.submit_spend(),
            Message::CancelSpend => {
                let session_id = self.spend.as_ref().and_then(|s| s.session_id);
                self.spend = None;
                Some(Event::CancelSpend { session_id })
            }
            Message::SubmitRegister => {
                let Some(r) = &mut self.register else {
                    return None;
                };
                let device_uri = r.device_uri.trim().to_string();
                if device_uri.is_empty() {
                    r.error = Some("Device URI is required".into());
                    return None;
                }
                if !(device_uri.starts_with("bunker://")
                    || device_uri.starts_with("nostrconnect://"))
                {
                    r.error = Some("URI must start with bunker:// or nostrconnect://".into());
                    return None;
                }
                let name_trimmed = r.wallet_name.trim();
                let wallet_name = if name_trimmed.is_empty() {
                    r.default_wallet_name.clone()
                } else {
                    name_trimmed.to_string()
                };
                r.error = None;
                r.submitting = true;
                Some(Event::SubmitRegister {
                    group_pubkey: r.group_pubkey,
                    external_descriptor: r.external_descriptor.clone(),
                    device_uri,
                    wallet_name,
                })
            }
        }
    }

    pub fn begin_spend(&mut self, wallet_idx: usize, entry: &WalletEntry) {
        self.spend = Some(Box::new(SpendState {
            wallet_idx,
            group_pubkey: entry.group_pubkey,
            network: entry.network.clone(),
            tier: "0".into(),
            psbt_text: String::new(),
            fee: String::new(),
            threshold: String::new(),
            signer_shares: String::new(),
            signer_fingerprints: String::new(),
            timeout_secs: String::new(),
            phase: SpendPhase::Compose,
            session_id: None,
            error: None,
        }));
    }

    pub fn spend_started(&mut self, session_id: [u8; 32]) {
        if let Some(s) = &mut self.spend {
            s.session_id = Some(session_id);
            s.error = None;
            s.phase = SpendPhase::InFlight {
                received: 0,
                threshold: s.threshold.parse().unwrap_or(0),
            };
        }
    }

    pub fn spend_progress(&mut self, received: usize, threshold: u32) {
        if let Some(s) = &mut self.spend {
            s.phase = SpendPhase::InFlight {
                received,
                threshold,
            };
        }
    }

    pub fn spend_finalized(&mut self, txid: Option<[u8; 32]>) {
        if let Some(s) = &mut self.spend {
            s.phase = SpendPhase::Finalized { txid };
        }
    }

    pub fn spend_failed(&mut self, reason: String) {
        if let Some(s) = &mut self.spend {
            s.error = Some(reason.clone());
            s.phase = SpendPhase::Failed(reason);
        }
    }

    fn submit_spend(&mut self) -> Option<Event> {
        let Some(s) = &mut self.spend else {
            return None;
        };
        if !matches!(s.phase, SpendPhase::Compose) {
            return None;
        }

        let tier: u32 = match s.tier.trim().parse() {
            Ok(v) => v,
            Err(_) => {
                s.error = Some("Tier must be a non-negative integer".into());
                return None;
            }
        };
        let fee: u64 = match s.fee.trim().parse() {
            Ok(v) => v,
            Err(_) => {
                s.error = Some("Fee must be a non-negative integer (sats)".into());
                return None;
            }
        };
        let threshold: u32 = match s.threshold.trim().parse() {
            Ok(v) if v >= 1 => v,
            _ => {
                s.error = Some("Threshold must be >= 1".into());
                return None;
            }
        };

        let mut signer_shares: Vec<u16> = Vec::new();
        let mut seen_shares = std::collections::HashSet::new();
        for part in s.signer_shares.split(',') {
            let p = part.trim();
            if p.is_empty() {
                continue;
            }
            match p.parse::<u16>() {
                Ok(idx) => {
                    if !seen_shares.insert(idx) {
                        s.error = Some(format!("Duplicate signer share: {idx}"));
                        return None;
                    }
                    signer_shares.push(idx);
                }
                Err(_) => {
                    s.error = Some(format!("Invalid share index: {p}"));
                    return None;
                }
            }
        }

        let mut signer_fingerprints: Vec<String> = Vec::new();
        let mut seen_fps = std::collections::HashSet::new();
        for part in s.signer_fingerprints.split(',') {
            let p = part.trim();
            if p.is_empty() {
                continue;
            }
            if p.len() != 8 || !p.chars().all(|c| c.is_ascii_hexdigit()) {
                s.error = Some(format!("Fingerprint '{p}' must be 8 hex characters"));
                return None;
            }
            let lower = p.to_ascii_lowercase();
            if !seen_fps.insert(lower.clone()) {
                s.error = Some(format!("Duplicate fingerprint: {lower}"));
                return None;
            }
            signer_fingerprints.push(lower);
        }

        if signer_shares.is_empty() && signer_fingerprints.is_empty() {
            s.error = Some("Specify at least one signer share or fingerprint".into());
            return None;
        }
        let total = signer_shares.len() + signer_fingerprints.len();
        if (threshold as usize) > total {
            s.error = Some(format!(
                "Threshold {threshold} exceeds total signers {total}"
            ));
            return None;
        }

        let timeout_secs: Option<u64> = if s.timeout_secs.trim().is_empty() {
            None
        } else {
            match s.timeout_secs.trim().parse::<u64>() {
                Ok(v) if (1..=PSBT_SESSION_MAX_TIMEOUT_SECS).contains(&v) => Some(v),
                _ => {
                    s.error = Some(format!(
                        "Timeout must be 1..={PSBT_SESSION_MAX_TIMEOUT_SECS} seconds"
                    ));
                    return None;
                }
            }
        };

        let psbt_bytes = match parse_psbt_text(&s.psbt_text) {
            Ok(b) => b,
            Err(e) => {
                s.error = Some(e);
                return None;
            }
        };

        s.error = None;

        Some(Event::SubmitSpend {
            wallet_idx: s.wallet_idx,
            group_pubkey: s.group_pubkey,
            network: s.network.clone(),
            tier,
            psbt_bytes,
            fee,
            threshold,
            signer_shares,
            signer_fingerprints,
            timeout_secs,
        })
    }

    pub fn register_submitted(&mut self) {
        self.register = None;
    }

    pub fn register_failed(&mut self, error: String) {
        if let Some(r) = &mut self.register {
            r.error = Some(error);
            r.submitting = false;
        }
    }

    fn update_tier_field(&mut self, encoded: &str, f: impl FnOnce(&mut TierConfig, String)) {
        if let Some(s) = &mut self.setup {
            if let Some((idx_str, val)) = encoded.split_once(':') {
                if let Ok(idx) = idx_str.parse::<usize>() {
                    if let Some(tier) = s.tiers.get_mut(idx) {
                        f(tier, val.to_string());
                    }
                }
            }
        }
    }

    pub fn begin_setup(&mut self, shares: Vec<ShareEntry>) {
        let selected = if shares.len() == 1 { Some(0) } else { None };
        self.setup = Some(SetupState {
            shares,
            selected_share: selected,
            network: "signet".into(),
            tiers: vec![TierConfig::default()],
            phase: SetupPhase::Configure,
            error: None,
            session_id: None,
        });
    }

    pub fn begin_announce(&mut self) {
        self.announce = Some(AnnounceState {
            xpub: String::new(),
            fingerprint: String::new(),
            label: String::new(),
            error: None,
            submitting: false,
        });
    }

    pub fn announce_submitted(&mut self) {
        self.announce = None;
    }

    pub fn announce_failed(&mut self, error: String) {
        if let Some(a) = &mut self.announce {
            a.error = Some(error);
            a.submitting = false;
        }
    }

    pub fn announce_not_connected(&mut self) {
        if let Some(a) = &mut self.announce {
            a.error = Some("Relay not connected".into());
            a.submitting = false;
        }
    }

    pub fn view(&self) -> Element<'_, Message> {
        if let Some(spend) = &self.spend {
            return self.view_spend(spend);
        }

        if let Some(register) = &self.register {
            return self.view_register(register);
        }

        if let Some(announce) = &self.announce {
            return self.view_announce(announce);
        }

        if let Some(setup) = &self.setup {
            return self.view_setup(setup);
        }

        let setup_btn = button(text("Setup Wallet").size(theme::size::BODY))
            .style(theme::primary_button)
            .padding([theme::space::SM, theme::space::LG])
            .on_press(Message::StartSetup);

        let announce_btn = button(text("Announce Recovery Keys").size(theme::size::BODY))
            .style(theme::secondary_button)
            .padding([theme::space::SM, theme::space::LG])
            .on_press(Message::StartAnnounce);

        let title_row = row![
            theme::heading("Wallet Descriptors"),
            Space::new().width(Length::Fill),
            announce_btn,
            setup_btn,
        ]
        .spacing(theme::space::SM)
        .align_y(Alignment::Center);

        let mut content = column![title_row].spacing(theme::space::MD);

        let mut list = column![].spacing(theme::space::SM);

        if self.descriptors.is_empty() {
            list = list.push(
                container(
                    column![
                        text("No wallet descriptors yet")
                            .size(theme::size::BODY)
                            .color(theme::color::TEXT_MUTED),
                        text("Use Setup Wallet to coordinate a descriptor with your peers.")
                            .size(theme::size::SMALL)
                            .color(theme::color::TEXT_DIM),
                    ]
                    .align_x(Alignment::Center)
                    .spacing(theme::space::SM),
                )
                .center_x(Length::Fill)
                .center_y(Length::Fill),
            );
        } else {
            for (i, entry) in self.descriptors.iter().enumerate() {
                list = list.push(self.wallet_card(i, entry));
            }
        }

        if !self.pending_psbt_signatures.is_empty() {
            list = list.push(self.pending_psbt_signatures_section());
        }

        if !self.peer_xpubs.is_empty() {
            list = list.push(self.peer_xpubs_card());
        }

        content = content.push(scrollable(list).height(Length::Fill));

        container(content)
            .padding(theme::space::XL)
            .width(Length::Fill)
            .height(Length::Fill)
            .into()
    }

    fn view_setup<'a>(&'a self, setup: &'a SetupState) -> Element<'a, Message> {
        match &setup.phase {
            SetupPhase::Configure => self.view_configure(setup),
            SetupPhase::Coordinating(progress) => self.view_coordinating(progress),
        }
    }

    fn view_configure<'a>(&self, setup: &'a SetupState) -> Element<'a, Message> {
        let back_btn = button(text("< Back").size(theme::size::BODY))
            .on_press(Message::CancelSetup)
            .style(theme::text_button)
            .padding([theme::space::XS, theme::space::SM]);

        let title_text = text("Setup Wallet")
            .size(theme::size::HEADING)
            .color(theme::color::TEXT);

        let header = row![back_btn, Space::new().width(theme::space::SM), title_text]
            .align_y(Alignment::Center);

        let subtitle = text("Configure the wallet policy and coordinate with connected peers")
            .size(theme::size::SMALL)
            .color(theme::color::TEXT_MUTED);

        let mut share_col = column![theme::label("Share")].spacing(theme::space::XS);
        for (i, share) in setup.shares.iter().enumerate() {
            let label = format!(
                "{} (share {}/{})",
                share.name, share.identifier, share.total_shares
            );
            let style = if setup.selected_share == Some(i) {
                theme::primary_button
            } else {
                theme::secondary_button
            };
            share_col = share_col.push(
                button(text(label).size(theme::size::SMALL))
                    .on_press(Message::SelectShare(i))
                    .style(style)
                    .padding([theme::space::XS, theme::space::SM]),
            );
        }

        let network_label = theme::label("Network");
        let network_options = ["signet", "testnet", "regtest", "bitcoin"];
        let mut network_row = row![].spacing(theme::space::SM);
        for net in &network_options {
            let style = if setup.network == *net {
                theme::primary_button
            } else {
                theme::secondary_button
            };
            network_row = network_row.push(
                button(text(*net).size(theme::size::SMALL))
                    .on_press(Message::NetworkChanged(net.to_string()))
                    .style(style)
                    .padding([theme::space::XS, theme::space::SM]),
            );
        }

        let mut tiers_col = column![theme::label("Recovery Tiers")].spacing(theme::space::SM);

        for (i, tier) in setup.tiers.iter().enumerate() {
            let threshold_input = text_input("2", &tier.threshold)
                .on_input(move |v| Message::ThresholdChanged(format!("{i}:{v}")))
                .padding(theme::space::SM)
                .width(60);

            let timelock_input = text_input("6", &tier.timelock_months)
                .on_input(move |v| Message::TimelockChanged(format!("{i}:{v}")))
                .padding(theme::space::SM)
                .width(60);

            let mut tier_row = row![
                text(format!("Tier {}", i + 1))
                    .size(theme::size::SMALL)
                    .color(theme::color::TEXT),
                text("threshold:")
                    .size(theme::size::SMALL)
                    .color(theme::color::TEXT_MUTED),
                threshold_input,
                text("timelock (months):")
                    .size(theme::size::SMALL)
                    .color(theme::color::TEXT_MUTED),
                timelock_input,
            ]
            .spacing(theme::space::SM)
            .align_y(Alignment::Center);

            if setup.tiers.len() > 1 {
                tier_row = tier_row.push(
                    button(text("Remove").size(theme::size::TINY))
                        .on_press(Message::RemoveTier(i))
                        .style(theme::danger_button)
                        .padding([2.0, theme::space::SM]),
                );
            }

            tiers_col = tiers_col.push(
                container(tier_row)
                    .style(theme::card_style)
                    .padding(theme::space::MD)
                    .width(Length::Fill),
            );
        }

        let add_tier_btn = button(text("+ Add Tier").size(theme::size::SMALL))
            .on_press(Message::AddTier)
            .style(theme::secondary_button)
            .padding([theme::space::XS, theme::space::SM]);

        let max_threshold = setup
            .selected_share
            .and_then(|i| setup.shares.get(i))
            .map(|s| s.total_shares as u32)
            .unwrap_or(0);
        let can_begin = setup.selected_share.is_some()
            && setup.tiers.iter().all(|t| {
                t.threshold
                    .parse::<u32>()
                    .is_ok_and(|v| v >= 1 && v <= max_threshold)
                    && t.timelock_months.parse::<u32>().is_ok_and(|v| v > 0)
            });

        let mut begin_btn = button(text("Begin Coordination").size(theme::size::BODY))
            .style(theme::primary_button)
            .padding(theme::space::MD);
        if can_begin {
            begin_btn = begin_btn.on_press(Message::BeginCoordination);
        }

        let mut content = column![
            header,
            subtitle,
            Space::new().height(theme::space::SM),
            share_col,
            Space::new().height(theme::space::SM),
            network_label,
            network_row,
            Space::new().height(theme::space::SM),
            tiers_col,
            add_tier_btn,
            Space::new().height(theme::space::MD),
            begin_btn,
        ]
        .spacing(theme::space::XS);

        if let Some(err) = &setup.error {
            content = content.push(theme::error_text(err.as_str()));
        }

        container(scrollable(content))
            .padding(theme::space::XL)
            .width(Length::Fill)
            .height(Length::Fill)
            .into()
    }

    fn view_coordinating(&self, progress: &DescriptorProgress) -> Element<'_, Message> {
        let back_btn = button(text("< Cancel").size(theme::size::BODY))
            .on_press(Message::CancelSetup)
            .style(theme::text_button)
            .padding([theme::space::XS, theme::space::SM]);

        let title_text = text("Wallet Coordination")
            .size(theme::size::HEADING)
            .color(theme::color::TEXT);

        let header = row![back_btn, Space::new().width(theme::space::SM), title_text]
            .align_y(Alignment::Center);

        let (status_text, status_color, hint) = match progress {
            DescriptorProgress::WaitingContributions { received, expected } => (
                format!("Waiting for contributions ({received}/{expected})"),
                theme::color::WARNING,
                "Peers need to contribute their extended public keys.",
            ),
            DescriptorProgress::Contributed => (
                "Contribution sent".into(),
                theme::color::PRIMARY,
                "Waiting for the initiator to finalize.",
            ),
            DescriptorProgress::Finalizing => (
                "Finalizing descriptor...".into(),
                theme::color::PRIMARY,
                "Building the final wallet descriptor.",
            ),
            DescriptorProgress::WaitingAcks { received, expected } => (
                format!("Waiting for acknowledgements ({received}/{expected})"),
                theme::color::WARNING,
                "Peers are verifying and acknowledging the descriptor.",
            ),
            DescriptorProgress::Complete => (
                "Descriptor coordination complete".into(),
                theme::color::SUCCESS,
                "The wallet descriptor has been stored.",
            ),
            DescriptorProgress::Failed(err) => (
                format!("Failed: {err}"),
                theme::color::ERROR,
                "You can cancel and try again.",
            ),
        };

        let status_badge = container(
            text(status_text)
                .size(theme::size::BODY)
                .color(status_color),
        )
        .style(theme::card_style)
        .padding(theme::space::LG)
        .width(Length::Fill);

        let content = column![
            header,
            Space::new().height(theme::space::MD),
            status_badge,
            Space::new().height(theme::space::SM),
            text(hint)
                .size(theme::size::SMALL)
                .color(theme::color::TEXT_DIM),
        ]
        .spacing(theme::space::XS);

        container(content)
            .padding(theme::space::XL)
            .width(Length::Fill)
            .height(Length::Fill)
            .into()
    }

    fn wallet_card<'a>(&self, i: usize, entry: &'a WalletEntry) -> Element<'a, Message> {
        let network_badge = container(
            text(&entry.network)
                .size(theme::size::TINY)
                .color(theme::color::PRIMARY),
        )
        .style(theme::badge_style)
        .padding([2.0, theme::space::SM]);

        let hex_text = text(entry.truncated_hex())
            .size(theme::size::SMALL)
            .color(theme::color::TEXT_MUTED);

        let arrow = if self.expanded == Some(i) { "v" } else { ">" };
        let name_btn = button(
            text(format!("{arrow} {}", entry.truncated_hex()))
                .size(theme::size::HEADING)
                .color(theme::color::TEXT),
        )
        .on_press(Message::ToggleDetails(i))
        .style(theme::text_button)
        .padding(0);

        let header_top =
            row![name_btn, Space::new().width(Length::Fill)].align_y(Alignment::Center);

        let header_info = column![
            header_top,
            row![network_badge, hex_text]
                .spacing(theme::space::SM)
                .align_y(Alignment::Center),
        ]
        .spacing(theme::space::XS);

        let mut card_content = column![header_info].spacing(theme::space::SM);

        if self.expanded == Some(i) {
            let ext_row = row![
                text("External:")
                    .size(theme::size::SMALL)
                    .color(theme::color::TEXT_MUTED),
                button(text("Copy").size(theme::size::TINY))
                    .on_press(Message::CopyDescriptor(entry.external_descriptor.clone()))
                    .style(theme::secondary_button)
                    .padding([2.0, theme::space::SM]),
            ]
            .spacing(theme::space::SM)
            .align_y(Alignment::Center);

            let ext_value = text(&entry.external_descriptor)
                .size(theme::size::TINY)
                .color(theme::color::TEXT_DIM);

            let int_row = row![
                text("Internal:")
                    .size(theme::size::SMALL)
                    .color(theme::color::TEXT_MUTED),
                button(text("Copy").size(theme::size::TINY))
                    .on_press(Message::CopyDescriptor(entry.internal_descriptor.clone()))
                    .style(theme::secondary_button)
                    .padding([2.0, theme::space::SM]),
            ]
            .spacing(theme::space::SM)
            .align_y(Alignment::Center);

            let int_value = text(&entry.internal_descriptor)
                .size(theme::size::TINY)
                .color(theme::color::TEXT_DIM);

            let hex_full = text(format!("Group key: {}", entry.group_hex))
                .size(theme::size::TINY)
                .color(theme::color::TEXT_DIM);

            let created = i64::try_from(entry.created_at)
                .map(keep_core::display::format_timestamp)
                .unwrap_or_else(|_| entry.created_at.to_string());
            let created_text = text(format!("Created: {created}"))
                .size(theme::size::SMALL)
                .color(theme::color::TEXT_MUTED);

            let register_btn = button(text("Register on Device").size(theme::size::SMALL))
                .on_press(Message::StartRegister(i))
                .style(theme::primary_button)
                .padding([theme::space::XS, theme::space::MD]);

            let mut spend_btn = button(text("Spend from Recovery Tier").size(theme::size::SMALL))
                .style(theme::secondary_button)
                .padding([theme::space::XS, theme::space::MD]);
            if !entry.external_descriptor.is_empty() {
                spend_btn = spend_btn.on_press(Message::StartSpend(i));
            }

            let actions_row = row![register_btn, spend_btn].spacing(theme::space::SM);

            let details = column![
                ext_row,
                ext_value,
                int_row,
                int_value,
                hex_full,
                created_text,
                Space::new().height(theme::space::SM),
                actions_row,
            ]
            .spacing(theme::space::XS);

            card_content = card_content.push(details);
        }

        container(card_content)
            .style(theme::card_style)
            .padding(theme::space::LG)
            .width(Length::Fill)
            .into()
    }

    fn view_announce<'a>(&self, state: &'a AnnounceState) -> Element<'a, Message> {
        let back_btn = button(text("< Back").size(theme::size::BODY))
            .on_press(Message::CancelAnnounce)
            .style(theme::text_button)
            .padding([theme::space::XS, theme::space::SM]);

        let title_text = text("Announce Recovery Key")
            .size(theme::size::HEADING)
            .color(theme::color::TEXT);

        let header = row![back_btn, Space::new().width(theme::space::SM), title_text]
            .align_y(Alignment::Center);

        let subtitle = text("Share a recovery xpub with your FROST group peers")
            .size(theme::size::SMALL)
            .color(theme::color::TEXT_MUTED);

        let xpub_input = text_input("tpub...", &state.xpub)
            .on_input(Message::XpubChanged)
            .padding(theme::space::SM);

        let fp_input = text_input("8 hex chars", &state.fingerprint)
            .on_input(Message::FingerprintChanged)
            .padding(theme::space::SM)
            .width(120);

        let label_input = text_input("e.g. coldcard-backup", &state.label)
            .on_input(Message::LabelChanged)
            .padding(theme::space::SM);

        let xpub_valid = VALID_XPUB_PREFIXES
            .iter()
            .any(|p| state.xpub.starts_with(p));
        let fp_valid = state.fingerprint.len() == 8
            && state.fingerprint.chars().all(|c| c.is_ascii_hexdigit());
        let can_submit = xpub_valid && fp_valid && !state.submitting;

        let mut submit_btn = button(text("Announce").size(theme::size::BODY))
            .style(theme::primary_button)
            .padding([theme::space::SM, theme::space::LG]);
        if can_submit {
            submit_btn = submit_btn.on_press(Message::SubmitAnnounce);
        }

        let mut content = column![
            header,
            subtitle,
            Space::new().height(theme::space::SM),
            theme::label("Extended Public Key"),
            xpub_input,
            Space::new().height(theme::space::XS),
            theme::label("Fingerprint"),
            fp_input,
            Space::new().height(theme::space::XS),
            theme::label("Label (optional)"),
            label_input,
            Space::new().height(theme::space::MD),
            submit_btn,
        ]
        .spacing(theme::space::XS);

        if let Some(err) = &state.error {
            content = content.push(theme::error_text(err.as_str()));
        }

        container(scrollable(content))
            .padding(theme::space::XL)
            .width(Length::Fill)
            .height(Length::Fill)
            .into()
    }

    fn view_register<'a>(&self, state: &'a RegisterState) -> Element<'a, Message> {
        let back_btn = button(text("< Back").size(theme::size::BODY))
            .on_press_maybe(if state.submitting {
                None
            } else {
                Some(Message::CancelRegister)
            })
            .style(theme::text_button)
            .padding([theme::space::XS, theme::space::SM]);

        let title_text = text("Register on Hardware Signer")
            .size(theme::size::HEADING)
            .color(theme::color::TEXT);

        let header = row![back_btn, Space::new().width(theme::space::SM), title_text]
            .align_y(Alignment::Center);

        let subtitle = text(
            "Send this descriptor to a NIP-46 capable hardware signer so it can verify addresses",
        )
        .size(theme::size::SMALL)
        .color(theme::color::TEXT_MUTED);

        let group_label = text(format!("Group: {}", hex::encode(&state.group_pubkey[..8])))
            .size(theme::size::TINY)
            .color(theme::color::TEXT_DIM);

        let mut uri_input = text_input("bunker://... or nostrconnect://...", &state.device_uri)
            .padding(theme::space::SM)
            .secure(true);
        if !state.submitting {
            uri_input = uri_input.on_input(Message::RegisterDeviceUriChanged);
        }

        let name_placeholder = format!("default: {}", state.default_wallet_name);
        let mut name_input =
            text_input(&name_placeholder, &state.wallet_name).padding(theme::space::SM);
        if !state.submitting {
            name_input = name_input.on_input(Message::RegisterNameChanged);
        }

        let can_submit = !state.submitting && !state.device_uri.trim().is_empty();
        let submit_label = if state.submitting {
            "Registering..."
        } else {
            "Register"
        };
        let mut submit_btn = button(text(submit_label).size(theme::size::BODY))
            .style(theme::primary_button)
            .padding([theme::space::SM, theme::space::LG]);
        if can_submit {
            submit_btn = submit_btn.on_press(Message::SubmitRegister);
        }

        let mut content = column![
            header,
            subtitle,
            group_label,
            Space::new().height(theme::space::SM),
            theme::label("Device URI"),
            uri_input,
            Space::new().height(theme::space::XS),
            theme::label("Wallet name (optional)"),
            name_input,
            Space::new().height(theme::space::MD),
            submit_btn,
        ]
        .spacing(theme::space::XS);

        if state.submitting {
            content = content.push(
                text("Confirm the registration on your hardware signer.")
                    .size(theme::size::SMALL)
                    .color(theme::color::TEXT_MUTED),
            );
        }

        if let Some(err) = &state.error {
            content = content.push(theme::error_text(err.as_str()));
        }

        container(scrollable(content))
            .padding(theme::space::XL)
            .width(Length::Fill)
            .height(Length::Fill)
            .into()
    }

    fn view_spend<'a>(&'a self, spend: &'a SpendState) -> Element<'a, Message> {
        let back_label = match &spend.phase {
            SpendPhase::Compose | SpendPhase::Failed(_) => "< Back",
            SpendPhase::InFlight { .. } => "< Cancel",
            SpendPhase::Finalized { .. } => "< Done",
        };
        let back_btn = button(text(back_label).size(theme::size::BODY))
            .on_press(Message::CancelSpend)
            .style(theme::text_button)
            .padding([theme::space::XS, theme::space::SM]);

        let title_text = text("Spend from Recovery Tier")
            .size(theme::size::HEADING)
            .color(theme::color::TEXT);

        let header = row![back_btn, Space::new().width(theme::space::SM), title_text]
            .align_y(Alignment::Center);

        let group_label = text(format!(
            "Group: {}   network: {}",
            hex::encode(&spend.group_pubkey[..8]),
            spend.network
        ))
        .size(theme::size::TINY)
        .color(theme::color::TEXT_DIM);

        let body: Element<'a, Message> = match &spend.phase {
            SpendPhase::Compose => {
                let tier_input = text_input("0", &spend.tier)
                    .on_input(Message::SpendTierChanged)
                    .padding(theme::space::SM)
                    .width(80);

                let psbt_input = text_input("base64 or hex", &spend.psbt_text)
                    .on_input(Message::SpendPsbtChanged)
                    .padding(theme::space::SM);

                let fee_input = text_input("sats", &spend.fee)
                    .on_input(Message::SpendFeeChanged)
                    .padding(theme::space::SM)
                    .width(140);

                let threshold_input = text_input("e.g. 2", &spend.threshold)
                    .on_input(Message::SpendThresholdChanged)
                    .padding(theme::space::SM)
                    .width(80);

                let shares_input = text_input("comma-separated, e.g. 1,2,3", &spend.signer_shares)
                    .on_input(Message::SpendSignerSharesChanged)
                    .padding(theme::space::SM);

                let fps_input = text_input(
                    "comma-separated 8-hex fingerprints",
                    &spend.signer_fingerprints,
                )
                .on_input(Message::SpendSignerFingerprintsChanged)
                .padding(theme::space::SM);

                let timeout_input = text_input("optional seconds", &spend.timeout_secs)
                    .on_input(Message::SpendTimeoutChanged)
                    .padding(theme::space::SM)
                    .width(160);

                let submit_btn = button(text("Submit Spend").size(theme::size::BODY))
                    .style(theme::primary_button)
                    .padding([theme::space::SM, theme::space::LG])
                    .on_press(Message::SubmitSpend);

                let mut content = column![
                    theme::label("Recovery tier index"),
                    tier_input,
                    Space::new().height(theme::space::XS),
                    theme::label("PSBT (base64 or hex)"),
                    psbt_input,
                    Space::new().height(theme::space::XS),
                    theme::label("Fee (sats, display)"),
                    fee_input,
                    Space::new().height(theme::space::XS),
                    theme::label("Threshold"),
                    threshold_input,
                    Space::new().height(theme::space::XS),
                    theme::label("Signer shares"),
                    shares_input,
                    Space::new().height(theme::space::XS),
                    theme::label("Signer fingerprints"),
                    fps_input,
                    Space::new().height(theme::space::XS),
                    theme::label("Timeout (optional)"),
                    timeout_input,
                    Space::new().height(theme::space::MD),
                    submit_btn,
                ]
                .spacing(theme::space::XS);

                if let Some(err) = &spend.error {
                    content = content.push(theme::error_text(err.as_str()));
                }
                content.into()
            }
            SpendPhase::InFlight {
                received,
                threshold,
            } => {
                let session = spend
                    .session_id
                    .map(|sid| {
                        let s = hex::encode(sid);
                        s.get(..16).unwrap_or(&s).to_string()
                    })
                    .unwrap_or_else(|| "pending".into());
                let status = format!(
                    "Coordinating PSBT (signatures {received}/{threshold})\nSession: {session}"
                );
                container(
                    text(status)
                        .size(theme::size::BODY)
                        .color(theme::color::PRIMARY),
                )
                .style(theme::card_style)
                .padding(theme::space::LG)
                .width(Length::Fill)
                .into()
            }
            SpendPhase::Finalized { txid } => {
                let msg = match txid {
                    Some(t) => format!("PSBT finalized.\nTxid: {}", hex::encode(t)),
                    None => "PSBT finalized (no final tx attached)".into(),
                };
                container(
                    text(msg)
                        .size(theme::size::BODY)
                        .color(theme::color::SUCCESS),
                )
                .style(theme::card_style)
                .padding(theme::space::LG)
                .width(Length::Fill)
                .into()
            }
            SpendPhase::Failed(err) => container(
                text(format!("PSBT spend failed: {err}"))
                    .size(theme::size::BODY)
                    .color(theme::color::ERROR),
            )
            .style(theme::card_style)
            .padding(theme::space::LG)
            .width(Length::Fill)
            .into(),
        };

        let content = column![
            header,
            group_label,
            Space::new().height(theme::space::SM),
            body,
        ]
        .spacing(theme::space::XS);

        container(scrollable(content))
            .padding(theme::space::XL)
            .width(Length::Fill)
            .height(Length::Fill)
            .into()
    }

    fn pending_psbt_signatures_section(&self) -> Element<'_, Message> {
        let mut request_list = column![].spacing(theme::space::SM);

        for entry in &self.pending_psbt_signatures {
            let sid_short = hex::encode(entry.session_id);
            let sid_short = sid_short.get(..12).unwrap_or(&sid_short).to_string();
            let initiator = entry.initiator_pubkey.to_string();
            let initiator_short = initiator.get(..16).unwrap_or(&initiator).to_string();

            let reject_btn = button(text("Reject").size(theme::size::SMALL))
                .on_press(Message::RejectPsbt(entry.session_id))
                .style(theme::danger_button)
                .padding([theme::space::XS, theme::space::MD]);

            let card: Element<'_, Message> = match &entry.snapshot {
                Some(snap) => {
                    let psbt_hash = hex::encode(snap.psbt_hash);
                    let psbt_hash_short = psbt_hash.get(..12).unwrap_or(&psbt_hash).to_string();
                    let fee_text = match snap.fee_sats {
                        Some(f) => format!("{f} sats"),
                        None => "unknown".into(),
                    };

                    let header =
                        row![
                            text(format!("PSBT signature request — session {sid_short}"))
                                .size(theme::size::SMALL)
                                .color(theme::color::TEXT_MUTED),
                        ]
                        .align_y(Alignment::Center);

                    let details = column![
                        text(format!("From: {initiator_short}"))
                            .size(theme::size::TINY)
                            .color(theme::color::TEXT_DIM),
                        text(format!(
                            "Tier {}   outputs: {}   fee: {}",
                            snap.tier_index, snap.output_count, fee_text
                        ))
                        .size(theme::size::TINY)
                        .color(theme::color::TEXT_DIM),
                        text(format!(
                            "Network: {}   threshold: {}/{}   PSBT hash: {}",
                            snap.network,
                            snap.threshold,
                            snap.expected_signers_len,
                            psbt_hash_short
                        ))
                        .size(theme::size::TINY)
                        .color(theme::color::TEXT_DIM),
                    ]
                    .spacing(theme::space::XS);

                    container(
                        column![header, details, row![reject_btn].spacing(theme::space::SM)]
                            .spacing(theme::space::XS),
                    )
                    .style(theme::warning_style)
                    .padding(theme::space::MD)
                    .width(Length::Fill)
                    .into()
                }
                None => container(
                    column![
                        text(format!(
                            "Malformed PSBT from {initiator_short} — Reject only."
                        ))
                        .size(theme::size::SMALL)
                        .color(theme::color::ERROR),
                        text(format!("Session: {sid_short}   tier {}", entry.tier_index))
                            .size(theme::size::TINY)
                            .color(theme::color::TEXT_DIM),
                        row![reject_btn].spacing(theme::space::SM),
                    ]
                    .spacing(theme::space::XS),
                )
                .style(theme::warning_style)
                .padding(theme::space::MD)
                .width(Length::Fill)
                .into(),
            };

            request_list = request_list.push(card);
        }

        let count = self.pending_psbt_signatures.len();
        let label = text(format!("Pending PSBT Signatures ({count})"))
            .size(theme::size::BODY)
            .color(theme::color::TEXT);

        container(column![label, request_list].spacing(theme::space::SM))
            .style(theme::card_style)
            .padding(theme::space::LG)
            .width(Length::Fill)
            .into()
    }

    fn peer_xpubs_card(&self) -> Element<'_, Message> {
        let title = text("Announced Recovery Keys")
            .size(theme::size::HEADING)
            .color(theme::color::TEXT);

        let mut content = column![title].spacing(theme::space::SM);

        let mut indices: Vec<_> = self.peer_xpubs.keys().copied().collect();
        indices.sort();

        for idx in indices {
            let xpubs = &self.peer_xpubs[&idx];
            let share_label = text(format!("Share {idx}"))
                .size(theme::size::BODY)
                .color(theme::color::TEXT);

            let mut share_col = column![share_label].spacing(theme::space::XS);

            for xpub in xpubs {
                let display = if xpub.xpub.chars().count() > 32 {
                    let prefix: String = xpub.xpub.chars().take(32).collect();
                    format!("{prefix}...")
                } else {
                    xpub.xpub.clone()
                };

                let mut xpub_row = row![
                    text(display)
                        .size(theme::size::TINY)
                        .color(theme::color::TEXT_DIM),
                    text(&xpub.fingerprint)
                        .size(theme::size::TINY)
                        .color(theme::color::TEXT_MUTED),
                ]
                .spacing(theme::space::SM);

                if let Some(label) = &xpub.label {
                    xpub_row = xpub_row.push(
                        text(label)
                            .size(theme::size::TINY)
                            .color(theme::color::TEXT_MUTED),
                    );
                }

                share_col = share_col.push(xpub_row);
            }

            content = content.push(share_col);
        }

        container(content)
            .style(theme::card_style)
            .padding(theme::space::LG)
            .width(Length::Fill)
            .into()
    }
}
