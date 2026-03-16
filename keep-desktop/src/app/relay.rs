use iced::Task;
use keep_core::relay::{normalize_relay_url, validate_relay_url, MAX_RELAYS};

use crate::message::Message;
use crate::screen::{relay, Screen};

use super::{App, ToastKind};

impl App {
    pub(crate) fn handle_relay_message(&mut self, msg: relay::Message) -> Task<Message> {
        let Screen::Relay(s) = &mut self.screen else {
            return Task::none();
        };
        let Some(event) = s.update(msg) else {
            return Task::none();
        };
        match event {
            relay::Event::AddRelay(url) => {
                if self.relay_urls.len() >= MAX_RELAYS {
                    self.set_toast(
                        format!("Maximum of {MAX_RELAYS} relays allowed"),
                        ToastKind::Error,
                    );
                    if let Screen::Relay(s) = &mut self.screen {
                        s.clear_input();
                    }
                    return Task::none();
                }
                if let Err(e) = validate_relay_url(&url) {
                    self.set_toast(format!("Invalid relay URL: {e}"), ToastKind::Error);
                    if let Screen::Relay(s) = &mut self.screen {
                        s.clear_input();
                    }
                    return Task::none();
                }
                let normalized = normalize_relay_url(&url);
                let is_new = !self.relay_urls.contains(&normalized);
                if is_new {
                    self.relay_urls.push(normalized.clone());
                    self.save_relay_urls();
                    if let Screen::Relay(s) = &mut self.screen {
                        s.relay_added(normalized);
                    }
                } else if let Screen::Relay(s) = &mut self.screen {
                    s.clear_input();
                }
                Task::none()
            }
            relay::Event::RemoveRelay(i) => {
                if let Screen::Relay(s) = &mut self.screen {
                    if i < s.relay_urls.len() {
                        s.relay_urls.remove(i);
                        self.relay_urls = s.relay_urls.clone();
                        self.save_relay_urls();
                    }
                }
                Task::none()
            }
            relay::Event::Connect => self.handle_connect_relay(),
            relay::Event::Disconnect => {
                self.handle_disconnect_relay();
                Task::none()
            }
            relay::Event::ApproveSignRequest(id) => {
                self.respond_to_sign_request(&id, true);
                Task::none()
            }
            relay::Event::RejectSignRequest(id) => {
                self.respond_to_sign_request(&id, false);
                Task::none()
            }
            relay::Event::SetPeerPolicy {
                pubkey_hex,
                allow_send,
                allow_receive,
            } => {
                match nostr_sdk::PublicKey::from_hex(&pubkey_hex) {
                    Ok(pubkey) => {
                        if let Some(node) = self.get_frost_node() {
                            use keep_frost_net::PeerPolicy;
                            node.set_peer_policy(
                                PeerPolicy::new(pubkey)
                                    .allow_send(allow_send)
                                    .allow_receive(allow_receive),
                            );
                        }
                        self.save_peer_policy(&pubkey_hex, allow_send, allow_receive);
                    }
                    Err(e) => {
                        tracing::warn!(
                            pubkey_hex, %e, "Failed to parse peer pubkey for policy"
                        );
                    }
                }
                Task::none()
            }
        }
    }
}
