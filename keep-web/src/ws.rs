use axum::extract::ws::{Message, WebSocket, WebSocketUpgrade};
use axum::extract::{Query, State};
use axum::http::StatusCode;
use axum::response::IntoResponse;
use serde::Deserialize;
use tokio::sync::broadcast::error::RecvError;

use crate::state::AppState;

#[derive(Deserialize)]
pub struct TicketQuery {
    ticket: Option<String>,
}

pub async fn events(
    ws: WebSocketUpgrade,
    State(state): State<AppState>,
    Query(q): Query<TicketQuery>,
) -> impl IntoResponse {
    match q.ticket {
        Some(ticket) if state.ws_tickets.consume(&ticket) => ws
            .on_upgrade(move |socket| handle(socket, state))
            .into_response(),
        _ => StatusCode::UNAUTHORIZED.into_response(),
    }
}

async fn handle(mut socket: WebSocket, state: AppState) {
    let mut rx = state.events.subscribe();
    loop {
        match rx.recv().await {
            Ok(event) => {
                let json = match serde_json::to_string(&event) {
                    Ok(j) => j,
                    Err(e) => {
                        tracing::debug!(error = %e, "failed to serialize event for WS");
                        continue;
                    }
                };
                if socket.send(Message::Text(json.into())).await.is_err() {
                    break;
                }
            }
            Err(RecvError::Lagged(_)) => continue,
            Err(RecvError::Closed) => break,
        }
    }
}
