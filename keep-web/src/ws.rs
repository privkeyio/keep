use axum::extract::ws::{Message, WebSocket, WebSocketUpgrade};
use axum::extract::State;
use axum::response::IntoResponse;
use tokio::sync::broadcast::error::RecvError;

use crate::state::AppState;

pub async fn events(ws: WebSocketUpgrade, State(state): State<AppState>) -> impl IntoResponse {
    ws.on_upgrade(move |socket| handle(socket, state))
}

async fn handle(mut socket: WebSocket, state: AppState) {
    let mut rx = state.events.subscribe();
    loop {
        match rx.recv().await {
            Ok(event) => {
                let Ok(json) = serde_json::to_string(&event) else {
                    continue;
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
