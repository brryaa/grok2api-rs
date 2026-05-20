use std::collections::HashMap;
use std::sync::Arc;

use serde::Serialize;
use tokio::task::JoinHandle;

use crate::core::config::get_config;
use crate::services::token::manager::get_token_manager;

#[derive(Debug, Clone, Serialize, Default)]
pub struct TokenRefreshState {
    pub trigger: String,
    pub last_run_at: Option<i64>,
    pub last_success_at: Option<i64>,
    pub checked: i32,
    pub refreshed: i32,
    pub recovered: i32,
    pub expired: i32,
    pub last_error: Option<String>,
}

async fn get_refresh_state() -> Arc<tokio::sync::Mutex<TokenRefreshState>> {
    static REFRESH_STATE: tokio::sync::OnceCell<Arc<tokio::sync::Mutex<TokenRefreshState>>> =
        tokio::sync::OnceCell::const_new();

    REFRESH_STATE
        .get_or_init(|| async { Arc::new(tokio::sync::Mutex::new(TokenRefreshState::default())) })
        .await
        .clone()
}

pub async fn snapshot_refresh_state() -> TokenRefreshState {
    get_refresh_state().await.lock().await.clone()
}

pub async fn refresh_tokens_with_tracking(
    trigger: &str,
    force: bool,
) -> HashMap<&'static str, i32> {
    let state = get_refresh_state().await;
    {
        let mut guard = state.lock().await;
        guard.trigger = trigger.to_string();
        guard.last_run_at = Some(chrono::Utc::now().timestamp_millis());
        guard.last_error = None;
    }

    let mgr = get_token_manager().await;
    let mut mgr = mgr.lock().await;
    let result = if force {
        mgr.force_restore_quotas().await
    } else {
        mgr.refresh_cooling_tokens().await
    };

    {
        let mut guard = state.lock().await;
        guard.last_success_at = Some(chrono::Utc::now().timestamp_millis());
        guard.checked = *result.get("checked").unwrap_or(&0);
        guard.refreshed = *result.get("refreshed").unwrap_or(&0);
        guard.recovered = *result.get("recovered").unwrap_or(&0);
        guard.expired = *result.get("expired").unwrap_or(&0);
        guard.last_error = None;
    }

    result
}

pub struct TokenRefreshScheduler {
    interval_hours: i64,
    handle: Option<JoinHandle<()>>,
    running: bool,
}

impl TokenRefreshScheduler {
    pub fn new(interval_hours: i64) -> Self {
        Self {
            interval_hours,
            handle: None,
            running: false,
        }
    }

    pub fn start(&mut self) {
        if self.running {
            return;
        }
        self.running = true;
        let interval_secs = self.interval_hours.max(1) as u64 * 3600;
        self.handle = Some(tokio::spawn(async move {
            loop {
                let _ = refresh_tokens_with_tracking("scheduler", false).await;
                tokio::time::sleep(std::time::Duration::from_secs(interval_secs)).await;
            }
        }));
    }

    pub fn stop(&mut self) {
        self.running = false;
        if let Some(handle) = self.handle.take() {
            handle.abort();
        }
    }
}

static SCHEDULER: tokio::sync::OnceCell<Arc<tokio::sync::Mutex<TokenRefreshScheduler>>> =
    tokio::sync::OnceCell::const_new();

pub async fn get_scheduler() -> Arc<tokio::sync::Mutex<TokenRefreshScheduler>> {
    let interval: i64 = get_config("token.refresh_interval_hours", 8i64).await;
    let scheduler = SCHEDULER
        .get_or_init(|| async {
            Arc::new(tokio::sync::Mutex::new(TokenRefreshScheduler::new(
                interval,
            )))
        })
        .await
        .clone();
    scheduler
}
