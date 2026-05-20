use crate::core::exceptions::ApiError;
use crate::services::grok::model::ModelService;
use crate::services::token::manager::get_token_manager;
use crate::services::token::models::EffortType;
use crate::services::token::scheduler::refresh_tokens_with_tracking;

pub struct TokenService;

impl TokenService {
    pub async fn get_token_for_model(model: &str) -> Result<String, ApiError> {
        let pool = ModelService::pool_for_model(model);
        let mgr_handle = get_token_manager().await;
        let mut mgr = mgr_handle.lock().await;
        mgr.reload_if_stale().await;
        let mut token = mgr.get_token(&pool);
        if token.is_none() {
            drop(mgr);
            let refreshed = refresh_tokens_with_tracking("on_demand", false).await;
            let mgr = mgr_handle.lock().await;
            if refreshed.get("recovered").copied().unwrap_or(0) > 0 {
                token = mgr.get_token(&pool);
            }
        }
        token.ok_or_else(|| ApiError::rate_limit("No available tokens. Please try again later."))
    }

    pub async fn consume(token: &str, effort: EffortType) -> bool {
        let mgr = get_token_manager().await;
        let mut mgr = mgr.lock().await;
        mgr.consume(token, effort).await
    }
}
