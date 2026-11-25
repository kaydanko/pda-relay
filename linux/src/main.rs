use pda_relay::{
    app,
    config::Config,
    v2_config::{start_v2, test_faults_enabled, V2Config},
    AppState,
};
use std::{error::Error, net::SocketAddr, sync::Arc};
use tokio::net::TcpListener;
use tracing::info;
use tracing_subscriber::EnvFilter;

#[tokio::main]
async fn main() -> Result<(), Box<dyn Error>> {
    tracing_subscriber::fmt()
        .with_env_filter(
            EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("pda_relay=info")),
        )
        .with_target(false)
        .init();

    let config = Config::from_env()?;
    // v2 is opt-in and fully validated before the socket is bound.
    let v2 = V2Config::from_env(config.listen)?;
    let listener = TcpListener::bind(config.listen).await?;
    let local_addr = listener.local_addr()?;
    let state = Arc::new(AppState::new(config));
    let mut router = app(state);
    if let Some(v2) = &v2 {
        router = router.merge(start_v2(v2)?.0);
    }
    println!("PDA_RELAY_LISTENING={local_addr}");
    if v2.is_some() {
        println!("PDA_RELAY_V2=enabled");
    }
    if v2.as_ref().is_some_and(|v2| v2.trust_proxy) {
        println!("PDA_RELAY_V2_TRUST_PROXY=enabled");
    }
    if v2.as_ref().is_some_and(test_faults_enabled) {
        println!("PDA_RELAY_V2_TEST_FAULTS=enabled");
    }
    info!(%local_addr, v2 = v2.is_some(), "relay listening");

    // Connect info feeds only the v2 per-address availability limits.
    axum::serve(
        listener,
        router.into_make_service_with_connect_info::<SocketAddr>(),
    )
    .with_graceful_shutdown(shutdown_signal())
    .await?;
    Ok(())
}

async fn shutdown_signal() {
    if let Err(error) = tokio::signal::ctrl_c().await {
        tracing::warn!(%error, "failed to install shutdown signal handler");
    }
}
