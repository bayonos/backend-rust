use std::sync::Arc;

use backend_rust::auth::AuthService;
use backend_rust::db::Database;
use backend_rust::telegram::TelegramNotifier;
use backend_rust::{config, db, http};

#[tokio::main]
async fn main() {
    if let Err(error) = run().await {
        eprintln!("Fatal error: {error}");
        std::process::exit(1);
    }
}

async fn run() -> Result<(), String> {
    let env = config::environ();
    let cfg = config::load_config(&env, ".env");
    if cfg.jwt_secret_is_ephemeral {
        eprintln!("[WARN] JWT_SECRET is not set; generated an ephemeral secret for this process.");
    }

    let db = db::connect(&cfg).await?;
    db.init_schema().await?;
    let description = if cfg.db_driver == "sqlite" {
        format!("sqlite:{}", cfg.db_path)
    } else {
        format!(
            "mysql://{}@{}:{}/{}",
            cfg.mysql_user, cfg.mysql_host, cfg.mysql_port, cfg.mysql_database
        )
    };

    let mut service = AuthService::new(Arc::new(db), cfg.clone());
    if !cfg.telegram_bot_token.is_empty() && !cfg.telegram_chat_id.is_empty() {
        service = service.with_telegram(TelegramNotifier::new(
            cfg.telegram_bot_token.clone(),
            cfg.telegram_chat_id.clone(),
        ));
    }
    let app = http::router(service);
    let listener = tokio::net::TcpListener::bind(format!("{}:{}", cfg.host, cfg.port))
        .await
        .map_err(|err| err.to_string())?;
    println!(
        "Auth server listening on http://{}:{} (db={}, runtime=rust)",
        cfg.host, cfg.port, description
    );

    axum::serve(
        listener,
        app.into_make_service_with_connect_info::<std::net::SocketAddr>(),
    )
    .with_graceful_shutdown(shutdown_signal())
    .await
    .map_err(|err| err.to_string())
}

async fn shutdown_signal() {
    #[cfg(unix)]
    {
        let mut terminate =
            tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())
                .expect("failed to install SIGTERM handler");
        tokio::select! {
            _ = tokio::signal::ctrl_c() => {},
            _ = terminate.recv() => {},
        }
    }
    #[cfg(not(unix))]
    {
        let _ = tokio::signal::ctrl_c().await;
    }
}
