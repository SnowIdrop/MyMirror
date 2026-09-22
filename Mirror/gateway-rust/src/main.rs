// Author: MingTea.
use anyhow::{Context, Result};
use mirror_gateway::{config::Config, server, storage::Database};

#[tokio::main]
async fn main() {
    if let Err(error) = run().await {
        eprintln!("{error:#}");
        std::process::exit(1);
    }
}

async fn run() -> Result<()> {
    let args: Vec<String> = std::env::args().collect();
    if args.get(1).map(String::as_str) == Some("migrate") {
        anyhow::ensure!(
            args.len() == 4,
            "用法: mirror-gateway migrate SOURCE_COPY NEW_DATABASE"
        );
        Database::migrate(
            std::path::Path::new(&args[2]),
            std::path::Path::new(&args[3]),
            &std::env::var("SOURCE_CREDENTIAL_ENCRYPTION_KEY").context("源密钥未配置")?,
            &std::env::var("CREDENTIAL_ENCRYPTION_KEY").context("新密钥未配置")?,
        )?;
        println!("迁移成功；源库保持不变，旧会话已失效");
        return Ok(());
    }
    let config = Config::from_env()?;
    tracing_subscriber::fmt()
        .with_env_filter(tracing_subscriber::EnvFilter::from_default_env())
        .init();
    let address = format!("{}:{}", config.host, config.port);
    let router = server::router(config).await?;
    let listener = tokio::net::TcpListener::bind(&address).await?;
    println!("gateway listening on http://{address} (offline candidate; release gate incomplete)");
    axum::serve(
        listener,
        router.into_make_service_with_connect_info::<std::net::SocketAddr>(),
    )
    .with_graceful_shutdown(async {
        let _ = tokio::signal::ctrl_c().await;
    })
    .await?;
    Ok(())
}
