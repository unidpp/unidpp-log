//! Entrypoint: environment-driven configuration, then serve forever.

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let config = unidpp_log::Config::from_env()?;
    unidpp_log::run(config).await
}
