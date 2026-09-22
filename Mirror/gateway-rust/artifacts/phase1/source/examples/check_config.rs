// Validate configured service origins without opening a database or making requests.
fn main() -> anyhow::Result<()> {
    let config = mirror_gateway::config::Config::from_env()?;
    println!(
        "{}",
        serde_json::json!({
            "django": config.django.as_str(),
            "chat": config.upstream.as_str(),
            "cdn": config.cdn_upstream.as_ref().map(url::Url::as_str),
            "cfbypass": config.cfbypass.as_ref().map(url::Url::as_str),
        })
    );
    Ok(())
}
