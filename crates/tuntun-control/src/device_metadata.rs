use sqlx::PgPool;

fn enrich_metadata(
    hostname: &str,
    agent_version: &str,
    os: &str,
    metadata: serde_json::Value,
) -> serde_json::Value {
    let mut obj = match metadata {
        serde_json::Value::Object(map) => map,
        _ => serde_json::Map::new(),
    };

    obj.insert("hostname".into(), hostname.into());
    obj.insert("agentVersion".into(), agent_version.into());

    let resolved_os = if !os.is_empty() {
        os.to_string()
    } else {
        obj.get("os")
            .and_then(|v| v.as_str())
            .unwrap_or("")
            .to_string()
    };

    if !resolved_os.is_empty() {
        obj.insert("os".into(), resolved_os.into());
    }

    serde_json::Value::Object(obj)
}

pub fn initial_enroll_metadata(
    hostname: &str,
    os: &str,
    agent_version: &str,
    metadata: Option<serde_json::Value>,
) -> serde_json::Value {
    let base = metadata.unwrap_or_else(|| {
        serde_json::json!({
            "reportedAt": chrono::Utc::now().to_rfc3339(),
        })
    });
    enrich_metadata(hostname, agent_version, os, base)
}

pub async fn merge_device_metadata(
    pool: &PgPool,
    endpoint_id: &str,
    hostname: &str,
    agent_version: &str,
    os: &str,
    metadata: serde_json::Value,
) -> anyhow::Result<()> {
    let enriched = enrich_metadata(hostname, agent_version, os, metadata);

    sqlx::query(crate::device_expiry_sql::SLIDE_ON_METADATA)
        .bind(endpoint_id)
        .bind(enriched)
        .execute(pool)
        .await?;

    Ok(())
}
