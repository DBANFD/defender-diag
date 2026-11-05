use anyhow::{Result, ensure};
use serde_json::Value;
use std::path::Path;
pub fn parse(bytes: &[u8]) -> Result<Value> {
    let v: Value = serde_json::from_slice(bytes)?;
    ensure!(
        v["schema_version"] == 1 && v["store"] == "ActiveStore" && v["rules"].is_array(),
        "Not a firewall ActiveStore schema 1 snapshot"
    );
    Ok(v)
}
pub fn filter(
    v: &Value,
    search: &str,
    direction: Option<&str>,
    action: Option<&str>,
) -> Vec<Value> {
    v["rules"]
        .as_array()
        .into_iter()
        .flatten()
        .filter(|r| {
            r.to_string()
                .to_lowercase()
                .contains(&search.to_lowercase())
                && direction.is_none_or(|d| {
                    r["direction"]
                        .as_str()
                        .is_some_and(|s| s.eq_ignore_ascii_case(d))
                })
                && action.is_none_or(|a| {
                    r["action"]
                        .as_str()
                        .is_some_and(|s| s.eq_ignore_ascii_case(a))
                })
        })
        .cloned()
        .collect()
}
pub fn export(v: &Value, json: Option<&Path>, csv: Option<&Path>) -> Result<()> {
    if let Some(path) = json {
        crate::collection::write_new(path, &serde_json::to_vec_pretty(v)?)?;
    }
    if let Some(path) = csv {
        let f = std::fs::OpenOptions::new()
            .create_new(true)
            .write(true)
            .open(path)?;
        let mut w = csv::Writer::from_writer(f);
        let fields = [
            "name",
            "displayName",
            "direction",
            "action",
            "enabled",
            "profiles",
            "source",
            "sourceType",
            "filters",
        ];
        w.write_record(fields)?;
        for r in v["rules"].as_array().into_iter().flatten() {
            w.write_record(fields.iter().map(|f| {
                let s = r[*f]
                    .as_str()
                    .map(str::to_string)
                    .unwrap_or_else(|| r[*f].to_string());
                if s.starts_with(['=', '+', '-', '@', '\t', '\r']) {
                    format!("'{s}")
                } else {
                    s
                }
            }))?;
        }
        w.flush()?;
    }
    Ok(())
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn unknown_source_and_filters() {
        let v=parse(br#"{"schema_version":1,"store":"ActiveStore","rules":[{"name":"fixture","direction":"Outbound","action":"Block","source":null,"filters":{"ports":[{"RemotePort":"443"}]}}]}"#).unwrap();
        let r = filter(&v, "443", Some("outbound"), Some("block"));
        assert_eq!(r.len(), 1);
        assert!(r[0]["source"].is_null());
        assert!(parse(br#"{"store":"PersistentStore","rules":[]}"#).is_err());
    }
}
