//! Explicit service classification, separate from feed hosting and domain ownership.
use serde::Deserialize;
#[derive(Deserialize)]
pub struct Rule {
    pub domain: String,
    pub subdomains: bool,
    pub purpose: String,
    pub source: String,
}
pub fn rules() -> Vec<Rule> {
    serde_json::from_str(include_str!("../assets/microsoft-scope.json"))
        .expect("reviewed scope registry")
}
pub fn classify(host: &str) -> Option<Rule> {
    rules()
        .into_iter()
        .find(|r| host == r.domain || (r.subdomains && host.ends_with(&format!(".{}", r.domain))))
}
pub fn validate(host: &str) -> Result<String, String> {
    let h = crate::cli::hostname(host)?;
    if classify(&h).is_none() {
        return Err("Host is not in the documented Microsoft service classification registry. Use a Microsoft service feed for documented dependencies, or propose a sourced registry entry.".into());
    }
    Ok(h)
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn boundary_and_dependency() {
        assert!(validate("login.microsoftonline.com").is_ok());
        assert!(validate("tenant.sharepoint.com").is_ok());
        assert!(validate("crl3.digicert.com").is_ok());
        for h in [
            "microsoft.com.evil.example",
            "example.com",
            "tenant.sentinelone.net",
        ] {
            assert!(validate(h).is_err());
        }
        assert!(
            crate::edl::validate_url("https://saasedl.paloaltonetworks.com/feeds/github/all/url")
                .is_err()
        );
        assert!(crate::edl::catalog("github").is_empty());
        assert!(
            rules()
                .iter()
                .all(|r| !r.purpose.is_empty()
                    && r.source.starts_with("https://learn.microsoft.com/"))
        );
    }
}
