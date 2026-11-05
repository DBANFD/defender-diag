//! Human-readable feed scope. Labels describe a feed, not tenant requirements.
pub fn label(url: &str) -> String {
    url.split("/feeds/")
        .nth(1)
        .unwrap_or(url)
        .trim_end_matches("/url")
        .split('/')
        .map(word)
        .collect::<Vec<_>>()
        .join(" / ")
}
fn word(s: &str) -> String {
    let name = match s {
        "msdefender" => "Microsoft Defender",
        "m365" => "Microsoft 365",
        "msintune" => "Microsoft Intune",
        "all" => "All scopes",
        "any" => "All service categories",
        "ww" | "worldwide" => "Worldwide / shared",
        "eu" => "EU (Europe)",
        "us" => "US (United States)",
        "uk" => "UK (United Kingdom)",
        "au" => "AU (Australia)",
        "dod" | "usgovdod" => "US Government DoD",
        "gcc" => "Government Community Cloud",
        "gcchigh" | "usgovgcchigh" => "GCC High",
        "usgov" => "US Government",
        "emea" => "Europe, Middle East and Africa",
        "malwaresubmission" => "Malware sample submission",
        "maps" => "MAPS cloud protection",
        "common" => "Common dependencies",
        "commonlinux" => "Common Linux dependencies",
        "commonmac" => "Common macOS dependencies",
        "commonmaclinux" => "Common macOS and Linux dependencies",
        "crl" => "Certificate revocation lists",
        "microsoftmonitoringagentmma" => "Legacy Microsoft Monitoring Agent",
        "muadl" => "Microsoft update downloads (MUADL)",
        "muwu" => "Microsoft / Windows Update (MUWU)",
        "security-center-portal" => "Security portal",
        "securitymanagement" => "Security settings management",
        "streamlinedconnectivitynewurlpattern" => "Streamlined connectivity patterns",
        "reportingandnotifications" => "Reporting and notifications",
        "utc" => "Diagnostic telemetry (UTC)",
        "symbols" => "Debug symbols",
        "skype" => "Skype / Teams service area",
        "allow" => "Allow category",
        "optimize" => "Optimize category",
        "default" => "Default category",
        "required" => "Required category",
        "recommended" => "Recommended category",
        "auth" => "Authentication",
        _ if s.starts_with("microsoftdefenderforendpoint") => "Defender for Endpoint service",
        _ => return s.replace(['-', '_'], " "),
    };
    name.into()
}
pub fn description(url: &str) -> String {
    let scope = if url.contains("/msdefender/all/") {
        "All published Defender scopes, including regional and government feeds; broader than one tenant needs."
    } else if url.contains("/msdefender/ww/") {
        "Worldwide shared Defender dependencies. Review alongside your tenant's regional categories."
    } else if url.contains("/msdefender/") {
        "Defender regional/cloud subset. Choose your tenant's data location and review Worldwide shared dependencies too."
    } else {
        "Published URL subset for the named service, scope and category. All means all within that feed's scope."
    };
    let purpose = if url.contains("/malwaresubmission/") {
        "Sample submission destinations; a generic HTTP probe does not upload a sample."
    } else if url.contains("/streamlinedconnectivity") {
        "Consolidated service patterns; wildcard entries need concrete hostnames and are not tested as apexes."
    } else if url.contains("/crl/") {
        "Certificate revocation dependencies; HTTP-only entries are excluded from these HTTPS tests."
    } else if url.contains("/maps/") {
        "Antivirus cloud protection lookups; reachability is not a functional protection verdict."
    } else if url.contains("/any/") {
        "Combines service categories in this scope."
    } else {
        "Tests concrete hostnames only; protocol-specific or authenticated operations may return non-2xx responses."
    };
    format!(
        "{scope} {purpose} This feed is not a complete tenant allowlist or proof of sensor health."
    )
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn scope_labels_and_search_are_unambiguous() {
        let all = "https://host/feeds/msdefender/all/any/url";
        let eu = "https://host/feeds/msdefender/eu/any/url";
        assert!(label(all).contains("All scopes"));
        assert!(label(eu).contains("EU (Europe)"));
        assert!(description(eu).contains("Worldwide"));
        for url in include_str!("../assets/edl-catalog.txt").lines() {
            assert!(!label(url).contains("https://"));
            assert!(description(url).contains("not a complete"));
        }
        assert!(!crate::edl::catalog("Europe").is_empty());
    }
}
