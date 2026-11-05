//! Service-aware probe paths and evidence-qualified interpretations.
//! Interpretations NEVER change raw success/error evidence.
use crate::reporting::Attempt;
use serde::Deserialize;
use std::sync::OnceLock;
#[derive(Debug, Clone, Copy)]
pub struct Probe {
    pub method: &'static str,
    pub path: &'static str,
    pub source: &'static str,
}
pub const GENERIC: Probe = Probe {
    method: "HEAD",
    path: "/",
    source: "generic connectivity probe",
};
pub fn probe(host: &str, port: u16, generic: bool) -> Probe {
    if generic || port != 443 {
        return GENERIC;
    }
    let path = match host {
        "edr-weu.eu.endpoint.security.microsoft.com"
        | "edr-neu.eu.endpoint.security.microsoft.com"
        | "edr-weu3.eu.endpoint.security.microsoft.com"
        | "edr-neu3.eu.endpoint.security.microsoft.com"
        | "edr-wus.us.endpoint.security.microsoft.com" => Some("/edr/commands/test"),
        "mdav.eu.endpoint.security.microsoft.com"
        | "mdav.us.endpoint.security.microsoft.com"
        | "mdav.uk.endpoint.security.microsoft.com" => Some("/mdav/wdcp.svc/heartbeat"),
        _ => None,
    };
    if let Some(path) = path {
        return Probe {
            method: "GET",
            path,
            source: "Test-MDERegionalComparison.ps1; Invoke-MDEFullDiag.ps1",
        };
    }
    let path = match host {
        "winatp-gw-cus.microsoft.com"
        | "winatp-gw-eus.microsoft.com"
        | "winatp-gw-weu.microsoft.com"
        | "winatp-gw-neu.microsoft.com"
        | "winatp-gw-ukw.microsoft.com"
        | "winatp-gw-uks.microsoft.com" => Some("/test"),
        "cdn.x.cp.wd.microsoft.com"
        | "eu-cdn.x.cp.wd.microsoft.com"
        | "wu-cdn.x.cp.wd.microsoft.com"
        | "eu-v20.events.data.microsoft.com"
        | "us-v20.events.data.microsoft.com"
        | "uk-v20.events.data.microsoft.com"
        | "v20.events.data.microsoft.com" => Some("/ping"),
        "x.cp.wd.microsoft.com" => Some("/api/report"),
        _ => None,
    };
    if let Some(path) = path {
        Probe {
            method: "GET",
            path,
            source: "https://learn.microsoft.com/en-us/defender-endpoint/linux-support-connectivity",
        }
    } else {
        GENERIC
    }
}
pub fn family_apex(host: &str) -> bool {
    matches!(
        host,
        "wd.microsoft.com"
            | "endpoint.security.microsoft.com"
            | "delivery.mp.microsoft.com"
            | "windowsupdate.com"
    )
}
#[derive(Deserialize)]
struct Rule {
    host: String,
    codes: Vec<u16>,
    confidence: String,
    source: String,
}
fn rules() -> &'static [Rule] {
    static RULES: OnceLock<Vec<Rule>> = OnceLock::new();
    RULES.get_or_init(|| {
        serde_json::from_str(include_str!("../assets/endpoint-expectations.json"))
            .expect("validated embedded expectations")
    })
}
pub fn assess(a: &mut Attempt) {
    let (assessment, note) = if let Some(e) = &a.error {
        if e.code == "DNS_LOOKUP_FAILED" && family_apex(&a.hostname) {
            ("apex_not_service_test".into(),"Known wildcard-family apex in local scripts; no resolved address is not evidence that concrete service hosts are blocked. Raw DNS failure retained; test real tenant/regional names. Historical baseline, not proof of current DNS design.".into())
        } else if a.hostname == "reflector.defender.microsoft.com"
            && (e.code.starts_with("DNS_") || e.code.starts_with("TCP_"))
        {
            ("optional_ipv6_probe".into(),"Microsoft documents this as an optional IPv6 probe. Check IPv6 availability before interpreting its failure as a required-service outage. Raw failure retained.".into())
        } else {
            ("transport_failure".into(),"Requested stage failed. No expected-response rule suppresses DNS, TCP or certificate failures.".into())
        }
    } else if let Some(status) = a.http_status {
        let root = a.http_path.as_deref() == Some("/") && a.port == 443;
        let rule = rules()
            .iter()
            .find(|r| root && r.host == a.hostname && r.codes.contains(&status));
        if status >= 500 {
            let historical = rule
                .map(|r| {
                    format!(
                        " Local scripts also record this status ({}, {}).",
                        r.confidence, r.source
                    )
                })
                .unwrap_or_default();
            (
                "review_http".into(),
                format!(
                    "HTTP {status}: HTTPS transport completed, but gateway/service response needs review. A bare service probe or an intermediary may produce this; it is not proof of service health or interception.{historical}"
                ),
            )
        } else if status >= 400 {
            if let Some(rule) = rule {
                (
                    if rule.confidence == "historical_script_baseline" {
                        "known_http_response"
                    } else {
                        "possible_expected_http"
                    }
                    .into(),
                    format!(
                        "HTTP {status} at / matches {} in {}. Generic service requests can be rejected; this is not a connectivity failure. This historical/script expectation is not current service-health validation.",
                        rule.confidence, rule.source
                    ),
                )
            } else if root && a.hostname.ends_with(".blob.core.windows.net") && status == 400 {
                ("known_http_response".into(),"Blob root HTTP 400 matches the local scripts' service-probe expectation: a concrete resource path is normally required. Transport succeeded; no storage authorization or sensor health is proven.".into())
            } else {
                (
                    "review_http".into(),
                    format!(
                        "HTTP {status}: transport succeeded; method, path, authentication or service policy may explain the response. No specific expectation matched this request."
                    ),
                )
            }
        } else {
            (
                "response_received".into(),
                format!(
                    "HTTP {status}: response received for the recorded method/path. This does not prove sensor health."
                ),
            )
        }
    } else {
        (
            "stage_succeeded".into(),
            "Selected diagnostic stages completed; downstream service operation is not asserted."
                .into(),
        )
    };
    a.assessment = assessment;
    a.diagnostic_note = note;
    if a.http_method.is_some() && a.http_path.as_deref() != Some("/") {
        let plan = probe(&a.hostname, a.port, false);
        a.diagnostic_note
            .push_str(&format!(" Probe path source: {}.", plan.source));
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    use crate::reporting::Failure;
    fn response(host: &str, path: &str, status: u16) -> Attempt {
        let mut a = Attempt::new(host.into(), None, 443, 1);
        a.success = true;
        a.http_status = Some(status);
        a.http_method = Some("HEAD".into());
        a.http_path = Some(path.into());
        a
    }
    #[test]
    fn exact_probe_paths_and_generic_override() {
        assert_eq!(
            probe("edr-weu.eu.endpoint.security.microsoft.com", 443, false).path,
            "/edr/commands/test"
        );
        assert_eq!(
            probe("winatp-gw-weu.microsoft.com", 443, false).path,
            "/test"
        );
        assert_eq!(probe("cdn.x.cp.wd.microsoft.com", 443, false).path, "/ping");
        assert_eq!(
            probe("mdav.eu.endpoint.security.microsoft.com", 443, false).path,
            "/mdav/wdcp.svc/heartbeat"
        );
        assert_eq!(
            probe(
                "edr-weu.eu.endpoint.security.microsoft.com.evil.test",
                443,
                false
            )
            .path,
            "/"
        );
        assert_eq!(
            probe("edr-weu.eu.endpoint.security.microsoft.com", 443, true).method,
            "HEAD"
        );
    }
    #[test]
    fn expectations_are_scoped_and_never_hide_failures() {
        let mut a = response("eu-v20.events.data.microsoft.com", "/", 404);
        assess(&mut a);
        assert_eq!(a.assessment, "known_http_response");
        assert!(a.success);
        a.http_path = Some("/ping".into());
        assess(&mut a);
        assert_eq!(a.assessment, "review_http");
        let mut a = response("mdav.eu.endpoint.security.microsoft.com", "/", 502);
        assess(&mut a);
        assert_eq!(a.assessment, "review_http");
        a.success = false;
        a.error = Some(Failure::new(
            "TLS_CERTIFICATE_INVALID",
            "issuer looks public",
        ));
        assess(&mut a);
        assert_eq!(a.assessment, "transport_failure");
        assert!(!a.success);
    }
    #[test]
    fn known_apex_is_not_success() {
        let mut a = Attempt::new("endpoint.security.microsoft.com".into(), None, 443, 1);
        a.error = Some(Failure::new("DNS_LOOKUP_FAILED", "no address"));
        assess(&mut a);
        assert_eq!(a.assessment, "apex_not_service_test");
        assert!(!a.success);
        let mut other = Attempt::new("dmd.metaservices.microsoft.com".into(), None, 443, 1);
        other.error = a.error.clone();
        assess(&mut other);
        assert_eq!(other.assessment, "transport_failure");
    }
}
