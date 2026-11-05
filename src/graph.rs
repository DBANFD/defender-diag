//! Optional read-only Graph enrichment. Tokens remain in memory, never in reports.
use crate::collection::{Cancel, new_dir, write_new};
use anyhow::{Context, Result, ensure};
use serde_json::{Value, json};
use std::{collections::BTreeSet, path::PathBuf, sync::atomic::Ordering, time::Duration};
#[derive(Clone, Debug, clap::Args)]
pub struct Options {
    #[arg(long,value_parser=guid)]
    pub tenant: String,
    #[arg(long,value_parser=guid)]
    pub client_id: String,
    /// Verified Entra deviceId (not directory object ID or Intune managed-device ID).
    #[arg(long,value_parser=guid)]
    pub entra_device_id: String,
    /// Required if several Intune records match the Entra deviceId.
    #[arg(long,value_parser=guid)]
    pub managed_device_id: Option<String>,
    /// Enable labelled beta Settings Catalog / endpoint security / baseline inventory.
    #[arg(long)]
    pub beta: bool,
    /// Resolve Entra object ID; adds Device.Read.All consent.
    #[arg(long)]
    pub directory: bool,
    /// Read bounded tenant compliance report pages, retain matching device rows only.
    #[arg(long)]
    pub reports: bool,
    #[arg(long, default_value = "results/intune")]
    pub output_dir: PathBuf,
}
pub fn guid(s: &str) -> std::result::Result<String, String> {
    if s.len() != 36
        || !s.bytes().enumerate().all(|(i, b)| {
            if [8, 13, 18, 23].contains(&i) {
                b == b'-'
            } else {
                b.is_ascii_hexdigit()
            }
        })
        || s.chars().all(|c| c == '0' || c == '-')
    {
        return Err("Expected a nonzero GUID".into());
    }
    Ok(s.to_ascii_lowercase())
}
fn check(cancel: &Cancel) -> Result<()> {
    ensure!(!cancel.load(Ordering::Relaxed), "Cancelled");
    Ok(())
}
pub fn allowed(url: &str) -> Result<reqwest::Url> {
    let u = reqwest::Url::parse(url)?;
    ensure!(
        u.scheme() == "https"
            && u.host_str() == Some("graph.microsoft.com")
            && u.username().is_empty()
            && u.password().is_none()
            && u.port_or_known_default() == Some(443)
            && (u.path().starts_with("/v1.0/") || u.path().starts_with("/beta/")),
        "Blocked Graph URL/nextLink origin"
    );
    Ok(u)
}
pub fn http_error(status: u16) -> &'static str {
    match status {
        401 => "Authentication expired or invalid",
        403 => "Permission/role/scope-tag access denied; coverage incomplete",
        429 => "Throttled; retry budget exhausted",
        _ => "Graph request failed; coverage incomplete",
    }
}
fn retry_delay(header: Option<&str>, attempt: u32) -> Result<u64> {
    let delay = header
        .and_then(|h| {
            h.parse::<u64>().ok().or_else(|| {
                chrono::DateTime::parse_from_rfc2822(h).ok().map(|d| {
                    (d.with_timezone(&chrono::Utc) - chrono::Utc::now())
                        .num_seconds()
                        .max(0) as u64
                        + 1
                })
            })
        })
        .unwrap_or(2u64.pow(attempt));
    ensure!(delay <= 300, "Retry-After exceeds wait budget; retry later");
    Ok(delay)
}
pub async fn bounded_json(mut response: reqwest::Response) -> Result<Value> {
    let mut b = vec![];
    while let Some(c) = response.chunk().await? {
        ensure!(
            b.len() + c.len() <= 8 * 1024 * 1024,
            "Response exceeds 8 MiB"
        );
        b.extend(c);
    }
    Ok(serde_json::from_slice(&b)?)
}
pub async fn paginate<F, Fut>(start: String, mut fetch: F) -> Result<Vec<Value>>
where
    F: FnMut(String) -> Fut,
    Fut: std::future::Future<Output = Result<Value>>,
{
    let mut next = Some(start);
    let mut seen = BTreeSet::new();
    let mut out = vec![];
    let mut bytes = 0;
    while let Some(url) = next {
        allowed(&url)?;
        ensure!(
            seen.len() < 100 && seen.insert(url.clone()),
            "Pagination limit or cycle; incomplete coverage"
        );
        let v = fetch(url).await?;
        bytes += v.to_string().len();
        ensure!(bytes <= 64 * 1024 * 1024, "Graph collection byte limit");
        let rows = v["value"]
            .as_array()
            .context("Graph response lacks value array")?;
        ensure!(
            out.len() + rows.len() <= 10000,
            "Graph row limit; incomplete coverage"
        );
        out.extend(rows.iter().cloned());
        next = v["@odata.nextLink"].as_str().map(str::to_owned);
    }
    Ok(out)
}
struct Graph {
    client: reqwest::Client,
    token: String,
    cancel: Cancel,
}
impl Graph {
    async fn request(&self, url: &str, body: Option<&Value>) -> Result<Value> {
        let u = allowed(url)?;
        for attempt in 0..5 {
            check(&self.cancel)?;
            let req = if let Some(body) = body {
                self.client.post(u.clone()).json(body)
            } else {
                self.client.get(u.clone())
            };
            let response = req.bearer_auth(&self.token).send().await?;
            let status = response.status();
            if matches!(status.as_u16(), 429 | 503) && attempt < 4 {
                let wait = retry_delay(
                    response
                        .headers()
                        .get("Retry-After")
                        .and_then(|x| x.to_str().ok()),
                    attempt,
                )?;
                for _ in 0..wait {
                    check(&self.cancel)?;
                    tokio::time::sleep(Duration::from_secs(1)).await;
                }
                continue;
            }
            ensure!(
                status.is_success(),
                "{} (HTTP {})",
                http_error(status.as_u16()),
                status.as_u16()
            );
            return bounded_json(response).await;
        }
        anyhow::bail!("Graph retry budget exhausted")
    }
    async fn list(&self, url: &str) -> Result<Vec<Value>> {
        paginate(url.into(), |u| async move { self.request(&u, None).await }).await
    }
}
async fn authenticate(o: &Options, cancel: Cancel, progress: &impl Fn(String)) -> Result<Graph> {
    let client = reqwest::Client::builder()
        .timeout(Duration::from_secs(30))
        .redirect(reqwest::redirect::Policy::none())
        .build()?;
    let base = format!(
        "https://login.microsoftonline.com/{}/oauth2/v2.0",
        guid(&o.tenant).map_err(anyhow::Error::msg)?
    );
    let mut scope="https://graph.microsoft.com/DeviceManagementManagedDevices.Read.All https://graph.microsoft.com/DeviceManagementConfiguration.Read.All".to_string();
    if o.directory {
        scope.push_str(" https://graph.microsoft.com/Device.Read.All");
    }
    let response = client
        .post(format!("{base}/devicecode"))
        .form(&[
            ("client_id", o.client_id.as_str()),
            ("scope", scope.as_str()),
        ])
        .send()
        .await?;
    ensure!(
        response.status().is_success(),
        "Device-code request rejected; check public-client registration, tenant and consent"
    );
    let v = bounded_json(response).await?;
    let code = v["device_code"]
        .as_str()
        .context("No device code")?
        .to_string();
    let user = v["user_code"].as_str().context("No user code")?;
    let uri = v["verification_uri"]
        .as_str()
        .context("No verification URI")?;
    ensure!(uri.starts_with("https://"), "Invalid verification URI");
    progress(format!(
        "Sign in at {uri} using code {user}. Only continue if you initiated this read-only investigation."
    ));
    let expires = std::time::Instant::now()
        + Duration::from_secs(v["expires_in"].as_u64().unwrap_or(900).min(1800));
    let mut interval = v["interval"].as_u64().unwrap_or(5).max(5);
    while std::time::Instant::now() < expires {
        for _ in 0..interval {
            check(&cancel)?;
            tokio::time::sleep(Duration::from_secs(1)).await;
        }
        let v = bounded_json(
            client
                .post(format!("{base}/token"))
                .form(&[
                    ("grant_type", "urn:ietf:params:oauth:grant-type:device_code"),
                    ("client_id", o.client_id.as_str()),
                    ("device_code", code.as_str()),
                ])
                .send()
                .await?,
        )
        .await?;
        if let Some(token) = v["access_token"].as_str() {
            return Ok(Graph {
                client,
                token: token.into(),
                cancel,
            });
        }
        match v["error"].as_str() {
            Some("authorization_pending") => {}
            Some("slow_down") => interval += 5,
            _ => anyhow::bail!("Authentication declined, expired or unavailable; no token saved"),
        }
    }
    anyhow::bail!("Authentication timed out")
}
pub fn resolve(rows: Vec<Value>, entra: &str, managed: Option<&str>) -> Result<Value> {
    let rows = rows
        .into_iter()
        .filter(|d| {
            d["azureADDeviceId"]
                .as_str()
                .is_some_and(|id| id.eq_ignore_ascii_case(entra))
                && managed
                    .is_none_or(|id| d["id"].as_str().is_some_and(|s| s.eq_ignore_ascii_case(id)))
        })
        .collect::<Vec<_>>();
    ensure!(
        rows.len() == 1,
        "Device identity missing or ambiguous; provide verified Entra deviceId and, if needed, Intune managed-device ID. Display-name matching is not used."
    );
    Ok(rows[0].clone())
}
pub fn coverage(beta: bool) -> Value {
    json!([
        {"family":"configuration profiles","api":"v1.0","inventory_assignments":"supported","device_status":"legacy deviceStatuses resource deprecated; not queried","per_setting":"not collected"},
        {"family":"compliance","api":"v1.0","inventory_assignments":"supported","device_status":"optional bounded reporting","per_setting":"optional bounded reporting"},
        {"family":"Settings Catalog and modern endpoint security/baselines","api":"beta","inventory_assignments":if beta{"enabled"}else{"disabled: use --beta"},"device_status":"not collected","per_setting":"not collected"},
        {"family":"legacy endpoint security/baselines intents","api":"beta","inventory_assignments":if beta{"enabled"}else{"disabled: use --beta"},"device_status":"not collected","per_setting":"not collected"},
        {"family":"scripts, remediations, apps, app protection, Windows Update rings outside profiles","inventory_assignments":"not covered"}
    ])
}
pub fn report_rows(v: &Value) -> Result<Vec<Value>> {
    let schema = v["Schema"].as_array().context("Report Schema missing")?;
    let values = v["Values"].as_array().context("Report Values missing")?;
    values
        .iter()
        .map(|row| {
            let row = row.as_array().context("Report row malformed")?;
            ensure!(row.len() == schema.len(), "Report schema/row mismatch");
            let mut obj = serde_json::Map::new();
            for (col, val) in schema.iter().zip(row) {
                let name = col["Column"].as_str().context("Report column missing")?;
                obj.insert(name.into(), val.clone());
            }
            Ok(Value::Object(obj))
        })
        .collect()
}
async fn reports(g: &Graph, name: &str, managed: &str) -> Result<Vec<Value>> {
    let mut out = vec![];
    for page in 0..100 {
        let v = g
            .request(
                &format!("https://graph.microsoft.com/v1.0/deviceManagement/reports/{name}"),
                Some(&json!({"skip":page*100,"top":100,"select":[],"orderBy":[],"filter":""})),
            )
            .await?;
        let rows = report_rows(&v)?;
        let len = rows.len();
        out.extend(rows.into_iter().filter(|r| {
            r["DeviceId"]
                .as_str()
                .is_some_and(|id| id.eq_ignore_ascii_case(managed))
        }));
        if len < 100 {
            return Ok(out);
        }
    }
    anyhow::bail!("Report page limit; coverage incomplete")
}
pub async fn run(o: &Options, cancel: Cancel, progress: impl Fn(String)) -> Result<PathBuf> {
    guid(&o.client_id).map_err(anyhow::Error::msg)?;
    guid(&o.entra_device_id).map_err(anyhow::Error::msg)?;
    let root = new_dir(&o.output_dir, "graph")?;
    let g = authenticate(o, cancel.clone(), &progress).await?;
    let mut url =
        reqwest::Url::parse("https://graph.microsoft.com/v1.0/deviceManagement/managedDevices")?;
    url.query_pairs_mut()
        .append_pair(
            "$filter",
            &format!("azureADDeviceId eq '{}'", o.entra_device_id),
        )
        .append_pair(
            "$select",
            "id,azureADDeviceId,deviceName,userId,lastSyncDateTime,complianceState,managementAgent",
        );
    let device = resolve(
        g.list(url.as_str()).await?,
        &o.entra_device_id,
        o.managed_device_id.as_deref(),
    )?;
    let managed = device["id"]
        .as_str()
        .context("Managed ID missing")?
        .to_string();
    guid(&managed).map_err(anyhow::Error::msg)?;
    let mut result = json!({"schema_version":1,"source":"Microsoft Graph","started_at":chrono::Utc::now().to_rfc3339(),"identity":{"intune_managed_device_id":managed,"entra_device_id":o.entra_device_id,"entra_object_id":null},"device":device,"coverage":coverage(o.beta),"assignments_and_policy_inventory":[],"reported_status":{},"locally_observed_effective_values":null,"errors":[],"notes":["Tenant policy inventory is not a list of policies applying to this device. Assignment targets retain device/user groups, exclusions and filters. Group membership and filters are not evaluated locally.","Reporting delay, user context, Intune RBAC/scope tags and permissions affect coverage. No policy, assignment, enrollment or synchronization changes.","Local collection is separate; cloud reporting is not proof of current local effective values."]});
    let mut errors = vec![];
    let mut inventory = vec![];
    let mut inventory_bytes = 0usize;
    if o.directory {
        match g
            .request(
                &format!(
                    "https://graph.microsoft.com/v1.0/devices(deviceId='{}')?$select=id,deviceId",
                    o.entra_device_id
                ),
                None,
            )
            .await
        {
            Ok(v)
                if v["deviceId"]
                    .as_str()
                    .is_some_and(|s| s.eq_ignore_ascii_case(&o.entra_device_id)) =>
            {
                result["identity"]["entra_object_id"] = v["id"].clone()
            }
            Ok(_) => errors.push(json!({"source":"directory","error":"Identity mismatch"})),
            Err(e) => errors.push(json!({"source":"directory","error":e.to_string()})),
        }
    }
    let mut families = vec![
        ("v1.0", "deviceConfigurations"),
        ("v1.0", "deviceCompliancePolicies"),
    ];
    if o.beta {
        families.extend([("beta", "configurationPolicies"), ("beta", "intents")]);
    }
    for (api, family) in families {
        if check(&cancel).is_err() {
            errors.push(json!({"error":"cancelled"}));
            break;
        }
        progress(format!(
            "Reading {api}/{family} inventory and assignment evidence"
        ));
        let base = format!("https://graph.microsoft.com/{api}/deviceManagement/{family}");
        match g.list(&base).await {
            Ok(policies) => {
                for policy in policies {
                    if inventory.len() >= 500 || inventory_bytes >= 64 * 1024 * 1024 {
                        errors.push(json!({"source":family,"error":"Inventory budget reached; partial coverage"}));
                        break;
                    }
                    if check(&cancel).is_err() {
                        break;
                    }
                    let Some(id) = policy["id"].as_str() else {
                        errors.push(json!({"source":family,"error":"Missing policy ID"}));
                        continue;
                    };
                    if guid(id).is_err() {
                        errors
                            .push(json!({"source":family,"error":"Unsupported policy ID format"}));
                        continue;
                    }
                    let mut row = json!({"api":api,"family":family,"id":id,"name":policy.get("displayName").or_else(||policy.get("name")),"lastModifiedDateTime":policy["lastModifiedDateTime"],"createdDateTime":policy["createdDateTime"],"type":policy["@odata.type"],"templateId":policy["templateId"],"templateReference":policy["templateReference"],"source":base,"retrieved_at":chrono::Utc::now().to_rfc3339(),"applicability":"not determined","assignments":null});
                    match g.list(&format!("{base}/{id}/assignments")).await {
                        Ok(a) => row["assignments"] = a.into(),
                        Err(e) => row["error"] = e.to_string().into(),
                    };
                    inventory_bytes += row.to_string().len();
                    inventory.push(row);
                }
            }
            Err(e) => errors.push(json!({"source":family,"error":e.to_string()})),
        }
    }
    if o.beta && !cancel.load(Ordering::Relaxed) {
        match g
            .list("https://graph.microsoft.com/beta/deviceManagement/assignmentFilters")
            .await
        {
            Ok(v) => result["assignment_filter_definitions"] = v.into(),
            Err(e) => errors.push(json!({"source":"assignmentFilters","error":e.to_string()})),
        }
    }
    if o.reports {
        for name in [
            "getDevicePoliciesComplianceReport",
            "getDevicePolicySettingsComplianceReport",
        ] {
            if check(&cancel).is_err() {
                break;
            }
            progress(format!(
                "Reading bounded {name}; retaining exact managed-device ID only"
            ));
            match reports(&g, name, &managed).await {
                Ok(rows) => {
                    result["reported_status"][name] =
                        json!({"retrieved_at":chrono::Utc::now().to_rfc3339(),"rows":rows})
                }
                Err(e) => errors.push(json!({"source":name,"error":e.to_string()})),
            }
        }
    }
    for row in &inventory {
        if row.get("error").is_some() {
            errors.push(json!({"source":row["family"],"policy_id":row["id"],"error":row["error"]}));
        }
    }
    result["assignments_and_policy_inventory"] = inventory.into();
    result["errors"] = errors.into();
    result["completed_at"] = chrono::Utc::now().to_rfc3339().into();
    result["cancelled"] = cancel.load(Ordering::Relaxed).into();
    write_new(
        &root.join("graph-private.json"),
        &serde_json::to_vec_pretty(&result)?,
    )?;
    write_new(&root.join("SUMMARY.txt"),b"Microsoft Graph read-only evidence. See graph-private.json for identity, coverage, assignment inventory, reported status and errors. Applicability remains not determined. Raw evidence is private. No local effective values are inferred.\n")?;
    write_new(
        &root.join("shareable-summary.json"),
        &serde_json::to_vec_pretty(
            &json!({"schema_version":1,"coverage":coverage(o.beta),"inventory_count":result["assignments_and_policy_inventory"].as_array().map(Vec::len),"errors":result["errors"].as_array().map(Vec::len),"notice":"No raw identifiers or error text included. Raw cloud evidence is not anonymous."}),
        )?,
    )?;
    let files = [
        "graph-private.json",
        "SUMMARY.txt",
        "shareable-summary.json",
    ]
    .into_iter()
    .map(|f| crate::collection::evidence(&root.join(f)))
    .collect::<Result<Vec<_>>>()?;
    write_new(
        &root.join("manifest.json"),
        &serde_json::to_vec_pretty(
            &json!({"schema_version":1,"collector":"graph-read-only","collector_version":"1","tool_version":env!("CARGO_PKG_VERSION"),"started_at":result["started_at"],"completed_at":result["completed_at"],"cancelled":result["cancelled"],"errors":result["errors"],"files":files}),
        )?,
    )?;
    crate::collection::support_zip(&root)?;
    Ok(root)
}
#[cfg(test)]
mod tests {
    use super::*;
    #[tokio::test]
    async fn throttling_and_missing_permissions_are_explicit() {
        assert_eq!(retry_delay(Some("20"), 0).unwrap(), 20);
        assert!(retry_delay(Some("600"), 0).is_err());
        let date = (chrono::Utc::now() + chrono::Duration::seconds(30)).to_rfc2822();
        assert!((29..=31).contains(&retry_delay(Some(&date), 0).unwrap()));
        let failure = paginate("https://graph.microsoft.com/v1.0/test".into(), |_| async {
            anyhow::bail!(http_error(403))
        })
        .await
        .unwrap_err();
        assert!(failure.to_string().contains("Permission"));
    }
    #[tokio::test]
    async fn pagination_permissions_and_hostile_links() {
        let rows = paginate(
            "https://graph.microsoft.com/v1.0/test".into(),
            |u| async move {
                Ok(if u.ends_with("page2") {
                    json!({"value":[2]})
                } else {
                    json!({"value":[1],"@odata.nextLink":"https://graph.microsoft.com/v1.0/page2"})
                })
            },
        )
        .await
        .unwrap();
        assert_eq!(rows.len(), 2);
        assert!(
            paginate("https://graph.microsoft.com/v1.0/test".into(), |_| async {
                Ok(json!({"value":[],"@odata.nextLink":"https://evil.example/"}))
            })
            .await
            .is_err()
        );
        assert!(http_error(403).contains("incomplete"));
    }
    #[test]
    fn identity_and_coverage_are_not_assignment_verdicts() {
        let d = json!({"id":"11111111-1111-1111-1111-111111111111","azureADDeviceId":"22222222-2222-2222-2222-222222222222"});
        assert!(
            resolve(
                vec![d.clone(), d.clone()],
                "22222222-2222-2222-2222-222222222222",
                None
            )
            .is_err()
        );
        assert!(resolve(vec![d], "11111111-1111-1111-1111-111111111111", None).is_err());
        assert!(coverage(false).to_string().contains("disabled"));
        assert!(guid("x' or 1 eq 1").is_err());
    }
    #[test]
    fn report_schema_conflicts_preserved() {
        let rows=report_rows(&json!({"Schema":[{"Column":"SettingStatus"},{"Column":"ErrorCode"}],"Values":[["conflict",123]]})).unwrap();
        assert_eq!(rows[0]["SettingStatus"], "conflict");
    }
}
