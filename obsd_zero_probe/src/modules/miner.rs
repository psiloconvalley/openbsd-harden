use reqwest::Client;
use regex::Regex;
use std::collections::HashSet;
use crate::models::{AnalysisReport, Finding};

fn extract_js_urls(html: &str, base_url: &str) -> Vec<String> {
    let script_re = Regex::new(r#"(?i)<script[^>]+src=["']([^"']+)["']"#).unwrap();
    let mut js_urls = Vec::new();
    let clean_base = base_url.trim_end_matches('/');

    for cap in script_re.captures_iter(html) {
        if let Some(src) = cap.get(1) {
            let path = src.as_str();
            if path.starts_with("http://") || path.starts_with("https://") {
                js_urls.push(path.to_string());
            } else if path.starts_with('/') {
                js_urls.push(format!("{}{}", clean_base, path));
            } else {
                js_urls.push(format!("{}/{}", clean_base, path));
            }
        }
    }
    js_urls
}

pub async fn run_js_blueprint_miner(client: &Client, target_url: &str, report: &mut AnalysisReport) {
    let mut discovered_routes = HashSet::new();
    let mut discovered_params = HashSet::new();

    if let Ok(resp) = client.get(target_url).send().await {
        if let Ok(html_body) = resp.text().await {
            let js_urls = extract_js_urls(&html_body, target_url);

            let route_re = Regex::new(r#"(?:"|')(/api/v[0-9]/[a-zA-Z0-9_/-]+|/v1/[a-zA-Z0-9_/-]+|/admin/[a-zA-Z0-9_/-]+|/internal/[a-zA-Z0-9_/-]+)(?:"|')"#).unwrap();
            let param_re = Regex::new(r#"\?([a-zA-Z0-9_]{2,20})="#).unwrap();

            for cap in route_re.captures_iter(&html_body) {
                if let Some(r) = cap.get(1) {
                    discovered_routes.insert(r.as_str().to_string());
                }
            }

            for js_url in js_urls {
                if let Ok(js_resp) = client.get(&js_url).send().await {
                    if let Ok(js_body) = js_resp.text().await {
                        report.js_bundles_scanned += 1;
                        for cap in route_re.captures_iter(&js_body) {
                            if let Some(r) = cap.get(1) {
                                discovered_routes.insert(r.as_str().to_string());
                            }
                        }
                        for cap in param_re.captures_iter(&js_body) {
                            if let Some(p) = cap.get(1) {
                                discovered_params.insert(p.as_str().to_string());
                            }
                        }
                    }
                }
            }
        }
    }

    report.mined_routes = discovered_routes.into_iter().collect();
    report.mined_parameters = discovered_params.into_iter().collect();

    let clean_base = target_url.trim_end_matches('/');
    for route in &report.mined_routes {
        let full_url = format!("{}{}", clean_base, route);
        if let Ok(resp) = client.get(&full_url).send().await {
            if resp.status().is_success() {
                report.findings.push(Finding {
                    cwe: "CWE-306".to_string(),
                    title: "Unauthenticated API Route Exposure".to_string(),
                    severity: "HIGH".to_string(),
                    description: format!("Route '{}' mined from JS bundle is publicly accessible (HTTP 200 OK) without credentials.", route),
                    fix_patch: "Enforce authentication middleware on route handler.".to_string(),
                    curl_poc: format!("curl -i -s \"{}\"", full_url),
                });
            }
        }
    }
}
