use reqwest::Client;
use crate::models::{AnalysisReport, Finding};

pub async fn run_proxy_bypass_check(client: &Client, target_url: &str, report: &mut AnalysisReport) {
    let clean_url = target_url.trim_end_matches('/');
    let test_endpoints = [format!("{}/admin", clean_url), format!("{}/api/v1/internal", clean_url)];

    let bypass_headers = [
        ("X-Forwarded-For", "127.0.0.1"),
        ("X-Original-URL", "/admin"),
        ("X-Rewrite-URL", "/admin"),
        ("X-Custom-IP-Authorization", "127.0.0.1"),
    ];

    for endpoint in test_endpoints {
        for (header_name, header_val) in bypass_headers {
            let req = client.get(&endpoint).header(header_name, header_val);
            if let Ok(resp) = req.send().await {
                if resp.status().is_success() {
                    let msg = format!("{} with header {}: {}", endpoint, header_name, header_val);
                    report.proxy_bypasses.push(msg.clone());
                    report.findings.push(Finding {
                        cwe: "CWE-444".to_string(),
                        title: "Reverse Proxy Authentication Bypass".to_string(),
                        severity: "CRITICAL".to_string(),
                        description: format!("Header override '{}: {}' bypassed proxy restriction on {}", header_name, header_val, endpoint),
                        fix_patch: "Strip override headers at reverse proxy gateway.".to_string(),
                        curl_poc: format!("curl -i -s -H \"{}: {}\" \"{}\"", header_name, header_val, endpoint),
                    });
                }
            }
        }
    }
}
