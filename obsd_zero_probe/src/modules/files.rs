use reqwest::Client;
use crate::models::{AnalysisReport, Finding};

pub async fn audit_files_and_headers(client: &Client, target_url: &str, report: &mut AnalysisReport) {
    let clean_base = target_url.trim_end_matches('/');
    
    if let Ok(resp) = client.get(target_url).send().await {
        let headers = resp.headers();
        let required_headers = [
            ("strict-transport-security", "CWE-523", "Missing HSTS Header", "HIGH", "add_header Strict-Transport-Security \"max-age=31536000; includeSubDomains\" always;"),
            ("x-frame-options", "CWE-1021", "Missing Anti-Clickjacking Header", "MEDIUM", "add_header X-Frame-Options \"DENY\" always;"),
            ("x-content-type-options", "CWE-79", "Missing MIME-Sniffing Prevention", "LOW", "add_header X-Content-Type-Options \"nosniff\" always;"),
            ("content-security-policy", "CWE-693", "Missing CSP Header", "HIGH", "add_header Content-Security-Policy \"default-src 'self'\";"),
        ];

        for (h, cwe, title, sev, patch) in required_headers {
            if headers.contains_key(h) {
                report.headers_present.push(h.to_string());
            } else {
                report.headers_missing.push(h.to_string());
                report.findings.push(Finding {
                    cwe: cwe.to_string(),
                    title: title.to_string(),
                    severity: sev.to_string(),
                    description: format!("Security header '{}' is missing.", h),
                    fix_patch: patch.to_string(),
                    curl_poc: format!("curl -I -s \"{}\"", target_url),
                });
            }
        }
    }

    let test_paths = [
        ("/.env", "Exposed Environment File (.env)", "CRITICAL", "CWE-200", "Block access to .env files."),
        ("/.git/HEAD", "Exposed Git Repository (.git)", "HIGH", "CWE-200", "Block access to .git directory."),
        ("/config.json", "Exposed Configuration File (config.json)", "MEDIUM", "CWE-200", "Restrict access to JSON config files."),
        ("/actuator/health", "Exposed Spring Boot Actuator Endpoint", "HIGH", "CWE-200", "Disable public access to actuator endpoints."),
    ];

    for (path, title, sev, cwe, patch) in test_paths {
        let full_url = format!("{}{}", clean_base, path);
        if let Ok(resp) = client.get(&full_url).send().await {
            if resp.status().is_success() {
                report.findings.push(Finding {
                    cwe: cwe.to_string(),
                    title: title.to_string(),
                    severity: sev.to_string(),
                    description: format!("Publicly accessible sensitive file at {}", full_url),
                    fix_patch: patch.to_string(),
                    curl_poc: format!("curl -i -s \"{}\"", full_url),
                });
            }
        }
    }
}
