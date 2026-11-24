use reqwest::Client;
use regex::Regex;
use crate::models::{AnalysisReport, Finding, MinedSecret};

async fn verify_live_status(client: &Client, secret_type: &str, value: &str) -> bool {
    match secret_type {
        "Slack Webhook URL" => {
            if let Ok(resp) = client.get(value).send().await {
                return resp.status().as_u16() != 404;
            }
        }
        "GitHub Access Token" => {
            if let Ok(resp) = client.get("https://api.github.com/user")
                .header("Authorization", format!("token {}", value))
                .header("User-Agent", "obsd_zero_probe")
                .send().await
            {
                return resp.status().is_success();
            }
        }
        _ => {}
    }
    false
}

pub async fn mine_and_verify_secrets(client: &Client, content: &str, report: &mut AnalysisReport) {
    let secret_patterns = [
        (Regex::new(r"AKIA[0-9A-Z]{16}").unwrap(), "AWS Access Key ID"),
        (Regex::new(r"https://hooks\.slack\.com/services/T[a-zA-Z0-9_]+/B[a-zA-Z0-9_]+/[a-zA-Z0-9_]+").unwrap(), "Slack Webhook URL"),
        (Regex::new(r"ghp_[a-zA-Z0-9]{36}").unwrap(), "GitHub Access Token"),
        (Regex::new(r"sq0atp-[0-9a-zA-Z\-_]{22}").unwrap(), "Square Access Token"),
    ];

    for (re, secret_type) in secret_patterns {
        for cap in re.captures_iter(content) {
            let secret_val = cap[0].to_string();
            let is_live = verify_live_status(client, secret_type, &secret_val).await;
            
            report.mined_secrets.push(MinedSecret {
                secret_type: secret_type.to_string(),
                value: secret_val.clone(),
                is_active_live: is_live,
            });

            let severity = if is_live { "CRITICAL (VERIFIED LIVE)" } else { "HIGH (UNVERIFIED)" };
            report.findings.push(Finding {
                cwe: "CWE-798".to_string(),
                title: "Exposed Hardcoded Credential".to_string(),
                severity: severity.to_string(),
                description: format!("Found {} in target web assets.", secret_type),
                fix_patch: "Revoke token immediately and move to environment variables.".to_string(),
                curl_poc: format!("Secret Value: {}", secret_val),
            });
        }
    }
}
