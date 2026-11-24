use reqwest::Client;
use crate::models::{AnalysisReport, CloudFingerprint, Finding};

fn get_fingerprints() -> Vec<CloudFingerprint> {
    vec![
        CloudFingerprint { provider: "Amazon S3 Bucket", cname_keyword: "s3.amazonaws.com", signature_body: "The specified bucket does not exist", severity: "HIGH" },
        CloudFingerprint { provider: "GitHub Pages", cname_keyword: "github.io", signature_body: "There isn't a GitHub Pages site here.", severity: "HIGH" },
        CloudFingerprint { provider: "Heroku App", cname_keyword: "herokuapp.com", signature_body: "no-such-app.herokuapp.com", severity: "HIGH" },
        CloudFingerprint { provider: "Azure App Service", cname_keyword: "azurewebsites.net", signature_body: "404 Web Site not found", severity: "HIGH" },
        CloudFingerprint { provider: "Fastly CDN", cname_keyword: "fastly.net", signature_body: "Fastly error: unknown domain", severity: "CRITICAL" },
        CloudFingerprint { provider: "Shopify Store", cname_keyword: "myshopify.com", signature_body: "Sorry, this shop is currently unavailable.", severity: "MEDIUM" },
    ]
}

pub async fn run_takeover_check(client: &Client, target_url: &str, report: &mut AnalysisReport) {
    let fps = get_fingerprints();
    if let Ok(resp) = client.get(target_url).send().await {
        if let Ok(body) = resp.text().await {
            for fp in fps {
                if body.contains(fp.signature_body) {
                    report.findings.push(Finding {
                        cwe: "CWE-1025".to_string(),
                        title: format!("Subdomain Takeover Discovered ({})", fp.provider),
                        severity: fp.severity.to_string(),
                        description: format!("Host returns unclaimed service error matching {} signature.", fp.provider),
                        fix_patch: format!("Claim host on {} or remove DNS record.", fp.provider),
                        curl_poc: format!("curl -i -s \"{}\"", target_url),
                    });
                }
            }
        }
    }
}
