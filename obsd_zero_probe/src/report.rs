use std::fs::File;
use std::io::Write;
use crate::models::AnalysisReport;

pub fn export_reports(report: &AnalysisReport, report_dir: &str) {
    let safe_host = report.target_url.replace('/', "_").replace(':', "_");

    let json_path = format!("{}/{}_audit.json", report_dir, safe_host);
    if let Ok(json_data) = serde_json::to_string_pretty(report) {
        if let Ok(mut f) = File::create(&json_path) {
            let _ = f.write_all(json_data.as_bytes());
            println!("[+] Saved JSON Audit Report: {}", json_path);
        }
    }

    let md_path = format!("{}/{}_report.md", report_dir, safe_host);
    if let Ok(mut f) = File::create(&md_path) {
        let mut md = String::new();
        md.push_str(&format!("# Zero-Auth Security Audit Report: {}\n\n", report.target_url));
        md.push_str("## Executive Summary\n");
        md.push_str(&format!("- **Target URL:** {}\n", report.target_url));
        md.push_str(&format!("- **Total Vulnerabilities Identified:** {}\n", report.findings.len()));
        md.push_str(&format!("- **JS Bundles Audited:** {}\n", report.js_bundles_scanned));
        md.push_str(&format!("- **Mined API Routes:** {}\n", report.mined_routes.len()));
        md.push_str(&format!("- **Mined Parameters:** {}\n", report.mined_parameters.len()));
        md.push_str(&format!("- **Mined Live Secrets:** {}\n\n", report.mined_secrets.len()));

        if !report.mined_routes.is_empty() {
            md.push_str("## Mined Disclosed API Routes\n");
            for r in &report.mined_routes {
                md.push_str(&format!("- `{}`\n", r));
            }
            md.push_str("\n");
        }

        md.push_str("## Actionable Findings & Submission-Ready PoCs\n\n");
        for (idx, finding) in report.findings.iter().enumerate() {
            md.push_str(&format!("### {}. {} ({})\n", idx + 1, finding.title, finding.cwe));
            md.push_str(&format!("- **Severity:** {}\n", finding.severity));
            md.push_str(&format!("- **Description:** {}\n", finding.description));
            md.push_str(&format!("- **Fix Patch:** `{}`\n", finding.fix_patch));
            md.push_str(&format!("- **PoC Trigger:**\n```bash\n{}\n```\n\n", finding.curl_poc));
        }

        let _ = f.write_all(md.as_bytes());
        println!("[+] Saved Markdown Report: {}", md_path);
    }
}
