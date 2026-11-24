use reqwest::Client;
use std::env;
use std::fs;
use std::process;
use std::time::Duration;

mod models;
mod sandbox;
mod modules;
mod report;

use models::AnalysisReport;

#[tokio::main]
async fn main() {
    let args: Vec<String> = env::args().collect();
    if args.len() < 2 {
        println!("Usage: obsd_zero_probe <target_domain_or_url>");
        process::exit(1);
    }

    let raw_target = &args[1];
    let target_url = if !raw_target.starts_with("http://") && !raw_target.starts_with("https://") {
        format!("https://{}", raw_target)
    } else {
        raw_target.clone()
    };

    let report_dir = "./reports";
    let _ = fs::create_dir_all(report_dir);

    sandbox::apply_sandboxing(report_dir);

    println!("============================================================");
    println!(" [obsd_zero_probe v1.1.0] Stealth Blueprint & Zero-Auth Prober");
    println!(" Hardened Target: {}", target_url);
    println!(" Sandbox State: PLEDGE(stdio inet dns rpath wpath cpath) UNVEIL(./reports)");
    println!("============================================================\n");

    let client = Client::builder()
        .timeout(Duration::from_secs(5))
        .user_agent("obsd_zero_probe/1.1.0 (OpenBSD Hardened)")
        .build()
        .unwrap();

    let mut report = AnalysisReport {
        target_url: target_url.clone(),
        ..Default::default()
    };

    println!("[1/5] Checking Subdomain CNAME Cloud Takeovers...");
    modules::takeover::run_takeover_check(&client, &target_url, &mut report).await;

    println!("[2/5] Testing Reverse Proxy & Gateway Header Override Bypasses...");
    modules::proxy::run_proxy_bypass_check(&client, &target_url, &mut report).await;

    println!("[3/5] Probing Sensitive File Leaks & Security Headers...");
    modules::files::audit_files_and_headers(&client, &target_url, &mut report).await;

    println!("[4/5] Mining JS Bundles for Disclosed API Routes & Parameters...");
    modules::miner::run_js_blueprint_miner(&client, &target_url, &mut report).await;

    println!("[5/5] Fetching Target Assets & Mining Live Secrets...");
    if let Ok(resp) = client.get(&target_url).send().await {
        if let Ok(body) = resp.text().await {
            modules::secrets::mine_and_verify_secrets(&client, &body, &mut report).await;
        }
    }

    println!("\n------------------------------------------------------------");
    println!(" EXPORTING AUDIT REPORTS TO DISK");
    println!("------------------------------------------------------------");
    report::export_reports(&report, report_dir);

    println!("\n============================================================");
    println!(" Zero-Auth Audit Complete. OpenBSD Process Terminated Cleanly.");
    println!("============================================================");
}
