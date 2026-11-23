use reqwest::Client;
use std::collections::HashSet;
use std::env;
use std::process;
use std::sync::Arc;
use tokio::sync::Barrier;
use regex::Regex;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Finding {
    pub cwe: &'static str,
    pub title: &'static str,
    pub severity: &'static str,
    pub description: String,
    pub root_cause_code_error: &'static str,
    pub remediation_patch: &'static str,
}

#[derive(Debug, Default)]
pub struct AnalysisReport {
    pub findings: Vec<Finding>,
    pub mined_routes: HashSet<String>,
    pub mined_secrets: HashSet<String>,
    pub js_bundles_scanned: usize,
    pub headers_present: Vec<String>,
    pub headers_missing: Vec<String>,
}

extern "C" {
    fn pledge(promises: *const libc::c_char, execpromises: *const libc::c_char) -> libc::c_int;
    fn unveil(path: *const libc::c_char, flags: *const libc::c_char) -> libc::c_int;
}

fn apply_sandboxing() {
    unsafe {
        let ssl_path = std::ffi::CString::new("/etc/ssl").unwrap();
        let read_mode = std::ffi::CString::new("r").unwrap();
        if unveil(ssl_path.as_ptr(), read_mode.as_ptr()) != 0 {
            eprintln!("Error: unveil /etc/ssl failed");
            process::exit(1);
        }
        if unveil(std::ptr::null(), std::ptr::null()) != 0 {
            eprintln!("Error: unveil lock failed");
            process::exit(1);
        }

        let promises = std::ffi::CString::new("stdio inet dns rpath").unwrap();
        if pledge(promises.as_ptr(), std::ptr::null()) != 0 {
            eprintln!("Error: pledge failed");
            process::exit(1);
        }
    }
}

fn analyze_headers(headers: &reqwest::header::HeaderMap, report: &mut AnalysisReport) {
    let required_headers = [
        ("strict-transport-security", "CWE-523", "Missing HSTS Header", "HIGH",
         "Web server configuration lacks Strict-Transport-Security directives.",
         "add_header Strict-Transport-Security \"max-age=31536000; includeSubDomains\" always;"),
        ("x-frame-options", "CWE-1021", "Missing Anti-Clickjacking Header", "MEDIUM",
         "HTTP responses allow frame rendering by third-party domains.",
         "add_header X-Frame-Options \"DENY\" always;"),
        ("x-content-type-options", "CWE-79", "Missing MIME-Sniffing Prevention", "LOW",
         "Browser can bypass declared Content-Type and sniff payloads.",
         "add_header X-Content-Type-Options \"nosniff\" always;"),
        ("content-security-policy", "CWE-693", "Missing Content Security Policy (CSP)", "HIGH",
         "No CSP policy defined; application vulnerable to XSS and unsafe script injection.",
         "add_header Content-Security-Policy \"default-src 'self'; script-src 'self'\";"),
        ("referrer-policy", "CWE-116", "Missing Referrer Policy Header", "LOW",
         "Referrer information leaked to external origins during navigation.",
         "add_header Referrer-Policy \"no-referrer-when-downgrade\" always;"),
    ];

    for (header, cwe, title, severity, root_cause, patch) in required_headers {
        if headers.contains_key(header) {
            report.headers_present.push(header.to_string());
        } else {
            report.headers_missing.push(header.to_string());
            report.findings.push(Finding {
                cwe,
                title,
                severity,
                description: format!("Header '{}' is missing from host response.", header),
                root_cause_code_error: root_cause,
                remediation_patch: patch,
            });
        }
    }
}

fn analyze_content(content: &str, report: &mut AnalysisReport) {
    let stack_trace_re = Regex::new(r"(?i)(stack trace:|at [a-zA-Z0-9_\.]+\([a-zA-Z0-9_\.]+\.rs:\d+|Traceback \(most recent call last\):|NullPointerException|panic at)").unwrap();
    if stack_trace_re.is_match(content) {
        report.findings.push(Finding {
            cwe: "CWE-209",
            title: "Verbose Error Message / Stack Trace Disclosure",
            severity: "HIGH",
            description: "Target endpoint returned raw code execution stack traces or unhandled error panics.".to_string(),
            root_cause_code_error: "Backend code unwraps Result/Option types directly without error handling middleware.",
            remediation_patch: "// Rust Axum / Actix fix:\napp.layer(CatchPanicLayer::new())",
        });
    }

    let secret_patterns = [
        (Regex::new(r"AKIA[0-9A-Z]{16}").unwrap(), "AWS Access Key ID"),
        (Regex::new(r"eyJ[a-zA-Z0-9_-]{10,}\.eyJ[a-zA-Z0-9_-]{10,}\.[a-zA-Z0-9_-]{10,}").unwrap(), "JWT Hardcoded Bearer Token"),
        (Regex::new(r"ghp_[a-zA-Z0-9]{36}").unwrap(), "GitHub Personal Access Token"),
        (Regex::new(r"sq0atp-[0-9a-zA-Z\-_]{22}").unwrap(), "Square Access Token"),
    ];

    for (re, secret_type) in secret_patterns {
        for cap in re.captures_iter(content) {
            let secret = cap[0].to_string();
            report.mined_secrets.insert(format!("{}: {}", secret_type, secret));
            report.findings.push(Finding {
                cwe: "CWE-798",
                title: "Hardcoded Credential / API Token Exposure",
                severity: "CRITICAL",
                description: format!("Discovered exposed secret ({}) in client-accessible bundle.", secret_type),
                root_cause_code_error: "Developer referenced sensitive environment variables directly in frontend code.",
                remediation_patch: "// Move tokens to server-side backend environment variables",
            });
        }
    }

    let route_re = Regex::new(r#"(?:"|')(/api/v[0-9]/[a-zA-Z0-9_/-]+|/v1/[a-zA-Z0-9_/-]+|/admin/[a-zA-Z0-9_/-]+|/wp-json/[a-zA-Z0-9_/-]+)(?:"|')"#).unwrap();
    for cap in route_re.captures_iter(content) {
        if let Some(matched) = cap.get(1) {
            report.mined_routes.insert(matched.as_str().to_string());
        }
    }
}

fn extract_js_urls(html: &str, base_url: &str) -> Vec<String> {
    let script_re = Regex::new(r#"(?i)<script[^>]+src=["']([^"']+)["']"#).unwrap();
    let mut js_urls = Vec::new();

    for cap in script_re.captures_iter(html) {
        if let Some(src) = cap.get(1) {
            let path = src.as_str();
            if path.starts_with("http://") || path.starts_with("https://") {
                js_urls.push(path.to_string());
            } else if path.starts_with('/') {
                js_urls.push(format!("{}{}", base_url.trim_end_matches('/'), path));
            } else {
                js_urls.push(format!("{}/{}", base_url.trim_end_matches('/'), path));
            }
        }
    }
    js_urls
}

async fn run_cms_and_rest_audit(client: &Client, base_url: &str, report: &mut AnalysisReport) {
    let clean_base = base_url.trim_end_matches('/');

    let wp_users_url = format!("{}/wp-json/wp/v2/users", clean_base);
    if let Ok(resp) = client.get(&wp_users_url).send().await {
        if resp.status().is_success() {
            if let Ok(body) = resp.text().await {
                if body.contains("\"slug\"") && body.contains("\"name\"") {
                    report.findings.push(Finding {
                        cwe: "CWE-200",
                        title: "WordPress REST API User Enumeration Enabled",
                        severity: "MEDIUM",
                        description: "The /wp-json/wp/v2/users endpoint is publicly accessible and leaks valid administrative usernames.".to_string(),
                        root_cause_code_error: "WordPress REST API permits unauthenticated queries to the user endpoint by default.",
                        remediation_patch: "// Add to functions.php:\nadd_filter('rest_endpoints', function($endpoints) {\n    if (isset($endpoints['/wp/v2/users'])) { unset($endpoints['/wp/v2/users']); }\n    if (isset($endpoints['/wp/v2/users/(?P<id>[\\d]+)'])) { unset($endpoints['/wp/v2/users/(?P<id>[\\d]+)']); }\n    return $endpoints;\n});",
                    });
                }
            }
        }
    }

    let xmlrpc_url = format!("{}/xmlrpc.php", clean_base);
    if let Ok(resp) = client.get(&xmlrpc_url).send().await {
        let status = resp.status();
        if status.as_u16() == 200 || status.as_u16() == 405 {
            report.findings.push(Finding {
                cwe: "CWE-400",
                title: "Exposed XML-RPC Gateway (xmlrpc.php)",
                severity: "MEDIUM",
                description: "XML-RPC interface is active and accessible. Automated bots abuse this for brute-force amplification and DDoS.".to_string(),
                root_cause_code_error: "WordPress XML-RPC interface remains active by default.",
                remediation_patch: "# Add to Nginx location block:\nlocation = /xmlrpc.php {\n    deny all;\n    return 404;\n}\n# Or add to functions.php: add_filter('xmlrpc_enabled', '__return_false');",
            });
        }
    }
}

async fn run_concurrency_race_audit(client: &Client, url: &str, report: &mut AnalysisReport) {
    let worker_count = 5;
    let barrier = Arc::new(Barrier::new(worker_count));
    let mut tasks = Vec::new();

    for _ in 0..worker_count {
        let c = client.clone();
        let u = url.to_string();
        let b = barrier.clone();
        tasks.push(tokio::spawn(async move {
            b.wait().await;
            c.get(&u).send().await
        }));
    }

    let mut status_codes = HashSet::new();
    for t in tasks {
        if let Ok(Ok(resp)) = t.await {
            status_codes.insert(resp.status().as_u16());
        }
    }

    if status_codes.len() > 1 {
        report.findings.push(Finding {
            cwe: "CWE-362",
            title: "Race Condition / Concurrent State Instability Detected",
            severity: "HIGH",
            description: format!("Concurrent burst requests yielded inconsistent status responses: {:?}", status_codes),
            root_cause_code_error: "Backend code suffers from non-atomic state mutated across concurrent requests.",
            remediation_patch: "// Rust fix: Use atomic structures or mutex locks:\nlet state = Arc::new(Mutex::new(shared_data));",
        });
    }
}

#[tokio::main]
async fn main() {
    apply_sandboxing();

    let args: Vec<String> = env::args().collect();
    if args.len() < 2 {
        println!("Usage: obsd_sec_engine <url_or_domain>");
        process::exit(1);
    }

    let raw_target = &args[1];
    let target_url = if !raw_target.starts_with("http://") && !raw_target.starts_with("https://") {
        format!("https://{}", raw_target)
    } else {
        raw_target.clone()
    };

    println!("============================================================");
    println!(" [obsd_sec_engine v0.7.0] Intelligent Root-Cause Vulnerability Analysis");
    println!(" Hardened Target: {}", target_url);
    println!(" Sandbox State: PLEDGE(stdio inet dns rpath) UNVEIL(/etc/ssl)");
    println!("============================================================\n");

    let client = Client::builder()
        .timeout(std::time::Duration::from_secs(5))
        .user_agent("obsd_sec_engine/0.7.0 (OpenBSD Hardened)")
        .build()
        .unwrap();

    let mut report = AnalysisReport::default();

    match client.get(&target_url).send().await {
        Ok(resp) => {
            let status = resp.status();
            println!("[+] Initial Target Status: {}", status);
            analyze_headers(resp.headers(), &mut report);

            match resp.text().await {
                Ok(html_body) => {
                    analyze_content(&html_body, &mut report);
                    let js_urls = extract_js_urls(&html_body, &target_url);
                    println!("[*] Discovered {} JavaScript bundles to analyze.", js_urls.len());

                    for js_url in js_urls {
                        if let Ok(js_resp) = client.get(&js_url).send().await {
                            if let Ok(js_body) = js_resp.text().await {
                                report.js_bundles_scanned += 1;
                                analyze_content(&js_body, &mut report);
                            }
                        }
                    }
                }
                Err(e) => eprintln!("[-] Error reading target body: {}", e),
            }
        }
        Err(e) => {
            eprintln!("[-] Target fetch failed: {}", e);
            process::exit(1);
        }
    }

    println!("[*] Running CMS & REST API Enumeration Heuristic Checks...");
    run_cms_and_rest_audit(&client, &target_url, &mut report).await;

    println!("[*] Running Tokio Concurrency Race & State Consistency Audit...");
    run_concurrency_race_audit(&client, &target_url, &mut report).await;

    println!("\n============================================================");
    println!(" INTELLIGENT TRIAGE & ROOT-CAUSE CODE DIAGNOSIS REPORT");
    println!("============================================================");

    println!("\n[+] JS Bundles Mined: {}", report.js_bundles_scanned);
    println!("[+] Mined Endpoints/Routes: {}", report.mined_routes.len());
    for route in &report.mined_routes {
        println!("    └── Route Discovered: {}", route);
    }

    println!("\n[+] Mined Secrets / Tokens: {}", report.mined_secrets.len());
    for secret in &report.mined_secrets {
        println!("    └── SECRET EXPOSED: {}", secret);
    }

    println!("\n[+] Security Headers Present: {}/5", report.headers_present.len());
    println!("[!] Security Headers Missing: {}/5", report.headers_missing.len());

    println!("\n------------------------------------------------------------");
    println!(" IDENTIFIED VULNERABILITIES & ROOT-CAUSE CODE FIXES");
    println!("------------------------------------------------------------");

    if report.findings.is_empty() {
        println!("  [✓] Zero high/medium vulnerability signatures identified.");
    } else {
        for (idx, finding) in report.findings.iter().enumerate() {
            println!("\n  [{}] {} ({}) - SEVERITY: {}", idx + 1, finding.title, finding.cwe, finding.severity);
            println!("      Description: {}", finding.description);
            println!("      ROOT-CAUSE CODE ERROR: {}", finding.root_cause_code_error);
            println!("      REMEDIATION CODE PATCH:");
            for line in finding.remediation_patch.lines() {
                println!("        {}", line);
            }
        }
    }

    println!("\n============================================================");
    println!(" Audit Complete. OpenBSD Process Terminated Cleanly.");
    println!("============================================================");
}
