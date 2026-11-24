use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Finding {
    pub cwe: String,
    pub title: String,
    pub severity: String,
    pub description: String,
    pub fix_patch: String,
    pub curl_poc: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MinedSecret {
    pub secret_type: String,
    pub value: String,
    pub is_active_live: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CloudFingerprint {
    pub provider: &'static str,
    pub cname_keyword: &'static str,
    pub signature_body: &'static str,
    pub severity: &'static str,
}

#[derive(Debug, Default, Serialize, Deserialize)]
pub struct AnalysisReport {
    pub target_url: String,
    pub findings: Vec<Finding>,
    pub mined_secrets: Vec<MinedSecret>,
    pub proxy_bypasses: Vec<String>,
    pub mined_routes: Vec<String>,
    pub mined_parameters: Vec<String>,
    pub js_bundles_scanned: usize,
    pub headers_present: Vec<String>,
    pub headers_missing: Vec<String>,
}
