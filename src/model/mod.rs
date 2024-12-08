use serde::{Deserialize, Serialize};
use std::collections::HashMap;

#[derive(Debug, Serialize, Deserialize)]
pub struct FirewallEvent {
    pub action: String,
    #[serde(rename = "clientASNDescription")]
    pub client_asn_description: String,
    #[serde(rename = "clientAsn")]
    pub client_asn: String,
    #[serde(rename = "clientCountryName")]
    pub client_country_name: String,
    #[serde(rename = "clientIP")]
    pub client_ip: String,
    #[serde(rename = "clientRequestHTTPHost")]
    pub client_request_http_host: String,
    #[serde(rename = "clientRequestHTTPMethodName")]
    pub client_request_http_method_name: String,
    #[serde(rename = "clientRequestHTTPProtocol")]
    pub client_request_http_protocol: String,
    #[serde(rename = "clientRequestPath")]
    pub client_request_path: String,
    #[serde(rename = "clientRequestQuery")]
    pub client_request_query: String,
    pub datetime: String,
    #[serde(rename = "ref")]
    pub ref_id: String,
    #[serde(rename = "rayName")]
    pub ray_name: String,
    #[serde(rename = "ruleId")]
    pub rule_id: String,
    #[serde(rename = "rulesetId")]
    pub ruleset_id: String,
    pub source: String,
    #[serde(rename = "userAgent")]
    pub user_agent: String,
    #[serde(rename = "matchIndex")]
    pub match_index: i32,
    pub metadata: Vec<Metadata>,
    #[serde(rename = "sampleInterval")]
    pub sample_interval: i32,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct Metadata {
    pub key: String,
    pub value: String,
}

#[derive(Debug, Clone)]
pub struct RulesetInfo {
    pub name: String,
    pub color: colored::Color,
}

impl RulesetInfo {
    pub fn new(name: &str, color: colored::Color) -> Self {
        Self {
            name: name.to_string(),
            color,
        }
    }
}

#[derive(Debug)]
pub struct AnalysisResult {
    pub total_events: usize,
    /// RuleID -> Rule ID -> Count
    pub ruleset_rules: HashMap<String, HashMap<String, i32>>,
    pub endpoints: HashMap<String, i32>,
    pub paths: HashMap<String, i32>,
    pub http_methods: HashMap<String, i32>,
    pub unique_hosts: usize,
}
