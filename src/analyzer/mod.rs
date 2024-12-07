use crate::error::Result;
use crate::model::{FirewallEvent, RulesetInfo};
use crate::output::OutputFormatter;
use crate::{AnalysisResult, CLOUDFLARE_RULESET_ID, LEAKED_CREDS_RULESET_ID, OWASP_RULESET_ID};
use std::collections::{HashMap, HashSet};
use std::fs::File;
use std::io::BufReader;
use std::path::Path;

// Type aliases for better readability and maintenance
type RulesetMap = HashMap<String, HashMap<String, i32>>;
type CountMap = HashMap<String, i32>;

pub struct FirewallAnalyzer {
    ruleset_mappings: HashMap<String, RulesetInfo>,
}

impl Default for FirewallAnalyzer {
    fn default() -> Self {
        Self::new()
    }
}

impl FirewallAnalyzer {
    pub fn new() -> Self {
        Self {
            ruleset_mappings: Self::initialize_ruleset_mappings(),
        }
    }

    fn initialize_ruleset_mappings() -> HashMap<String, RulesetInfo> {
        [
            (
                CLOUDFLARE_RULESET_ID.to_string(),
                RulesetInfo::new("Cloudflare Rules", colored::Color::Blue),
            ),
            (
                OWASP_RULESET_ID.to_string(),
                RulesetInfo::new("OWASP Rules", colored::Color::Green),
            ),
            (
                LEAKED_CREDS_RULESET_ID.to_string(),
                RulesetInfo::new("Leaked Credentials Rules", colored::Color::Red),
            ),
        ]
        .into_iter()
        .collect()
    }

    pub fn analyze_file<P: AsRef<Path>>(&self, path: P, format: String) -> Result<()> {
        let events = self.load_events(path)?;
        let analysis = self.analyze_events(&events);
        self.output_analysis(analysis, &format)
    }

    fn load_events<P: AsRef<Path>>(&self, path: P) -> Result<Vec<FirewallEvent>> {
        let file = File::open(path)?;
        let reader = BufReader::new(file);
        Ok(serde_json::from_reader(reader)?)
    }

    fn output_analysis(&self, analysis: AnalysisResult, format: &str) -> Result<()> {
        let formatter = OutputFormatter::new(format);
        formatter.output(analysis)
    }

    fn analyze_events(&self, events: &[FirewallEvent]) -> AnalysisResult {
        EventAnalyzer::new(events).analyze()
    }

    #[cfg(test)]
    pub fn get_ruleset_info(&self, ruleset_id: &str) -> Option<&RulesetInfo> {
        self.ruleset_mappings.get(ruleset_id)
    }
}

struct EventAnalyzer<'a> {
    events: &'a [FirewallEvent],
    ruleset_rules: RulesetMap,
    endpoints: CountMap,
    paths: CountMap,
    http_methods: CountMap,
    unique_hosts: HashSet<String>,
}

impl<'a> EventAnalyzer<'a> {
    fn new(events: &'a [FirewallEvent]) -> Self {
        Self {
            events,
            ruleset_rules: HashMap::new(),
            endpoints: HashMap::new(),
            paths: HashMap::new(),
            http_methods: HashMap::new(),
            unique_hosts: HashSet::new(),
        }
    }

    fn analyze(mut self) -> AnalysisResult {
        for event in self.events {
            self.process_event(event);
        }

        self.build_result()
    }

    fn process_event(&mut self, event: &FirewallEvent) {
        self.update_ruleset_rules(event);
        self.update_endpoints(event);
        self.update_paths(event);
        self.update_http_methods(event);
    }

    fn update_ruleset_rules(&mut self, event: &FirewallEvent) {
        let rule_counts = self
            .ruleset_rules
            .entry(event.ruleset_id.clone())
            .or_default();
        *rule_counts.entry(event.rule_id.clone()).or_default() += 1;
    }

    fn update_endpoints(&mut self, event: &FirewallEvent) {
        *self
            .endpoints
            .entry(event.client_request_http_host.clone())
            .or_default() += 1;
        self.unique_hosts
            .insert(event.client_request_http_host.clone());
    }

    fn update_paths(&mut self, event: &FirewallEvent) {
        *self
            .paths
            .entry(event.client_request_path.clone())
            .or_default() += 1;
    }

    fn update_http_methods(&mut self, event: &FirewallEvent) {
        *self
            .http_methods
            .entry(event.client_request_http_method_name.clone())
            .or_default() += 1;
    }

    fn build_result(self) -> AnalysisResult {
        AnalysisResult {
            total_events: self.events.len(),
            ruleset_rules: self.ruleset_rules,
            endpoints: self.endpoints,
            paths: self.paths,
            http_methods: self.http_methods,
            unique_hosts: self.unique_hosts.len(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // Move test helpers to a separate module
    mod test_helpers {
        use super::*;

        pub fn create_test_event(
            ruleset_id: &str,
            rule_id: &str,
            host: &str,
            path: &str,
            method: &str,
        ) -> FirewallEvent {
            FirewallEvent {
                action: "log".to_string(),
                client_asn_description: "Test ASN".to_string(),
                client_asn: "12345".to_string(),
                client_country_name: "Test Country".to_string(),
                client_ip: "127.0.0.1".to_string(),
                client_request_http_host: host.to_string(),
                client_request_http_method_name: method.to_string(),
                client_request_http_protocol: "HTTP/1.1".to_string(),
                client_request_path: path.to_string(),
                client_request_query: "".to_string(),
                datetime: "2024-12-07T15:11:24Z".to_string(),
                ref_id: "test-ref".to_string(),
                ray_name: "test-ray".to_string(),
                rule_id: rule_id.to_string(),
                ruleset_id: ruleset_id.to_string(),
                source: "test".to_string(),
                user_agent: "".to_string(),
                match_index: 0,
                metadata: vec![],
                sample_interval: 1,
            }
        }
    }

    #[test]
    fn test_analyze_events() {
        use test_helpers::create_test_event;

        let analyzer = FirewallAnalyzer::new();
        let events = vec![
            create_test_event(
                CLOUDFLARE_RULESET_ID,
                "rule1",
                "host1.example.com",
                "/path1",
                "GET",
            ),
            create_test_event(
                CLOUDFLARE_RULESET_ID,
                "rule1",
                "host1.example.com",
                "/path2",
                "POST",
            ),
            create_test_event(
                OWASP_RULESET_ID,
                "rule2",
                "host2.example.com",
                "/path1",
                "GET",
            ),
        ];

        let result = analyzer.analyze_events(&events);

        assert_eq!(result.total_events, 3);
        assert_eq!(result.unique_hosts, 2);
        assert_eq!(result.ruleset_rules[CLOUDFLARE_RULESET_ID]["rule1"], 2);
        assert_eq!(result.ruleset_rules[OWASP_RULESET_ID]["rule2"], 1);
        assert_eq!(result.endpoints["host1.example.com"], 2);
        assert_eq!(result.endpoints["host2.example.com"], 1);
        assert_eq!(result.paths["/path1"], 2);
        assert_eq!(result.paths["/path2"], 1);
        assert_eq!(result.http_methods["GET"], 2);
        assert_eq!(result.http_methods["POST"], 1);
    }
}
