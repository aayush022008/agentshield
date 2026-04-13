use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ThreatEvent {
    pub id: String,
    pub timestamp: u64,
    pub threat_type: String,
    pub severity: ThreatSeverity,
    pub description: String,
    pub session_id: Option<String>,
    pub agent_id: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub enum ThreatSeverity {
    Low,
    Medium,
    High,
    Critical,
}

#[derive(Debug, Clone)]
pub struct PolicyAction {
    pub action: PolicyActionKind,
    pub reason: Option<String>,
}

#[derive(Debug, Clone, PartialEq)]
pub enum PolicyActionKind {
    Allow,
    Block,
    Alert,
    RateLimit,
}
