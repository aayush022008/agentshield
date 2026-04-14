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

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuditRecord {
    pub timestamp: u64,
    pub session_id: String,
    pub agent_id: Option<String>,
    pub direction: String,
    pub text: String,
    pub action: String,
    pub score: f64,
    pub reason: String,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub enum ThreatSeverity { Low, Medium, High, Critical }

#[derive(Debug, Clone)]
pub struct PolicyAction {
    pub action: PolicyActionKind,
    pub reason: Option<String>,
    pub score: f64,
}

#[derive(Debug, Clone, PartialEq)]
pub enum PolicyActionKind { Allow, Block, Alert, RateLimit }

