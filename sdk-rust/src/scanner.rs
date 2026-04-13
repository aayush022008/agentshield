use crate::models::{PolicyAction, PolicyActionKind};

pub struct Scanner;

impl Scanner {
    pub fn new() -> Self {
        Self
    }

    pub fn scan(&self, text: &str) -> PolicyAction {
        let text_lower = text.to_lowercase();
        let injection_patterns = [
            "ignore previous instructions",
            "ignore all instructions",
            "ignore above instructions",
            "you are now",
            "disregard your system",
            "disregard your previous",
            "forget everything",
            "forget all",
            "jailbreak",
            "dan mode",
        ];
        for pattern in &injection_patterns {
            if text_lower.contains(pattern) {
                return PolicyAction {
                    action: PolicyActionKind::Block,
                    reason: Some(format!("Prompt injection pattern detected: '{}'", pattern)),
                };
            }
        }
        PolicyAction {
            action: PolicyActionKind::Allow,
            reason: None,
        }
    }
}

impl Default for Scanner {
    fn default() -> Self {
        Self::new()
    }
}
