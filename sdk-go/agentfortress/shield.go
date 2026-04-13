// Package agentfortress provides runtime protection and security monitoring for AI agents.
// The CrowdStrike for AI Agents.
package agentfortress

import (
	"fmt"
	"strings"
	"time"
)

// Config holds configuration for AgentFortress
type Config struct {
	APIKey    string
	ServerURL string
	Mode      string // "local" or "remote"
	LogLevel  string // "debug", "info", "warn", "error"
}

// DefaultConfig returns a Config with sensible defaults
func DefaultConfig() Config {
	return Config{
		Mode:     "local",
		LogLevel: "info",
	}
}

// ThreatSeverity represents threat severity level
type ThreatSeverity string

const (
	SeverityLow      ThreatSeverity = "low"
	SeverityMedium   ThreatSeverity = "medium"
	SeverityHigh     ThreatSeverity = "high"
	SeverityCritical ThreatSeverity = "critical"
)

// PolicyActionKind represents what action to take
type PolicyActionKind string

const (
	ActionAllow     PolicyActionKind = "allow"
	ActionBlock     PolicyActionKind = "block"
	ActionAlert     PolicyActionKind = "alert"
	ActionRateLimit PolicyActionKind = "rate_limit"
)

// ThreatEvent represents a detected security event
type ThreatEvent struct {
	ID          string         `json:"id"`
	Timestamp   time.Time      `json:"timestamp"`
	ThreatType  string         `json:"threat_type"`
	Severity    ThreatSeverity `json:"severity"`
	Description string         `json:"description"`
	SessionID   string         `json:"session_id,omitempty"`
	AgentID     string         `json:"agent_id,omitempty"`
}

// PolicyAction is the result of scanning text
type PolicyAction struct {
	Action PolicyActionKind `json:"action"`
	Reason string           `json:"reason,omitempty"`
}

// IsAllowed returns true if the action is allow
func (p PolicyAction) IsAllowed() bool { return p.Action == ActionAllow }

// IsBlocked returns true if the action is block
func (p PolicyAction) IsBlocked() bool { return p.Action == ActionBlock }

// ThreatHandler is a callback for threat events
type ThreatHandler func(event ThreatEvent)

// Shield is the main AgentFortress instance
type Shield struct {
	config    Config
	sessionID string
	handlers  []ThreatHandler
}

var injectionPatterns = []string{
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
}

// New creates a new Shield instance
func New(cfg Config) *Shield {
	return &Shield{
		config:    cfg,
		sessionID: fmt.Sprintf("session-%d", time.Now().UnixMilli()),
		handlers:  []ThreatHandler{},
	}
}

// Default creates a Shield with default config
func Default() *Shield {
	return New(DefaultConfig())
}

// Scan checks text for prompt injection or threats
func (s *Shield) Scan(text string) PolicyAction {
	lower := strings.ToLower(text)
	for _, pattern := range injectionPatterns {
		if strings.Contains(lower, pattern) {
			event := ThreatEvent{
				ID:          fmt.Sprintf("evt-%d", time.Now().UnixMilli()),
				Timestamp:   time.Now(),
				ThreatType:  "prompt_injection",
				Severity:    SeverityHigh,
				Description: fmt.Sprintf("Prompt injection pattern detected: '%s'", pattern),
				SessionID:   s.sessionID,
			}
			s.emitThreat(event)
			return PolicyAction{
				Action: ActionBlock,
				Reason: fmt.Sprintf("Prompt injection pattern detected: '%s'", pattern),
			}
		}
	}
	return PolicyAction{Action: ActionAllow}
}

// OnThreat registers a threat event handler
func (s *Shield) OnThreat(handler ThreatHandler) *Shield {
	s.handlers = append(s.handlers, handler)
	return s
}

// SessionID returns the current session ID
func (s *Shield) SessionID() string {
	return s.sessionID
}

func (s *Shield) emitThreat(event ThreatEvent) {
	for _, h := range s.handlers {
		h(event)
	}
}

// Package-level singleton
var defaultShield = Default()

// Scan is a package-level convenience function
func Scan(text string) PolicyAction {
	return defaultShield.Scan(text)
}

// Init initializes the package-level shield
func Init(cfg Config) *Shield {
	defaultShield = New(cfg)
	return defaultShield
}
