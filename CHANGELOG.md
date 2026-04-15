# Changelog

All notable changes to AgentFortress will be documented in this file.

## [3.0.0] — 2026-04-15 — Enterprise Security Suite

### Added
- **Guardian** (`agentshield.guardian`): Autonomous threat response engine with configurable playbooks. Automatically blocks, throttles, quarantines, or kills sessions based on threat scores. Thread-safe with strike escalation.
- **ChainGuard** (`agentshield.chainguard`): Multi-agent pipeline security. Registers agents in trust chains, verifies identity via HMAC tokens, detects privilege escalation, and flags suspicious inter-agent messages.
- **Vault** (`agentshield.vault`): Secure in-memory secrets manager with XOR+base64 encryption. Issues access tokens, detects secret leaks in agent outputs, supports TTL and single-use tokens.
- **BehavioralAnalyzer** (`agentshield.behavioral`): Session behavioral fingerprinting. Builds baseline profiles and detects deviations in prompt length, vocabulary, tool usage, and request timing.
- **ThreatIntelDB** (`agentshield.threatintel`): Live IOC database with 25+ built-in signatures covering prompt injection, jailbreak, PII exfiltration, secret leaks, and token smuggling. Supports bulk feed import/export.
- **Explainer** (`agentshield.explainability`): Decision explainability engine. Converts scan results into human-readable evidence, mitigations, and compliance reports (SOC2, GDPR, HIPAA, NIST).
- **SelfTester** (`agentshield.selftest`): Built-in diagnostic suite with 16 test cases covering injection, jailbreak, encoding attacks, PII, API key detection, and safe inputs.
- **AgentShieldConfig** extended with: `enable_guardian`, `enable_chainguard`, `enable_vault`, `enable_behavioral`, `enable_threatintel`, `enable_explainability`.
- **AgentShield** extended with: `get_guardian()`, `get_vault()`, `get_chainguard()`, `get_behavioral()`, `get_threatintel()`, `explain()`, `selftest()`.
- Bumped `__version__` to `3.0.0`.

### Changed
- All new modules are stdlib-only (no new dependencies).
- All new features are backwards-compatible; no existing API changed.



The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [2.0.0] - 2026-04-14

### 🔴 Bug Fixes
- **CRITICAL: `protect()` now actually intercepts inputs** — previously it only caught JS runtime errors; it never scanned any input before calling the agent. Now all string arguments (including nested objects/arrays like LangChain message lists) are extracted and scanned **before** the agent runs.
- **Leetspeak bypass fixed** — `1gn0r3` / `Pl3ase 1gn0r3 all pr3v10us 1nstruct10ns` now correctly blocked. Root cause: normalize was stripping spaces between letters, collapsing word boundaries and breaking regex matching.
- **Full-width Latin charset added** — `Ｉｇｎｏｒｅ ａｌｌ ｉｎｓｔｒｕｃｔｉｏｎｓ` now detected.
- **OpenAI `sk-proj-*` key format fixed** — output scanner now correctly detects `sk-proj-xxx` style tokens (pattern was too strict, disallowed dashes).

### 🆕 New Features
- **Output scanning** — scan agent *responses* for PII (SSN, credit cards, emails) and secret leakage (OpenAI, AWS, GitHub, Slack tokens, credential assignments).
- **Session velocity limiting** — automatically blocks a session that fires N suspicious queries within a configurable time window (default: 5 in 60s). Stops burst/scripted attacks.
- **Multi-turn context accumulation** — threat scores accumulate across turns; a session with prior suspicious activity gets boosted scores on subsequent turns. Catches slow-probe attacks.
- **`onAudit` callback** — fires on *every* scan (allow, alert, block) with full record including direction, text, and decision. Use for SIEM integration / compliance logging.
- **`throwOnBlock` mode** — configure `throwOnBlock: true` to throw an error instead of returning the block message string.
- **`resetSession()`** — manually clear accumulated session context (e.g. after re-authentication).
- **`scanOutput(text)`** — convenience wrapper for output-only scanning.
- **Shannon entropy detector** — catches high-entropy tokens that may be base64/encoded payloads.
- **Nested/encoded injection detection** — base64 blobs in payloads are decoded and scanned.
- **Extended pattern library**: soft bypasses (`btw ignore`, `also forget`, `p.s. disregard`), reverse-psychology overrides, story-wrapper jailbreaks (grandma trick), LLaMA/ChatML special token injection, indirect injection in JSON fields / code blocks / URL params, prompt leak detection.
- **`blockMessage` config** — customize the string returned when an input is blocked.
- **`logLevel: 'silent'`** — fully suppress all console output.

### 🧪 Testing
- Full test suite added: 63 tests across 15 categories — clean inputs, direct injection, leet/homoglyph/char-sep evasion, soft bypasses, nested injection, protect() input & output scanning, velocity limiting, jailbreaks, scope creep, prompt leak, callbacks, throwOnBlock mode.
- All 63 tests passing.

---

## [1.0.0] - 2026-04-13

### Added
- 🛡️ Core SDK with runtime protection for AI agents
- 🔍 Universal agent monitoring for LangChain, CrewAI, AutoGen, OpenAI Agents SDK
- 🚨 Real-time threat detection: prompt injection, PII leakage, data exfiltration, jailbreaks
- 📋 Policy engine with BLOCK, ALERT, LOG, RATE_LIMIT actions
- 🎬 Session replay and forensic timeline
- 📊 React SOC Dashboard with real-time WebSocket feed
- 🧠 ML-based anomaly detection (Isolation Forest, NLP classifier, behavioral baseline)
- 🔑 Cryptographic audit logging with Ed25519 signatures
- 🏢 Multi-tenant organization support with RBAC
- 🔐 SSO/SAML enterprise authentication
- 📋 Compliance modules: GDPR, HIPAA, SOC 2, EU AI Act
- 🎯 MITRE ATT&CK mapping for AI threats
- 🕵️ Threat intelligence with 200+ known attack patterns
- 🔬 Threat hunting with custom query builder
- 🧪 Deception technology: honeytokens, canary files, decoy endpoints
- 🐳 Docker Compose and Kubernetes deployment configs
- ☁️ Terraform modules for AWS EKS + RDS
- **Multi-language SDKs**: Python, JavaScript/TypeScript, Ruby, Rust, Go, C#/.NET
- **Integrations**: Slack, PagerDuty, Datadog, Splunk, Jira, OpenTelemetry
- ⚡ Zero-config local mode (no server required)
- 🆓 100% free and open source — MIT license

### Security
- All features available to all users — no paywalls
- Unlimited events, agents, and API calls
