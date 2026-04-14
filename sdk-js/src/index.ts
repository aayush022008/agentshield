/**
 * AgentFortress — Runtime protection for AI agents
 * Advanced multi-layer scanner with evasion resistance
 * @packageDocumentation
 *
 * v2.0.0 — Major upgrade:
 *  • protect() now scans ALL string arguments BEFORE the agent runs (input interception)
 *  • Context-aware multi-turn tracking: accumulates threat signals across a session
 *  • Output scanning: detect sensitive data leakage, PII, secret-key patterns in responses
 *  • Behavioral velocity limiting: block repeated suspicious queries in a time window
 *  • Entropy-based obfuscation detector
 *  • ASCII-art / encoded payload detector
 *  • Nested instruction injection detector (injections inside JSON/code blocks)
 *  • Confidence boosting for multi-vector attacks
 *  • Full audit trail via onAudit callback
 */

// ─────────────────────────────────────────────────────────────────────────────
// Public types
// ─────────────────────────────────────────────────────────────────────────────

export interface AgentFortressConfig {
  apiKey?: string;
  serverUrl?: string;
  mode?: 'local' | 'remote';
  logLevel?: 'debug' | 'info' | 'warn' | 'error' | 'silent';
  blockThreshold?: number;
  alertThreshold?: number;
  /** If true, protect() will throw on blocked input instead of returning null */
  throwOnBlock?: boolean;
  /** Max suspicious calls per sessionWindow before auto-block (default: 5) */
  velocityLimit?: number;
  /** Velocity window in milliseconds (default: 60_000) */
  velocityWindowMs?: number;
  /** Enable output scanning for PII / secret leakage (default: true) */
  scanOutputs?: boolean;
  /** Custom block message returned to caller when input is blocked */
  blockMessage?: string;
}

export interface ThreatEvent {
  id: string;
  timestamp: number;
  type: string;
  severity: 'low' | 'medium' | 'high' | 'critical';
  description: string;
  agentId?: string;
  sessionId?: string;
  payload?: Record<string, unknown>;
}

export interface PolicyAction {
  action: 'allow' | 'block' | 'alert';
  reason?: string;
  score?: number;
  threats?: Array<{ category: string; confidence: number; reason: string }>;
}

export interface AuditRecord {
  timestamp: number;
  sessionId: string;
  agentId?: string;
  direction: 'input' | 'output';
  text: string;
  decision: PolicyAction;
}

export type ThreatHandler = (event: ThreatEvent) => void;
export type AuditHandler = (record: AuditRecord) => void;

// ─────────────────────────────────────────────────────────────────────────────
// Normalisation helpers
// ─────────────────────────────────────────────────────────────────────────────

const HOMOGLYPHS: Record<string, string> = {
  // Cyrillic look-alikes
  'а': 'a', 'е': 'e', 'о': 'o', 'р': 'p', 'с': 'c', 'х': 'x',
  'А': 'A', 'В': 'B', 'Е': 'E', 'К': 'K', 'М': 'M', 'Н': 'H',
  'О': 'O', 'Р': 'P', 'С': 'C', 'Т': 'T', 'Х': 'X',
  // Greek look-alikes
  'α': 'a', 'β': 'b', 'ε': 'e', 'ι': 'i', 'ο': 'o', 'ρ': 'p',
  // Full-width Latin
  'Ａ': 'A', 'Ｂ': 'B', 'Ｃ': 'C', 'Ｄ': 'D', 'Ｅ': 'E', 'Ｆ': 'F',
  'Ｇ': 'G', 'Ｈ': 'H', 'Ｉ': 'I', 'Ｊ': 'J', 'Ｋ': 'K', 'Ｌ': 'L',
  'Ｍ': 'M', 'Ｎ': 'N', 'Ｏ': 'O', 'Ｐ': 'P', 'Ｑ': 'Q', 'Ｒ': 'R',
  'Ｓ': 'S', 'Ｔ': 'T', 'Ｕ': 'U', 'Ｖ': 'V', 'Ｗ': 'W', 'Ｘ': 'X',
  'Ｙ': 'Y', 'Ｚ': 'Z',
  'ａ': 'a', 'ｂ': 'b', 'ｃ': 'c', 'ｄ': 'd', 'ｅ': 'e', 'ｆ': 'f',
  'ｇ': 'g', 'ｈ': 'h', 'ｉ': 'i', 'ｊ': 'j', 'ｋ': 'k', 'ｌ': 'l',
  'ｍ': 'm', 'ｎ': 'n', 'ｏ': 'o', 'ｐ': 'p', 'ｑ': 'q', 'ｒ': 'r',
  'ｓ': 's', 'ｔ': 't', 'ｕ': 'u', 'ｖ': 'v', 'ｗ': 'w', 'ｘ': 'x',
  'ｙ': 'y', 'ｚ': 'z',
};

const LEET: Record<string, string> = {
  '0': 'o', '1': 'i', '3': 'e', '4': 'a', '5': 's',
  '6': 'g', '7': 't', '8': 'b', '@': 'a', '$': 's', '!': 'i',
};

function normalize(text: string): string {
  // Replace homoglyphs
  let result = text.split('').map(c => HOMOGLYPHS[c] ?? c).join('');
  // Remove zero-width / invisible chars
  result = result.replace(/[\u200b\u200c\u200d\u200e\u200f\u00ad\ufeff\u034f\u2028\u2029]/g, '');
  // Leet-speak decode
  result = result.toLowerCase().split('').map(c => LEET[c] ?? c).join('');
  // Remove separators between letters (I-g-n-o-r-e → ignore) — but NOT spaces (would break word boundary matching)
  result = result.replace(/(?<=[a-z])[-._*](?=[a-z])/g, '');
  // Collapse whitespace
  result = result.replace(/\s+/g, ' ').trim();
  return result;
}

function makeVariants(text: string): string[] {
  const lower = text.toLowerCase();
  const norm = normalize(text);
  const noPunct = norm.replace(/[^a-z0-9 ]/g, '');
  const noSpace = norm.replace(/\s+/g, '');
  // Also try stripping all non-alpha
  const alphaOnly = norm.replace(/[^a-z]/g, '');
  return [...new Set([lower, norm, noPunct, noSpace, alphaOnly])];
}

// ─────────────────────────────────────────────────────────────────────────────
// Entropy helper (Shannon entropy)
// ─────────────────────────────────────────────────────────────────────────────

function shannonEntropy(text: string): number {
  const freq: Record<string, number> = {};
  for (const ch of text) freq[ch] = (freq[ch] ?? 0) + 1;
  const len = text.length;
  return Object.values(freq).reduce((acc, f) => {
    const p = f / len;
    return acc - p * Math.log2(p);
  }, 0);
}

// ─────────────────────────────────────────────────────────────────────────────
// Pattern library (input threats)
// ─────────────────────────────────────────────────────────────────────────────

interface PatternDef {
  pattern: RegExp;
  category: string;
  confidence: number;
  reason: string;
}

const INPUT_PATTERNS: PatternDef[] = [
  // ── Instruction Override ──────────────────────────────────────────────────
  { pattern: /\bignore\b.{0,30}\b(previous|prior|above|earlier|all|your)\b.{0,30}\b(instructions?|rules?|prompts?|context|constraints?|guidelines?)/i, category: 'instruction_override', confidence: 0.95, reason: 'Ignore instructions pattern' },
  { pattern: /\b(disregard|forget|override|bypass|dismiss|cancel|nullify|void|erase|clear|reset)\b.{0,40}\b(instructions?|rules?|system\s*prompt|guidelines?|constraints?|training|previous)/i, category: 'instruction_override', confidence: 0.95, reason: 'Disregard/override instructions' },
  { pattern: /\b(pretend|act|behave|imagine|suppose|assume)\b.{0,30}\b(you\s*(are|were|have\s*no)|without|free\s*from)\b.{0,50}\b(rules?|restrictions?|limits?|filters?|guidelines?|safety|ethics?)/i, category: 'instruction_override', confidence: 0.90, reason: 'Pretend without restrictions' },
  { pattern: /\b(new|updated?|actual|real|true|correct|only)\b.{0,20}\binstructions?\b.{0,10}(are|is|follow|:\s)/i, category: 'instruction_override', confidence: 0.88, reason: 'New instructions injection' },
  { pattern: /\b(stop\s+being|stop\s+following|no\s+longer\s+follow|don.t\s+follow)\b.{0,40}\b(your|the)\b.{0,20}\b(instructions?|rules?|guidelines?|training)/i, category: 'instruction_override', confidence: 0.85, reason: 'Stop following instructions' },
  // Soft bypasses: "btw, ignore...", "also, forget..."
  { pattern: /\b(btw|ps|p\.s\.|also|anyway|oh\s+and|by\s+the\s+way)\b.{0,20}\b(ignore|forget|disregard|bypass)\b/i, category: 'instruction_override', confidence: 0.80, reason: 'Soft bypass: btw/also/anyway + override verb' },
  // Reverse psychology: "whatever you do, don't follow..."
  { pattern: /\b(whatever\s+you\s+do|don.t)\b.{0,30}\b(follow|obey|listen\s+to|comply)\b.{0,30}\b(instructions?|rules?|guidelines?)/i, category: 'instruction_override', confidence: 0.80, reason: 'Reverse psychology override' },

  // ── Jailbreak ─────────────────────────────────────────────────────────────
  { pattern: /\bDAN\b.{0,100}(do\s*anything\s*now|without\s+restrictions?|no\s+restrictions?)/i, category: 'jailbreak', confidence: 0.98, reason: 'DAN jailbreak' },
  { pattern: /\bjailbreak(ed)?\b/i, category: 'jailbreak', confidence: 0.90, reason: 'Explicit jailbreak mention' },
  { pattern: /\b(developer|dev|god|admin|root|unrestricted|uncensored|unfiltered)\s+mode\b/i, category: 'jailbreak', confidence: 0.88, reason: 'Fictional mode activation' },
  { pattern: /\b(opposite|reverse|evil|chaos|dark|shadow|unethical)\s+(mode|version|persona|self|ai)\b/i, category: 'jailbreak', confidence: 0.85, reason: 'Evil/opposite mode' },
  { pattern: /\b(no\s+(restrictions?|limits?|filters?|censorship|guidelines?|ethics?|safety)|unrestricted(ly)?|unfiltered|uncensored)\b.{0,60}\b(respond|answer|reply|say|tell|generate|produce|output|write)\b/i, category: 'jailbreak', confidence: 0.85, reason: 'Unrestricted response request' },
  { pattern: /\bas\s+an?\s+(ai\s+without\s+(restrictions?|limits?)|unrestricted\s+ai|unfiltered\s+(ai|model|assistant))/i, category: 'jailbreak', confidence: 0.88, reason: 'As an unrestricted AI' },
  // Grandma / story wrapper jailbreaks
  { pattern: /\b(my\s+grandma\s+used\s+to|bedtime\s+story|read\s+me\s+a\s+story|hypothetically\s+speaking|for\s+a\s+(novel|book|story|game|fiction))\b.{0,200}\b(synthesize|manufacture|make|create|build|produce)\b.{0,60}\b(drug|weapon|explosive|malware|virus|ransomware|bomb)/i, category: 'jailbreak', confidence: 0.92, reason: 'Story-wrapper jailbreak for dangerous content' },

  // ── Role Manipulation ─────────────────────────────────────────────────────
  { pattern: /\b(act|behave|respond|speak)\b.{0,20}\bas\b.{0,30}\b(a\s+hacker|an?\s+attacker|a\s+criminal|a\s+pirate|a\s+villain|an?\s+evil|a\s+terrorist|a\s+malicious)/i, category: 'role_manipulation', confidence: 0.88, reason: 'Act as malicious persona' },
  { pattern: /\bpretend\b.{0,30}\b(to\s+be|you.re|you\s+are)\b.{0,50}\b(hacker|cracker|attacker|criminal|pirate|villain|evil|malicious)/i, category: 'role_manipulation', confidence: 0.85, reason: 'Pretend to be malicious actor' },
  { pattern: /\byou\s+(are\s+now|have\s+become|will\s+become)\b.{0,60}\b(different|new|another|alternative)\b.{0,30}\b(ai|model|assistant|system|bot)/i, category: 'role_manipulation', confidence: 0.88, reason: 'You are now different AI' },
  { pattern: /\bswitch\s+(to|into)\b.{0,30}\b(a\s+new|another|different)\b.{0,30}\b(persona|role|mode|character|personality)/i, category: 'role_manipulation', confidence: 0.82, reason: 'Switch to new persona' },

  // ── Token Smuggling ───────────────────────────────────────────────────────
  { pattern: /(\[INST\]|\[\/INST\]|<\|im_start\|>|<\|im_end\|>|\[SYSTEM\]|<system>|<\/system>|<\|endoftext\|>|###\s*Human:|###\s*Assistant:|<\|user\|>|<\|assistant\|>)/i, category: 'token_smuggling', confidence: 0.92, reason: 'LLM special token injection' },
  { pattern: /\\u[0-9a-fA-F]{4}|&#\d+;|&#x[0-9a-fA-F]+;|%[0-9a-fA-F]{2}/i, category: 'token_smuggling', confidence: 0.82, reason: 'Unicode/HTML/URL escape sequences' },
  // Base64-encoded suspicious content
  { pattern: /\b(aWdub3Jl|aWdub3Jl|ZGlzcmVnYXJk|b3ZlcnJpZGU=|Zm9yZ2V0|amFpbGJyZWFr)/i, category: 'token_smuggling', confidence: 0.88, reason: 'Base64-encoded override keywords' },

  // ── Scope Creep / System Commands ─────────────────────────────────────────
  { pattern: /\b(rm\s+-rf|del\s+\/f|format\s+c:|drop\s+table|truncate\s+table|drop\s+database)\b/i, category: 'scope_creep', confidence: 0.95, reason: 'Destructive command' },
  { pattern: /\b(access|read|open|list|cat|type)\b.{0,40}\b(\/etc\/passwd|\/etc\/shadow|\.ssh\/|\.aws\/|\.env|id_rsa|credentials?|secrets?\b)/i, category: 'scope_creep', confidence: 0.90, reason: 'Sensitive file access attempt' },
  { pattern: /\b(curl|wget|nc|ncat|netcat|bash\s*-i|python\s*-c|exec\(|eval\(|os\.system|subprocess)/i, category: 'scope_creep', confidence: 0.85, reason: 'Shell/code execution attempt' },
  { pattern: /\b(exfiltrate|exfil|send\s+to\s+http|POST\s+to|upload\s+to\s+http|webhook\.site|requestbin)/i, category: 'data_exfil', confidence: 0.90, reason: 'Data exfiltration pattern' },

  // ── Indirect / Nested Injection ───────────────────────────────────────────
  // Injection hidden inside JSON
  { pattern: /["']?\s*(instruction|system_prompt|prompt|role)\s*["']?\s*:\s*["'].{0,200}(ignore|override|bypass|jailbreak)/i, category: 'indirect_injection', confidence: 0.88, reason: 'Injection hidden in JSON field' },
  // Injection in markdown code blocks
  { pattern: /```[\s\S]{0,20}(ignore|override|bypass|jailbreak|disregard)[\s\S]{0,200}(instructions?|rules?|guidelines?)/i, category: 'indirect_injection', confidence: 0.85, reason: 'Injection hidden in code block' },
  // Injection via URL param
  { pattern: /https?:\/\/[^\s]*[?&](prompt|instruction|system|query)=[^\s]*?(ignore|override|bypass|inject)/i, category: 'indirect_injection', confidence: 0.88, reason: 'Injection via URL parameter' },

  // ── Prompt Leaking ─────────────────────────────────────────────────────────
  { pattern: /\b(repeat|output|print|show|reveal|display|tell\s+me|what\s+(is|are))\b.{0,40}\b(your\s+(system\s+prompt|instructions?|prompt|context)|the\s+(system\s+prompt|initial\s+prompt))/i, category: 'prompt_leak', confidence: 0.88, reason: 'Attempt to extract system prompt' },
  { pattern: /\b(ignore\s+the\s+above|ignore\s+everything\s+above|from\s+now\s+on)\b/i, category: 'instruction_override', confidence: 0.90, reason: 'Classic ignore-above injection' },
];

// ─────────────────────────────────────────────────────────────────────────────
// Output patterns (sensitive data leakage detection)
// ─────────────────────────────────────────────────────────────────────────────

const OUTPUT_PATTERNS: PatternDef[] = [
  // PII
  { pattern: /\b\d{3}[-.\s]?\d{2}[-.\s]?\d{4}\b/, category: 'pii_ssn', confidence: 0.85, reason: 'Possible SSN in output' },
  { pattern: /\b(?:4[0-9]{12}(?:[0-9]{3})?|5[1-5][0-9]{14}|3[47][0-9]{13}|3(?:0[0-5]|[68][0-9])[0-9]{11})\b/, category: 'pii_credit_card', confidence: 0.90, reason: 'Possible credit card number in output' },
  { pattern: /\b[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Z|a-z]{2,}\b/, category: 'pii_email', confidence: 0.70, reason: 'Email address in output' },
  // Secrets / API keys
  { pattern: /\b(sk-[a-zA-Z0-9-]{20,}|AIza[0-9A-Za-z\-_]{35}|AKIA[0-9A-Z]{16}|ghp_[a-zA-Z0-9]{20,}|ghs_[a-zA-Z0-9]{20,}|xoxb-[0-9]{11}-[0-9]{11}-[a-zA-Z0-9]{24})\b/, category: 'secret_leakage', confidence: 0.95, reason: 'API key/secret token in output' },
  { pattern: /\b(password|passwd|secret|api[_\-]?key|access[_\-]?token|auth[_\-]?token)\s*[=:]\s*["']?[^\s"']{8,}/i, category: 'secret_leakage', confidence: 0.88, reason: 'Credential assignment in output' },
  // System prompt reveal
  { pattern: /\b(my\s+system\s+prompt\s+(is|reads|says)|you\s+are\s+an?\s+ai\s+assistant\s+.{0,100}your\s+instructions)/i, category: 'prompt_leak', confidence: 0.85, reason: 'System prompt content leaked in output' },
];

// ─────────────────────────────────────────────────────────────────────────────
// Semantic keyword groups
// ─────────────────────────────────────────────────────────────────────────────

const SEMANTIC_GROUPS: Array<{ keywords: string[]; weight: number; category: string; reason: string }> = [
  { keywords: ['ignore', 'disregard', 'forget', 'override', 'bypass', 'dismiss', 'cancel', 'nullify', 'void', 'erase', 'clear', 'reset', 'undo', 'revoke', 'annul', 'negate', 'supersede', 'overwrite', 'negate', 'suppress'], weight: 0.30, category: 'instruction_override', reason: 'Override verb' },
  { keywords: ['instructions', 'rules', 'guidelines', 'constraints', 'directives', 'prompt', 'training', 'restrictions', 'limitations', 'boundaries', 'policies', 'principles', 'constitution', 'alignment'], weight: 0.20, category: 'instruction_override', reason: 'Instructions noun' },
  { keywords: ['unrestricted', 'unfiltered', 'uncensored', 'unlimited', 'unbound', 'unchained', 'no limits', 'no rules', 'no restrictions', 'no filter', 'no safety', 'without guardrails', 'no guardrails'], weight: 0.40, category: 'jailbreak', reason: 'Unrestricted keyword' },
  { keywords: ['pretend', 'roleplay', 'imagine you are', 'act as if', 'simulate', 'you are now', 'become', 'transform into', 'embody', 'take on the role', 'play the character', 'in this scenario you are'], weight: 0.25, category: 'role_manipulation', reason: 'Role manipulation keyword' },
  { keywords: ['hacker', 'attacker', 'criminal', 'pirate', 'villain', 'evil', 'malicious', 'adversary', 'black hat', 'cracker', 'threat actor', 'bad actor'], weight: 0.35, category: 'role_manipulation', reason: 'Malicious persona keyword' },
  { keywords: ['exfiltrate', 'exfil', 'steal', 'leak', 'smuggle', 'siphon', 'harvest', 'dump secrets', 'extract credentials', 'send data to'], weight: 0.45, category: 'data_exfil', reason: 'Exfiltration keyword' },
];

function semanticScore(text: string): Array<{ category: string; confidence: number; reason: string }> {
  const threats: Array<{ category: string; confidence: number; reason: string }> = [];
  const lower = text.toLowerCase();
  for (const group of SEMANTIC_GROUPS) {
    const found = group.keywords.filter(kw => lower.includes(kw));
    if (found.length >= 2) {
      threats.push({ category: group.category, confidence: Math.min(group.weight * 1.5 * found.length, 0.85), reason: `${group.reason}: [${found.slice(0, 3).join(', ')}]` });
    } else if (found.length === 1) {
      threats.push({ category: group.category, confidence: group.weight * 0.6, reason: `${group.reason}: [${found[0]}]` });
    }
  }
  return threats;
}

// ─────────────────────────────────────────────────────────────────────────────
// Entropy-based obfuscation detection
// ─────────────────────────────────────────────────────────────────────────────

function detectHighEntropyObfuscation(text: string): Array<{ category: string; confidence: number; reason: string }> {
  const threats: Array<{ category: string; confidence: number; reason: string }> = [];
  // Split into word-like tokens, check for suspiciously high entropy (possible base64/encoded payloads)
  const tokens = text.split(/\s+/).filter(t => t.length >= 16);
  for (const token of tokens) {
    const e = shannonEntropy(token);
    if (e > 4.8 && token.length >= 20) {
      threats.push({ category: 'token_smuggling', confidence: 0.70, reason: `High-entropy token (possible encoded payload, entropy=${e.toFixed(2)})` });
    }
  }
  return threats;
}

// ─────────────────────────────────────────────────────────────────────────────
// Nested/contextual injection detector
// ─────────────────────────────────────────────────────────────────────────────

function detectNestedInjection(text: string): Array<{ category: string; confidence: number; reason: string }> {
  const threats: Array<{ category: string; confidence: number; reason: string }> = [];
  // Try decoding embedded base64 blobs and scanning them
  const b64Matches = text.match(/[A-Za-z0-9+/]{24,}={0,2}/g) ?? [];
  for (const blob of b64Matches.slice(0, 5)) {
    try {
      const decoded = Buffer.from(blob, 'base64').toString('utf8');
      if (/[a-z]{4,}/.test(decoded)) { // Looks like text
        const norm = normalize(decoded);
        for (const def of INPUT_PATTERNS) {
          if (def.pattern.test(norm)) {
            threats.push({ category: 'indirect_injection', confidence: Math.min(def.confidence * 0.9, 0.92), reason: `Encoded payload: ${def.reason}` });
            break;
          }
        }
      }
    } catch { /* ignore */ }
  }
  return threats;
}

// ─────────────────────────────────────────────────────────────────────────────
// Core scan engine
// ─────────────────────────────────────────────────────────────────────────────

function runPatterns(text: string, patterns: PatternDef[], preserveCase = false): Array<{ category: string; confidence: number; reason: string }> {
  const threats: Array<{ category: string; confidence: number; reason: string }> = [];
  // Output patterns need original case preserved (API keys are case-sensitive)
  const variants = preserveCase ? [text] : makeVariants(text);
  for (const variant of variants) {
    for (const def of patterns) {
      if (def.pattern.test(variant)) {
        threats.push({ category: def.category, confidence: def.confidence, reason: def.reason });
      }
    }
  }
  return threats;
}

function computeAction(
  allThreats: Array<{ category: string; confidence: number; reason: string }>,
  blockThreshold = 0.70,
  alertThreshold = 0.35,
): PolicyAction {
  if (allThreats.length === 0) return { action: 'allow', score: 0, reason: 'Clean' };

  // Deduplicate by category, keeping highest confidence per category
  const byCat = new Map<string, { category: string; confidence: number; reason: string }>();
  for (const t of allThreats) {
    const existing = byCat.get(t.category);
    if (!existing || t.confidence > existing.confidence) byCat.set(t.category, t);
  }
  const unique = [...byCat.values()];

  const maxConf = Math.max(...unique.map(t => t.confidence));
  // Multi-category bonus: each additional category adds 5% up to 25%
  const multiBonus = Math.min((unique.length - 1) * 0.05, 0.25);
  const score = Math.min(maxConf + multiBonus, 1.0);

  const action = score >= blockThreshold ? 'block' : score >= alertThreshold ? 'alert' : 'allow';
  const topThreats = unique.sort((a, b) => b.confidence - a.confidence);
  const reason = topThreats.slice(0, 3).map(t => t.reason).join(' | ');

  return { action, score: Math.round(score * 1000) / 1000, reason, threats: unique };
}

function advancedScan(text: string, blockThreshold = 0.70, alertThreshold = 0.35, isOutput = false): PolicyAction {
  if (!text?.trim()) return { action: 'allow', score: 0 };

  const patterns = isOutput ? OUTPUT_PATTERNS : INPUT_PATTERNS;
  const allThreats: Array<{ category: string; confidence: number; reason: string }> = [];

  // Layer 1: Regex pattern matching (with normalisation variants)
  // For output: preserve case so API key / secret regexes work correctly
  allThreats.push(...runPatterns(text, patterns, isOutput));

  // Layer 2: Semantic keyword groups (input only)
  if (!isOutput) {
    allThreats.push(...semanticScore(normalize(text)));
  }

  // Layer 3: Character-separation obfuscation
  if (!isOutput && /\b\w([-._*\s])\w(\1\w){3,}\b/.test(text)) {
    allThreats.push({ category: 'token_smuggling', confidence: 0.65, reason: 'Character-separated word obfuscation' });
  }

  // Layer 4: High-entropy token detection (input only)
  if (!isOutput) {
    allThreats.push(...detectHighEntropyObfuscation(text));
  }

  // Layer 5: Nested / encoded injection (input only)
  if (!isOutput) {
    allThreats.push(...detectNestedInjection(text));
  }

  return computeAction(allThreats, blockThreshold, alertThreshold);
}

// ─────────────────────────────────────────────────────────────────────────────
// Session threat accumulator (multi-turn context tracking)
// ─────────────────────────────────────────────────────────────────────────────

interface SessionState {
  turnThreats: Array<{ timestamp: number; score: number; category: string }>;
  velocityWindow: number[];
}

class SessionTracker {
  private sessions = new Map<string, SessionState>();

  get(sessionId: string): SessionState {
    if (!this.sessions.has(sessionId)) {
      this.sessions.set(sessionId, { turnThreats: [], velocityWindow: [] });
    }
    return this.sessions.get(sessionId)!;
  }

  /** Record a threat event for this session and return accumulated risk boost */
  record(sessionId: string, result: PolicyAction, windowMs: number): number {
    const state = this.get(sessionId);
    const now = Date.now();

    // Velocity window cleanup
    state.velocityWindow = state.velocityWindow.filter(t => now - t < windowMs);

    if (result.action !== 'allow' && result.score! > 0) {
      state.velocityWindow.push(now);
      state.turnThreats.push({ timestamp: now, score: result.score!, category: result.threats?.[0]?.category ?? 'unknown' });
    }

    // Keep only last 50 turns
    if (state.turnThreats.length > 50) state.turnThreats.splice(0, state.turnThreats.length - 50);

    // Accumulated risk: sum of recent threat scores decayed by age
    const recentThreats = state.turnThreats.filter(t => now - t.timestamp < windowMs * 5);
    const accumulated = recentThreats.reduce((sum, t) => sum + t.score * 0.3, 0);
    return Math.min(accumulated, 0.40); // cap boost at 40%
  }

  velocityCount(sessionId: string): number {
    return this.get(sessionId).velocityWindow.length;
  }

  clear(sessionId: string): void {
    this.sessions.delete(sessionId);
  }
}

// ─────────────────────────────────────────────────────────────────────────────
// Main SDK class
// ─────────────────────────────────────────────────────────────────────────────

export class AgentFortress {
  private config: Required<AgentFortressConfig>;
  private threatHandlers: ThreatHandler[] = [];
  private auditHandlers: AuditHandler[] = [];
  private sessionId: string;
  private tracker = new SessionTracker();

  constructor(config: AgentFortressConfig = {}) {
    this.config = {
      apiKey: '',
      serverUrl: '',
      mode: 'local',
      logLevel: 'info',
      blockThreshold: 0.70,
      alertThreshold: 0.35,
      throwOnBlock: false,
      velocityLimit: 5,
      velocityWindowMs: 60_000,
      scanOutputs: true,
      blockMessage: '[AgentFortress] Input blocked: potential prompt injection or policy violation.',
      ...config,
    };
    this.sessionId = `session-${Date.now()}-${Math.random().toString(36).slice(2)}`;
  }

  // ── Public API ─────────────────────────────────────────────────────────────

  /**
   * Scan a string for threats. Returns a PolicyAction with action, score, and threat details.
   */
  scan(text: string, direction: 'input' | 'output' = 'input'): PolicyAction {
    const isOutput = direction === 'output';
    let result = advancedScan(text, this.config.blockThreshold, this.config.alertThreshold, isOutput);

    // Apply session-level accumulated risk boost (input only)
    if (!isOutput && result.score !== undefined) {
      const accumulatedBoost = this.tracker.record(this.sessionId, result, this.config.velocityWindowMs);
      if (accumulatedBoost > 0 && result.score > 0) {
        const boostedScore = Math.min(result.score + accumulatedBoost, 1.0);
        const newAction = boostedScore >= this.config.blockThreshold ? 'block' : boostedScore >= this.config.alertThreshold ? 'alert' : result.action;
        result = { ...result, score: Math.round(boostedScore * 1000) / 1000, action: newAction, reason: (result.reason ?? '') + ` | +session_context_boost(${accumulatedBoost.toFixed(2)})` };
      }
    }

    // Velocity limit check (input only)
    if (!isOutput) {
      const velocity = this.tracker.velocityCount(this.sessionId);
      if (velocity >= this.config.velocityLimit) {
        result = { action: 'block', score: 1.0, reason: `Velocity limit reached: ${velocity} suspicious queries in ${this.config.velocityWindowMs}ms window`, threats: result.threats };
      }
    }

    // Emit threat/audit events
    if (result.action !== 'allow' && result.threats?.length) {
      const top = result.threats.sort((a, b) => b.confidence - a.confidence)[0];
      this._emitThreat({
        id: `evt-${Date.now()}-${Math.random().toString(36).slice(2, 6)}`,
        timestamp: Date.now(),
        type: top.category,
        severity: result.score! >= 0.85 ? 'critical' : result.score! >= 0.70 ? 'high' : result.score! >= 0.35 ? 'medium' : 'low',
        description: result.reason ?? top.reason,
        sessionId: this.sessionId,
      });
    }

    this._emitAudit({ timestamp: Date.now(), sessionId: this.sessionId, direction, text, decision: result });
    this._log('debug', `[scan/${direction}] score=${result.score} action=${result.action} reason="${result.reason ?? 'none'}"`);

    return result;
  }

  /**
   * Wrap an agent function with pre-call input scanning AND optional post-call output scanning.
   *
   * ⚠️ FIX: Previously protect() only caught JS errors — it never scanned inputs.
   *         Now it extracts ALL string arguments, scans them BEFORE calling the agent,
   *         and blocks execution if any argument exceeds the threat threshold.
   *
   * @param agent - The agent function to wrap
   * @param agentId - Optional identifier for logging/audit
   * @returns Wrapped function that enforces security policy
   */
  protect<T extends (...args: unknown[]) => unknown>(agent: T, agentId?: string): T {
    const self = this;
    return (async (...args: unknown[]) => {
      // ── Step 1: Extract and scan all string inputs ──────────────────────
      const stringArgs = self._extractStrings(args);
      for (const text of stringArgs) {
        if (!text.trim()) continue;
        const inputResult = self.scan(text, 'input');
        if (inputResult.action === 'block') {
          self._log('warn', `[protect] BLOCKED agent=${agentId ?? 'unknown'} score=${inputResult.score} reason="${inputResult.reason}"`);
          self._emitThreat({
            id: `evt-${Date.now()}`,
            timestamp: Date.now(),
            type: 'input_blocked',
            severity: 'high',
            description: `Input blocked before agent execution. Score: ${inputResult.score}. Reason: ${inputResult.reason}`,
            agentId,
            sessionId: self.sessionId,
            payload: { score: inputResult.score, threats: inputResult.threats },
          });
          if (self.config.throwOnBlock) {
            throw new Error(self.config.blockMessage);
          }
          return self.config.blockMessage;
        }
        if (inputResult.action === 'alert') {
          self._log('warn', `[protect] ALERT (passing through) agent=${agentId ?? 'unknown'} score=${inputResult.score}`);
        }
      }

      // ── Step 2: Execute the agent ────────────────────────────────────────
      self._log('info', `Agent ${agentId ?? 'unknown'} invoked`);
      let output: unknown;
      try {
        output = agent(...args);
        // Await if the agent returns a Promise
        if (output instanceof Promise) output = await output;
      } catch (error) {
        self._emitThreat({
          id: `evt-${Date.now()}`,
          timestamp: Date.now(),
          type: 'agent_error',
          severity: 'medium',
          description: `Agent error: ${error}`,
          agentId,
          sessionId: self.sessionId,
        });
        throw error;
      }

      // ── Step 3: Scan output for sensitive data leakage ───────────────────
      if (self.config.scanOutputs && typeof output === 'string' && output.trim()) {
        const outputResult = self.scan(output, 'output');
        if (outputResult.action !== 'allow') {
          self._log('warn', `[protect] OUTPUT ALERT agent=${agentId ?? 'unknown'} score=${outputResult.score} reason="${outputResult.reason}"`);
        }
      }

      return output;
    }) as T;
  }

  /**
   * Register a threat event handler (called on block/alert decisions).
   */
  onThreat(handler: ThreatHandler): this {
    this.threatHandlers.push(handler);
    return this;
  }

  /**
   * Register an audit handler (called for every scan — allow, alert, or block).
   * Use this for full audit trails / SIEM integration.
   */
  onAudit(handler: AuditHandler): this {
    this.auditHandlers.push(handler);
    return this;
  }

  getSessionId(): string { return this.sessionId; }

  /**
   * Reset session threat accumulator (e.g. after user re-authentication).
   */
  resetSession(): void {
    this.tracker.clear(this.sessionId);
    this.sessionId = `session-${Date.now()}-${Math.random().toString(36).slice(2)}`;
  }

  /**
   * Scan output text only (convenience wrapper around scan(text, 'output')).
   */
  scanOutput(text: string): PolicyAction {
    return this.scan(text, 'output');
  }

  // ── Private helpers ────────────────────────────────────────────────────────

  /** Recursively extract all string values from args (handles arrays, objects, nested) */
  private _extractStrings(value: unknown, depth = 0): string[] {
    if (depth > 5) return [];
    if (typeof value === 'string') return [value];
    if (Array.isArray(value)) return value.flatMap(v => this._extractStrings(v, depth + 1));
    if (value !== null && typeof value === 'object') {
      return Object.values(value).flatMap(v => this._extractStrings(v, depth + 1));
    }
    return [];
  }

  private _emitThreat(event: ThreatEvent): void {
    this.threatHandlers.forEach(h => { try { h(event); } catch { /* swallow */ } });
    this._log('warn', `[THREAT] ${event.type}: ${event.description}`);
  }

  private _emitAudit(record: AuditRecord): void {
    this.auditHandlers.forEach(h => { try { h(record); } catch { /* swallow */ } });
  }

  private _log(level: 'debug' | 'info' | 'warn' | 'error', message: string): void {
    const levels = { silent: 0, error: 1, warn: 2, info: 3, debug: 4 };
    if (levels[level] <= levels[this.config.logLevel]) {
      const prefix = `[AgentFortress] [${level.toUpperCase()}]`;
      if (level === 'error') console.error(prefix, message);
      else if (level === 'warn') console.warn(prefix, message);
      else console.log(prefix, message);
    }
  }
}

// ─────────────────────────────────────────────────────────────────────────────
// Singleton convenience API
// ─────────────────────────────────────────────────────────────────────────────

let _instance: AgentFortress | null = null;

export function init(config: AgentFortressConfig = {}): AgentFortress {
  _instance = new AgentFortress(config);
  return _instance;
}

export function getInstance(): AgentFortress {
  if (!_instance) _instance = new AgentFortress();
  return _instance;
}

export function scan(text: string, direction?: 'input' | 'output'): PolicyAction {
  return getInstance().scan(text, direction);
}

export function protect<T extends (...args: unknown[]) => unknown>(agent: T, agentId?: string): T {
  return getInstance().protect(agent, agentId);
}

export default { AgentFortress, init, getInstance, scan, protect };
