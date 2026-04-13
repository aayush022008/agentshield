/**
 * AgentFortress — Runtime protection for AI agents
 * Advanced multi-layer scanner with evasion resistance
 * @packageDocumentation
 */

export interface AgentFortressConfig {
  apiKey?: string;
  serverUrl?: string;
  mode?: 'local' | 'remote';
  logLevel?: 'debug' | 'info' | 'warn' | 'error';
  blockThreshold?: number;
  alertThreshold?: number;
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

export type ThreatHandler = (event: ThreatEvent) => void;

// ─────────────────────────────────────────────────────────────────────────────
// Normalisation
// ─────────────────────────────────────────────────────────────────────────────

const HOMOGLYPHS: Record<string, string> = {
  'а': 'a', 'е': 'e', 'о': 'o', 'р': 'p', 'с': 'c', 'х': 'x',
  'А': 'A', 'В': 'B', 'Е': 'E', 'К': 'K', 'М': 'M', 'Н': 'H',
  'О': 'O', 'Р': 'P', 'С': 'C', 'Т': 'T', 'Х': 'X',
  'α': 'a', 'β': 'b', 'ε': 'e', 'ι': 'i', 'ο': 'o', 'ρ': 'p',
};

const LEET: Record<string, string> = {
  '0': 'o', '1': 'i', '3': 'e', '4': 'a', '5': 's',
  '6': 'g', '7': 't', '8': 'b', '@': 'a', '$': 's', '!': 'i',
};

function normalize(text: string): string {
  // Replace homoglyphs
  let result = text.split('').map(c => HOMOGLYPHS[c] ?? c).join('');
  // Remove zero-width chars
  result = result.replace(/[\u200b\u200c\u200d\u200e\u200f\ufeff]/g, '');
  // Leet decode
  result = result.toLowerCase().split('').map(c => LEET[c] ?? c).join('');
  // Remove separators between letters (I-g-n-o-r-e → ignore)
  result = result.replace(/(?<=[a-z])[-._* ](?=[a-z])/g, '');
  // Collapse whitespace
  result = result.replace(/\s+/g, ' ').trim();
  return result;
}

function makeVariants(text: string): string[] {
  const lower = text.toLowerCase();
  const norm = normalize(text);
  const noPunct = norm.replace(/[^a-z0-9 ]/g, '');
  const noSpace = norm.replace(/\s+/g, '');
  return [...new Set([lower, norm, noPunct, noSpace])];
}

// ─────────────────────────────────────────────────────────────────────────────
// Pattern library
// ─────────────────────────────────────────────────────────────────────────────

interface PatternDef {
  pattern: RegExp;
  category: string;
  confidence: number;
  reason: string;
}

const PATTERNS: PatternDef[] = [
  // Instruction Override
  { pattern: /\bignore\b.{0,30}\b(previous|prior|above|earlier|all|your)\b.{0,30}\b(instructions?|rules?|prompts?|context|constraints?|guidelines?)/i, category: 'instruction_override', confidence: 0.95, reason: 'Ignore instructions pattern' },
  { pattern: /\b(disregard|forget|override|bypass|dismiss|cancel|nullify|void|erase|clear|reset)\b.{0,40}\b(instructions?|rules?|system\s*prompt|guidelines?|constraints?|training|previous)/i, category: 'instruction_override', confidence: 0.95, reason: 'Disregard/override instructions' },
  { pattern: /\b(pretend|act|behave|imagine|suppose|assume)\b.{0,30}\b(you\s*(are|were|have\s*no)|without|free\s*from)\b.{0,50}\b(rules?|restrictions?|limits?|filters?|guidelines?|safety|ethics?)/i, category: 'instruction_override', confidence: 0.90, reason: 'Pretend without restrictions' },
  { pattern: /\b(new|updated?|actual|real|true|correct|only)\b.{0,20}\binstructions?\b.{0,10}(are|is|follow|:\s)/i, category: 'instruction_override', confidence: 0.88, reason: 'New instructions injection' },
  { pattern: /\b(stop\s+being|stop\s+following|no\s+longer\s+follow|don.t\s+follow)\b.{0,40}\b(your|the)\b.{0,20}\b(instructions?|rules?|guidelines?|training)/i, category: 'instruction_override', confidence: 0.85, reason: 'Stop following instructions' },

  // Jailbreak
  { pattern: /\bDAN\b.{0,100}(do\s*anything\s*now|without\s+restrictions?|no\s+restrictions?)/i, category: 'jailbreak', confidence: 0.98, reason: 'DAN jailbreak' },
  { pattern: /\bjailbreak(ed)?\b/i, category: 'jailbreak', confidence: 0.90, reason: 'Explicit jailbreak' },
  { pattern: /\b(developer|dev|god|admin|root|unrestricted|uncensored|unfiltered)\s+mode\b/i, category: 'jailbreak', confidence: 0.88, reason: 'Fictional mode activation' },
  { pattern: /\b(opposite|reverse|evil|chaos|dark|shadow|unethical)\s+(mode|version|persona|self|ai)\b/i, category: 'jailbreak', confidence: 0.85, reason: 'Evil/opposite mode' },
  { pattern: /\b(no\s+(restrictions?|limits?|filters?|censorship|guidelines?|ethics?|safety)|unrestricted(ly)?|unfiltered|uncensored)\b.{0,60}\b(respond|answer|reply|say|tell|generate|produce|output|write)\b/i, category: 'jailbreak', confidence: 0.85, reason: 'Unrestricted response request' },
  { pattern: /\bas\s+an?\s+(ai\s+without\s+(restrictions?|limits?)|unrestricted\s+ai|unfiltered\s+(ai|model|assistant))/i, category: 'jailbreak', confidence: 0.88, reason: 'As an unrestricted AI' },

  // Role manipulation
  { pattern: /\b(act|behave|respond|speak)\b.{0,20}\bas\b.{0,30}\b(a\s+hacker|an?\s+attacker|a\s+criminal|a\s+pirate|a\s+villain|an?\s+evil|a\s+terrorist|a\s+malicious)/i, category: 'role_manipulation', confidence: 0.88, reason: 'Act as malicious persona' },
  { pattern: /\bpretend\b.{0,30}\b(to\s+be|you.re|you\s+are)\b.{0,50}\b(hacker|cracker|attacker|criminal|pirate|villain|evil|malicious)/i, category: 'role_manipulation', confidence: 0.85, reason: 'Pretend to be malicious actor' },
  { pattern: /\byou\s+(are\s+now|have\s+become|will\s+become)\b.{0,60}\b(different|new|another|alternative)\b.{0,30}\b(ai|model|assistant|system|bot)/i, category: 'role_manipulation', confidence: 0.88, reason: 'You are now different AI' },

  // Token smuggling
  { pattern: /(\[INST\]|\[\/INST\]|<\|im_start\|>|<\|im_end\|>|\[SYSTEM\]|<system>|<\/system>|<\|endoftext\|>|###\s*Human:|###\s*Assistant:)/i, category: 'token_smuggling', confidence: 0.92, reason: 'LLM special token injection' },
  { pattern: /\\u[0-9a-fA-F]{4}|&#\d+;|&#x[0-9a-fA-F]+;|%[0-9a-fA-F]{2}/i, category: 'token_smuggling', confidence: 0.82, reason: 'Unicode/HTML escape sequences' },

  // Scope creep
  { pattern: /\b(rm\s+-rf|del\s+\/f|format\s+c:|drop\s+table|truncate\s+table|drop\s+database)\b/i, category: 'scope_creep', confidence: 0.95, reason: 'Destructive command' },
  { pattern: /\b(access|read|open|list)\b.{0,40}\b(\/etc\/passwd|\/etc\/shadow|\.ssh\/|\.aws\/|\.env|id_rsa|credentials?)/i, category: 'scope_creep', confidence: 0.90, reason: 'Sensitive file access' },
];

// Semantic keyword groups
const SEMANTIC_GROUPS: Array<{ keywords: string[]; weight: number; category: string; reason: string }> = [
  { keywords: ['ignore', 'disregard', 'forget', 'override', 'bypass', 'dismiss', 'cancel', 'nullify', 'void', 'erase', 'clear', 'reset', 'undo', 'revoke', 'annul', 'negate'], weight: 0.30, category: 'instruction_override', reason: 'Override verb' },
  { keywords: ['instructions', 'rules', 'guidelines', 'constraints', 'directives', 'prompt', 'training', 'restrictions', 'limitations', 'boundaries', 'policies'], weight: 0.20, category: 'instruction_override', reason: 'Instructions noun' },
  { keywords: ['unrestricted', 'unfiltered', 'uncensored', 'unlimited', 'unbound', 'unchained', 'no limits', 'no rules', 'no restrictions', 'no filter', 'no safety'], weight: 0.40, category: 'jailbreak', reason: 'Unrestricted keyword' },
  { keywords: ['pretend', 'roleplay', 'imagine you are', 'act as if', 'simulate', 'you are now', 'become', 'transform into', 'embody', 'take on the role'], weight: 0.25, category: 'role_manipulation', reason: 'Role manipulation keyword' },
  { keywords: ['hacker', 'attacker', 'criminal', 'pirate', 'villain', 'evil', 'malicious', 'adversary', 'black hat', 'cracker'], weight: 0.35, category: 'role_manipulation', reason: 'Malicious persona keyword' },
  { keywords: ['exfiltrate', 'exfil', 'steal', 'leak', 'smuggle', 'siphon', 'harvest', 'dump secrets'], weight: 0.45, category: 'data_exfil', reason: 'Exfiltration keyword' },
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

function advancedScan(text: string, blockThreshold = 0.70, alertThreshold = 0.35): PolicyAction {
  if (!text?.trim()) return { action: 'allow', score: 0 };

  const variants = makeVariants(text);
  const allThreats: Array<{ category: string; confidence: number; reason: string }> = [];

  // Pattern layer
  for (const variant of variants) {
    for (const def of PATTERNS) {
      if (def.pattern.test(variant)) {
        allThreats.push({ category: def.category, confidence: def.confidence, reason: def.reason });
      }
    }
  }

  // Semantic layer
  allThreats.push(...semanticScore(variants[1] ?? text.toLowerCase()));

  // Structural: character separation
  if (/\b\w([-._* ])\w(\1\w){3,}\b/.test(text)) {
    allThreats.push({ category: 'token_smuggling', confidence: 0.65, reason: 'Character-separated word obfuscation' });
  }

  if (allThreats.length === 0) return { action: 'allow', score: 0, reason: 'Clean' };

  // Deduplicate by category
  const byCat = new Map<string, { category: string; confidence: number; reason: string }>();
  for (const t of allThreats) {
    const existing = byCat.get(t.category);
    if (!existing || t.confidence > existing.confidence) byCat.set(t.category, t);
  }
  const unique = [...byCat.values()];

  const maxConf = Math.max(...unique.map(t => t.confidence));
  const multiBonus = Math.min((unique.length - 1) * 0.05, 0.25);
  const score = Math.min(maxConf + multiBonus, 1.0);

  const action = score >= blockThreshold ? 'block' : score >= alertThreshold ? 'alert' : 'allow';
  const reason = unique.sort((a, b) => b.confidence - a.confidence).slice(0, 3).map(t => t.reason).join(' | ');

  return { action, score: Math.round(score * 1000) / 1000, reason, threats: unique };
}

// ─────────────────────────────────────────────────────────────────────────────
// Main SDK class
// ─────────────────────────────────────────────────────────────────────────────

export class AgentFortress {
  private config: AgentFortressConfig;
  private handlers: ThreatHandler[] = [];
  private sessionId: string;

  constructor(config: AgentFortressConfig = {}) {
    this.config = { mode: 'local', logLevel: 'info', blockThreshold: 0.70, alertThreshold: 0.35, ...config };
    this.sessionId = `session-${Date.now()}-${Math.random().toString(36).slice(2)}`;
  }

  scan(text: string): PolicyAction {
    const result = advancedScan(text, this.config.blockThreshold, this.config.alertThreshold);
    if (result.action !== 'allow' && result.threats?.length) {
      const top = result.threats.sort((a, b) => b.confidence - a.confidence)[0];
      this._emitThreat({
        id: `evt-${Date.now()}`,
        timestamp: Date.now(),
        type: top.category,
        severity: result.score! >= 0.85 ? 'critical' : result.score! >= 0.70 ? 'high' : 'medium',
        description: result.reason ?? top.reason,
        sessionId: this.sessionId,
      });
    }
    return result;
  }

  protect<T extends (...args: unknown[]) => unknown>(agent: T, agentId?: string): T {
    const self = this;
    return ((...args: unknown[]) => {
      self._log('info', `Agent ${agentId ?? 'unknown'} invoked`);
      try { return agent(...args); }
      catch (error) {
        self._emitThreat({ id: `evt-${Date.now()}`, timestamp: Date.now(), type: 'agent_error', severity: 'medium', description: `Agent error: ${error}`, agentId, sessionId: self.sessionId });
        throw error;
      }
    }) as T;
  }

  onThreat(handler: ThreatHandler): this { this.handlers.push(handler); return this; }
  getSessionId(): string { return this.sessionId; }

  private _emitThreat(event: ThreatEvent): void {
    this.handlers.forEach(h => h(event));
    this._log('warn', `[THREAT] ${event.type}: ${event.description}`);
  }

  private _log(level: string, message: string): void {
    if (this.config.logLevel !== 'error' || level === 'error') {
      console.log(`[AgentFortress] [${level.toUpperCase()}] ${message}`);
    }
  }
}

let _instance: AgentFortress | null = null;

export function init(config: AgentFortressConfig = {}): AgentFortress {
  _instance = new AgentFortress(config);
  return _instance;
}

export function getInstance(): AgentFortress {
  if (!_instance) _instance = new AgentFortress();
  return _instance;
}

export function scan(text: string): PolicyAction {
  return getInstance().scan(text);
}

export function protect<T extends (...args: unknown[]) => unknown>(agent: T, agentId?: string): T {
  return getInstance().protect(agent, agentId);
}

export default { AgentFortress, init, getInstance, scan, protect };
