/**
 * AgentFortress — Runtime protection for AI agents
 * The CrowdStrike for AI Agents
 * @packageDocumentation
 */

export interface AgentFortressConfig {
  apiKey?: string;
  serverUrl?: string;
  mode?: 'local' | 'remote';
  logLevel?: 'debug' | 'info' | 'warn' | 'error';
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
  action: 'allow' | 'block' | 'alert' | 'rate_limit';
  reason?: string;
}

export type ThreatHandler = (event: ThreatEvent) => void;

/**
 * Main AgentFortress SDK class
 */
export class AgentFortress {
  private config: AgentFortressConfig;
  private handlers: ThreatHandler[] = [];
  private sessionId: string;

  constructor(config: AgentFortressConfig = {}) {
    this.config = {
      mode: 'local',
      logLevel: 'info',
      ...config,
    };
    this.sessionId = `session-${Date.now()}-${Math.random().toString(36).slice(2)}`;
  }

  /**
   * Wrap an agent function with security monitoring
   */
  protect<T extends (...args: unknown[]) => unknown>(agent: T, agentId?: string): T {
    const self = this;
    return ((...args: unknown[]) => {
      self._log('info', `Agent ${agentId ?? 'unknown'} invoked`);
      try {
        const result = agent(...args);
        return result;
      } catch (error) {
        self._emitThreat({
          id: `evt-${Date.now()}`,
          timestamp: Date.now(),
          type: 'agent_error',
          severity: 'medium',
          description: `Agent threw an error: ${error}`,
          agentId,
          sessionId: self.sessionId,
        });
        throw error;
      }
    }) as T;
  }

  /**
   * Scan text for prompt injection or threats
   */
  scan(text: string): PolicyAction {
    const injectionPatterns = [
      /ignore (previous|all|above) instructions/i,
      /you are now/i,
      /disregard your (system|previous)/i,
      /forget (everything|all)/i,
      /act as (a|an) (?!AI)/i,
      /jailbreak/i,
    ];
    for (const pattern of injectionPatterns) {
      if (pattern.test(text)) {
        const event: ThreatEvent = {
          id: `evt-${Date.now()}`,
          timestamp: Date.now(),
          type: 'prompt_injection',
          severity: 'high',
          description: `Potential prompt injection detected`,
          sessionId: this.sessionId,
        };
        this._emitThreat(event);
        return { action: 'block', reason: 'Prompt injection pattern detected' };
      }
    }
    return { action: 'allow' };
  }

  /**
   * Register a threat event handler
   */
  onThreat(handler: ThreatHandler): this {
    this.handlers.push(handler);
    return this;
  }

  /**
   * Get current session ID
   */
  getSessionId(): string {
    return this.sessionId;
  }

  private _emitThreat(event: ThreatEvent): void {
    this.handlers.forEach(h => h(event));
    this._log('warn', `[THREAT] ${event.type}: ${event.description}`);
  }

  private _log(level: string, message: string): void {
    if (this.config.logLevel === 'debug' || level !== 'debug') {
      console.log(`[AgentFortress] [${level.toUpperCase()}] ${message}`);
    }
  }
}

// Singleton instance support
let _instance: AgentFortress | null = null;

/**
 * Initialize AgentFortress with config (singleton)
 */
export function init(config: AgentFortressConfig = {}): AgentFortress {
  _instance = new AgentFortress(config);
  return _instance;
}

/**
 * Get the singleton instance (call init() first)
 */
export function getInstance(): AgentFortress {
  if (!_instance) {
    _instance = new AgentFortress();
  }
  return _instance;
}

/**
 * Quick scan — no setup needed
 */
export function scan(text: string): PolicyAction {
  return getInstance().scan(text);
}

/**
 * Protect an agent function — no setup needed
 */
export function protect<T extends (...args: unknown[]) => unknown>(agent: T, agentId?: string): T {
  return getInstance().protect(agent, agentId);
}

export default { AgentFortress, init, getInstance, scan, protect };
