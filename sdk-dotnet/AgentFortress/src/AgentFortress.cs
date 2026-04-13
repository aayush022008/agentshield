using System;
using System.Collections.Generic;
using System.Text.RegularExpressions;

namespace AgentFortress
{
    /// <summary>
    /// Configuration for AgentFortress
    /// </summary>
    public class AgentFortressConfig
    {
        public string? ApiKey { get; set; }
        public string? ServerUrl { get; set; }
        public string Mode { get; set; } = "local";
        public string LogLevel { get; set; } = "info";
    }

    /// <summary>
    /// Represents a detected threat event
    /// </summary>
    public class ThreatEvent
    {
        public string Id { get; set; } = Guid.NewGuid().ToString();
        public DateTimeOffset Timestamp { get; set; } = DateTimeOffset.UtcNow;
        public string Type { get; set; } = string.Empty;
        public string Severity { get; set; } = "medium";
        public string Description { get; set; } = string.Empty;
        public string? AgentId { get; set; }
        public string? SessionId { get; set; }
    }

    /// <summary>
    /// Result of a policy evaluation
    /// </summary>
    public class PolicyAction
    {
        public string Action { get; set; } = "allow";
        public string? Reason { get; set; }

        public bool IsAllowed => Action == "allow";
        public bool IsBlocked => Action == "block";
    }

    /// <summary>
    /// AgentFortress — Runtime protection for AI agents.
    /// The CrowdStrike for AI Agents.
    /// </summary>
    public class AgentFortressShield
    {
        private readonly AgentFortressConfig _config;
        private readonly List<Action<ThreatEvent>> _handlers = new();
        private readonly string _sessionId;

        private static readonly Regex[] InjectionPatterns = new[]
        {
            new Regex(@"ignore (previous|all|above) instructions", RegexOptions.IgnoreCase),
            new Regex(@"you are now", RegexOptions.IgnoreCase),
            new Regex(@"disregard your (system|previous)", RegexOptions.IgnoreCase),
            new Regex(@"forget (everything|all)", RegexOptions.IgnoreCase),
            new Regex(@"jailbreak", RegexOptions.IgnoreCase),
        };

        public AgentFortressShield(AgentFortressConfig? config = null)
        {
            _config = config ?? new AgentFortressConfig();
            _sessionId = $"session-{DateTimeOffset.UtcNow.ToUnixTimeMilliseconds()}";
        }

        /// <summary>Scan text for prompt injection or threats</summary>
        public PolicyAction Scan(string text)
        {
            foreach (var pattern in InjectionPatterns)
            {
                if (pattern.IsMatch(text))
                {
                    var evt = new ThreatEvent
                    {
                        Type = "prompt_injection",
                        Severity = "high",
                        Description = "Prompt injection pattern detected",
                        SessionId = _sessionId,
                    };
                    EmitThreat(evt);
                    return new PolicyAction { Action = "block", Reason = "Prompt injection pattern detected" };
                }
            }
            return new PolicyAction { Action = "allow" };
        }

        /// <summary>Register a threat event handler</summary>
        public AgentFortressShield OnThreat(Action<ThreatEvent> handler)
        {
            _handlers.Add(handler);
            return this;
        }

        /// <summary>Get current session ID</summary>
        public string GetSessionId() => _sessionId;

        private void EmitThreat(ThreatEvent evt)
        {
            foreach (var handler in _handlers)
                handler(evt);
        }
    }

    /// <summary>Static convenience API</summary>
    public static class Shield
    {
        private static AgentFortressShield? _instance;

        public static AgentFortressShield Init(AgentFortressConfig? config = null)
        {
            _instance = new AgentFortressShield(config);
            return _instance;
        }

        public static AgentFortressShield GetInstance()
            => _instance ??= new AgentFortressShield();

        public static PolicyAction Scan(string text)
            => GetInstance().Scan(text);
    }
}
