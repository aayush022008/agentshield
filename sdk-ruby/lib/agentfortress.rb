# frozen_string_literal: true

require_relative "agentfortress/version"
require_relative "agentfortress/scanner"
require_relative "agentfortress/shield"

# AgentFortress — Runtime protection for AI agents
# The CrowdStrike for AI Agents
module AgentFortress
  class Error < StandardError; end

  INJECTION_PATTERNS = [
    /ignore (previous|all|above) instructions/i,
    /you are now/i,
    /disregard your (system|previous)/i,
    /forget (everything|all)/i,
    /jailbreak/i,
  ].freeze

  # Quick scan for prompt injection
  def self.scan(text)
    Scanner.new.scan(text)
  end

  # Initialize with config
  def self.init(api_key: nil, server_url: nil, mode: :local)
    Shield.new(api_key: api_key, server_url: server_url, mode: mode)
  end
end
