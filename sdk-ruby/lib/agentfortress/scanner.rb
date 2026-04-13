# frozen_string_literal: true
module AgentFortress
  class Scanner
    INJECTION_PATTERNS = [
      /ignore (previous|all|above) instructions/i,
      /you are now/i,
      /disregard your (system|previous)/i,
      /forget (everything|all)/i,
      /jailbreak/i,
    ].freeze

    def scan(text)
      INJECTION_PATTERNS.each do |pattern|
        if text.match?(pattern)
          return { action: :block, reason: "Prompt injection pattern detected", threat: :prompt_injection }
        end
      end
      { action: :allow }
    end
  end
end
