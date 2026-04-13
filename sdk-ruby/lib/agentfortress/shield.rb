# frozen_string_literal: true
module AgentFortress
  class Shield
    attr_reader :session_id

    def initialize(api_key: nil, server_url: nil, mode: :local)
      @api_key = api_key
      @server_url = server_url
      @mode = mode
      @session_id = "session-#{Time.now.to_i}-#{rand(36**8).to_s(36)}"
      @handlers = []
    end

    def protect(agent_id: nil, &block)
      -> (*args) {
        result = block.call(*args)
        result
      }
    end

    def on_threat(&block)
      @handlers << block
      self
    end

    def scan(text)
      Scanner.new.scan(text)
    end
  end
end
