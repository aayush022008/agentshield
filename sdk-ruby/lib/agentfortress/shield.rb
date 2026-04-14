# frozen_string_literal: true
module AgentFortress
  class BlockedError < StandardError
    attr_reader :direction
    def initialize(msg = 'Blocked by AgentFortress', direction: :input)
      super(msg)
      @direction = direction
    end
  end

  class Shield
    attr_reader :session_id

    BLOCK_MESSAGE = '[AgentFortress] Request blocked: potential security threat detected.'
    OUTPUT_BLOCK_MESSAGE = '[AgentFortress] Output blocked: sensitive data detected.'

    def initialize(
      api_key: nil,
      server_url: nil,
      mode: :local,
      on_audit: nil,
      throw_on_block: false,
      velocity_limit: 5,
      velocity_window: 60,
      block_threshold: 0.70,
      alert_threshold: 0.35
    )
      @api_key = api_key
      @server_url = server_url
      @mode = mode
      @on_audit = on_audit
      @throw_on_block = throw_on_block
      @velocity_limit = velocity_limit
      @velocity_window = velocity_window
      @block_threshold = block_threshold
      @alert_threshold = alert_threshold

      @session_id = _new_session_id
      @handlers = []
      @suspicious_times = []
      @session_threat_score = 0.0
      @turn_count = 0
      @scanner = Scanner.new(block_threshold: block_threshold, alert_threshold: alert_threshold)
    end

    def reset_session
      @session_id = _new_session_id
      @suspicious_times.clear
      @session_threat_score = 0.0
      @turn_count = 0
    end

    def scan(text)
      result = @scanner.scan(text)
      _fire_audit(direction: :input, text: text, decision: result[:action], score: result[:score], reason: result[:reason])
      result
    end

    def scan_output(text)
      result = @scanner.scan_output(text)
      _fire_audit(direction: :output, text: text, decision: result[:action], score: result[:score], reason: result[:reason])
      result
    end

    def protect(agent_id: nil, &block)
      lambda do |*args|
        @turn_count += 1

        # Velocity check
        if _check_velocity
          msg = '[AgentFortress] Rate limit exceeded: too many suspicious queries.'
          _fire_audit(direction: :input, text: '', decision: :block, score: 1.0, reason: 'velocity_limit_exceeded')
          raise BlockedError.new(msg, direction: :input) if @throw_on_block
          return msg
        end

        # Scan all string inputs
        strings = _extract_strings(args)
        strings.each do |t|
          result = @scanner.scan(t)
          score = result[:score]

          # Boost based on session history
          if @session_threat_score > 0 && @turn_count > 1
            boost = [@session_threat_score * 0.1, 0.20].min
            score = [score + boost, 1.0].min
          end

          @session_threat_score = @session_threat_score * 0.8 + result[:score] * 0.2 if result[:score] > 0
          @suspicious_times << Time.now.to_i if result[:score] >= @alert_threshold

          decision = if score >= @block_threshold
                       :block
                     elsif score >= @alert_threshold
                       :alert
                     else
                       :allow
                     end

          _fire_audit(direction: :input, text: t[0, 500], decision: decision, score: score, reason: result[:reason])

          if decision == :block
            raise BlockedError.new(BLOCK_MESSAGE, direction: :input) if @throw_on_block
            return BLOCK_MESSAGE
          end
        end

        # Call the wrapped block
        result = block.call(*args)

        # Scan output
        if result.is_a?(String)
          out_result = scan_output(result)
          if out_result[:action] == :block
            raise BlockedError.new(OUTPUT_BLOCK_MESSAGE, direction: :output) if @throw_on_block
            return OUTPUT_BLOCK_MESSAGE
          end
        end

        result
      end
    end

    def on_threat(&blk)
      @handlers << blk
      self
    end

    def on_audit(&blk)
      @on_audit = blk
      self
    end

    private

    def _new_session_id
      "session-#{Time.now.to_i}-#{rand(36**8).to_s(36)}"
    end

    def _fire_audit(direction:, text:, decision:, score:, reason:)
      return unless @on_audit
      @on_audit.call({
        timestamp: Time.now.to_f,
        session_id: @session_id,
        direction: direction,
        text: (text || '')[0, 500],
        decision: decision,
        score: score,
        reason: reason,
      })
    end

    def _check_velocity
      now = Time.now.to_i
      @suspicious_times.reject! { |ts| now - ts > @velocity_window }
      @suspicious_times.size >= @velocity_limit
    end

    def _extract_strings(obj, depth = 0)
      return [] if depth > 10
      case obj
      when String then [obj]
      when Array then obj.flat_map { |v| _extract_strings(v, depth + 1) }
      when Hash then obj.values.flat_map { |v| _extract_strings(v, depth + 1) }
      else []
      end
    end
  end
end
