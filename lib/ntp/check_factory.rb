module Intrigue
  module Ident
    module Ntp
      class CheckFactory
        #
        # Register a new handler
        #
        def self.register(klass)
          @checks ||= []
          @checks << klass if klass
        end

        #
        # Provide the full list of checks
        #
        class << self
          attr_reader :checks
        end
      end
    end
  end
end
