module Intrigue
  module Ident
    module NtpCheck
      class Base
        include Intrigue::Ident::BannerHelpers

        def self.inherited(base)
          Intrigue::Ident::Ntp::CheckFactory.register(base)
        end
      end
    end
  end
end
