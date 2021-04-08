module Intrigue
  module Ident
    module RdpCheck
      class Base
        include Intrigue::Ident::BannerHelpers

        def self.inherited(base)
          Intrigue::Ident::Rdp::CheckFactory.register(base)
        end
      end
    end
  end
end
