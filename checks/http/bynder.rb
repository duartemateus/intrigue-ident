module Intrigue
  module Ident
  module Check
  class Bynder < Intrigue::Ident::Check::Base
  
    def generate_checks(url)
      [
        {
          :type => "fingerprint",
          :category => "application",
          :tags => ["CMS"],
          :vendor => "Bynder",
          :product => "Bynder",
          :website => "https://www.bynder.com/en/",
          :references => [],
          :version => nil,
          :match_type => :content_cookies,
          :match_content => /bynder=/i,
          :match_details => "unique cookie",
          :hide => false,
          :paths => ["#{url}"],
          :inference => false
        }
      ]
    end
  
  end
  end
  end
  end
  