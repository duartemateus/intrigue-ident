module Intrigue
  module Ident
  module Check
  class JqueryUi < Intrigue::Ident::Check::Base
  
    def generate_checks(url)
      [
        {
          :type => "fingerprint",
          :category => "application",
          :tags => ["Javascript"],
          :vendor => "JQuery",
          :product =>"JQuery UI",
          :match_details =>"unique sting",
          :match_type => :content_body,
          :match_content =>  /\,this\._getPanelForTab\(this\.active\)\.show\(\)\.attr\(\{\"aria-hid/i,
          :paths => ["#{url}"],
          :inference => true
        },
        {
          :type => "fingerprint",
          :category => "application",
          :tags => ["Javascript"],
          :vendor => "JQuery",
          :product =>"JQuery UI",
          :match_details =>"version in js file",
          :match_type => :content_body,
          :match_content =>  /jQuery UI - v/i,
          :dynamic_version => lambda {|x| 
            _first_body_capture(x,/\*\! jQuery UI - v([\d\.]+)/i) },
          :paths => ["#{url}"],
          :inference => true
        }

        
      ]
    end
  
  end
  end
  end
  end
  