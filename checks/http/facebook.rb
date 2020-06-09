module Intrigue
module Ident
module Check
  class Facebook < Intrigue::Ident::Check::Base

    def generate_checks(url)
      [
        {
          :type => "fingerprint",
          :category => "application",
          :tags => ["Marketing", "Javascript"],
          :vendor => "Facebook",
          :product =>"JS SDK",
          :version => nil,
          :match_details =>"load string",
          :match_type => :content_body,
          :match_content =>  /(document, 'script', 'facebook-jssdk')/,
          :paths => ["#{url}"],
          :inference => false
        }, 
        {
          :type => "fingerprint",
          :category => "application",
          :tags => ["Javascript"],
          :vendor => "Facebook",
          :product =>"React",
          :match_details =>"version in js file",
          :match_type => :content_body,
          :match_content =>  /^\/\*\* @license React v\d+\.\d+.\d+/i,
          :dynamic_version => lambda {|x| 
            _first_body_capture(x,/^\/\*\* @license React v(\d+\.\d+.\d+)/i) },
          :paths => ["#{url}"],
          :inference => true
        }
      ]
    end

  end
end
end
end