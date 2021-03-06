module Intrigue
module Ident
module Check
class Modwsgi < Intrigue::Ident::Check::Base

  def generate_checks(url)
    [
      {
        :type => "fingerprint",
        :category => "application",
        :tags => ["Library"],
        :vendor =>"modwsgi",
        :product =>"mod_wsgi",
        :match_details =>"server header",
        :version => nil,
        :match_type => :content_headers,
        :match_content =>  /^.*mod_wsgi\/.*$/i,
        :dynamic_version => lambda { |x|
          _first_header_capture(x,/^.*mod_wsgi\/([\w\d\.\-]*)\s.*$/i)
        },
        :paths => ["#{url}"],
        :inference => true
      }
    ]
  end

end
end
end
end
