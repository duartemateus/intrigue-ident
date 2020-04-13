# encoding: utf-8

module Intrigue
module Ident
module Http

  require_relative 'browser'
  include Intrigue::Ident::HttpBrowser
  
  #require_relative 'content_helpers'
  #include Intrigue::Ident::Content::HttpHelpers

  def ident_encode(string)
    string.force_encoding('ISO-8859-1').encode('UTF-8')
  end

  ###
  ### XXX - significant updates made to zlib, determine whether to
  ### move this over to RestClient: https://github.com/ruby/ruby/commit/3cf7d1b57e3622430065f6a6ce8cbd5548d3d894
  ###
  def ident_http_request(method, uri_string, credentials=nil, headers={}, data=nil, limit = 3, open_timeout=15, read_timeout=15)

    response = nil
    begin

      # set user agent
      user_agent = "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_11_1) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/47.0.2526.73 Safari/537.36"
      headers["User-Agent"] = user_agent

      attempts=0
      max_attempts=limit
      found = false
      timeout = false

      uri = URI.parse uri_string

      # keep track of redirects
      response_urls = ["#{uri}"]

      unless uri
        _log error "Unable to parse URI from: #{uri_string}"
        return
      end

      until( found || attempts >= max_attempts)

        attempts+=1

        if $global_config
          if $global_config.config["http_proxy"]
            proxy_config = $global_config.config["http_proxy"]
            proxy_addr = $global_config.config["http_proxy"]["host"]
            proxy_port = $global_config.config["http_proxy"]["port"]
            proxy_user = $global_config.config["http_proxy"]["user"]
            proxy_pass = $global_config.config["http_proxy"]["pass"]
          end
        end

        # set options
        opts = {}
        if uri.instance_of? URI::HTTPS
          opts[:use_ssl] = true
          opts[:verify_mode] = OpenSSL::SSL::VERIFY_NONE
        end

        http = Net::HTTP.start(uri.host, uri.port, proxy_addr, proxy_port, opts)
        http.open_timeout = open_timeout
        http.read_timeout = read_timeout

        path = "#{uri.path}"
        path = "/" if path==""

        # add in the query parameters
        if uri.query
          path += "?#{uri.query}"
        end

        ### ALLOW DIFFERENT VERBS HERE
        if method == :get
          request = Net::HTTP::Get.new(uri)
        elsif method == :post
          # see: https://coderwall.com/p/c-mu-a/http-posts-in-ruby
          request = Net::HTTP::Post.new(uri)
          request.body = data
        elsif method == :head
          request = Net::HTTP::Head.new(uri)
        elsif method == :propfind
          request = Net::HTTP::Propfind.new(uri.request_uri)
          request.body = "Here's the body." # Set your body (data)
          request["Depth"] = "1" # Set your headers: one header per line.
        elsif method == :options
          request = Net::HTTP::Options.new(uri.request_uri)
        elsif method == :trace
          request = Net::HTTP::Trace.new(uri.request_uri)
          request.body = "blah blah"
        end
        ### END VERBS

        # set the headers
        headers.each do |k,v|
          request[k] = v
        end

        # handle credentials
        if credentials
          request.basic_auth(credentials[:username],credentials[:password])
        end

        # USE THIS TO PRINT HTTP REQUEST
        #request.each_header{|h| puts "#{h}: #{request[h]}" }
        # END USE THIS TO PRINT HTTP REQUEST

        # get the response
        response = http.request(request)

        ###
        ### Handle redirects 
        ### 
        location_header = response.header['location'] || response.header['Location'] 
        if location_header != nil
          # location header redirect
          #puts "Following redirect: #{location_header}"

          newuri=URI.parse(location_header)

          # handle relative uri 
          if(newuri.relative?)
            newuri=URI.parse("#{uri}#{location_header}")
          end
          
          response_urls << ident_encode(newuri.to_s)
          uri=newuri

        elsif response.body =~ /META HTTP-EQUIV=\"?Refresh/i # meta refresh
          # meta refresh redirect

          # get the URL 
          metaurl = URI.parse(response.body.scan(/META HTTP-EQUIV=Refresh CONTENT=.*; URL=(.*)"/i).first)
          
          if metaurl
            newuri = metaurl.first  
          else # unable to parse 
            puts "ERROR Unable to parse redirection!!"
            found = true 
            break 
          end
          
          # handle relative uri 
          if(newuri.relative?)
            newuri=URI.parse("#{uri}/#{newuri}")
          end
          
          response_urls << ident_encode(newuri.to_s)
          uri=newuri

        else

          found = true
          break

        end #end redirect handling

        ###
        ### Done Handling Redirects, proactively set final_url
        ###
        final_url = uri

      end #until

    ### TODO - create a global $debug config option
    
    #rescue ArgumentError => e
      #puts "Unable to connect #{uri}: #{e}"
    rescue Net::OpenTimeout => e
      #puts "Unable to connect #{uri}: #{e}"
      timeout = true
    rescue Net::ReadTimeout => e
      #puts "Unable to connect #{uri}: #{e}"
      timeout = true
    rescue Errno::ENETDOWN => e
      #puts "Unable to connect #{uri}: #{e}" 
    rescue Errno::ETIMEDOUT => e
      #puts "Unable to connect #{uri}: #{e}" 
      timeout = true
    rescue Errno::EINVAL => e
      #puts "Unable to connect #{uri}: #{e}"
    rescue Errno::ENETUNREACH => e
      #puts "Unable to connect #{uri}: #{e}"
    rescue Errno::EHOSTUNREACH => e
      #puts "Unable to connect #{uri}: #{e}"
    rescue URI::InvalidURIError => e
      #
      # XXX - This is an issue. We should catch this and ensure it's not
      # due to an underscore / other acceptable character in the URI
      # http://stackoverflow.com/questions/5208851/is-there-a-workaround-to-open-urls-containing-underscores-in-ruby
      #
      #puts "Unable to connect #{uri}: #{e}"
    rescue OpenSSL::SSL::SSLError => e
      #puts "Unable to connect #{uri}: #{e}" 
    rescue Errno::ECONNREFUSED => e
      #puts "Unable to connect #{uri}: #{e}" 
    rescue Errno::ECONNRESET => e
      #puts "Unable to connect #{uri}: #{e}" 
    rescue Net::HTTPBadResponse => e
      #puts "Unable to connect #{uri}: #{e}" 
    rescue Zlib::BufError => e
      #puts "Unable to connect #{uri}: #{e}" 
    rescue Zlib::DataError => e # "incorrect header check - may be specific to ruby 2.0"
      #puts "Unable to connect #{uri}: #{e}" 
    rescue EOFError => e
      #puts "Unable to connect #{uri}: #{e}" 
    rescue SocketError => e
      #puts "Unable to connect #{uri}: #{e}" 
    rescue Encoding::InvalidByteSequenceError => e
      #puts "Encoding issue #{uri}: #{e}" 
    rescue Encoding::UndefinedConversionError => e
      #puts "Encoding issue #{uri}: #{e}" 
    end

    # generate our output
    out = {
      :timeout => timeout,
      :start_url => uri_string,
      :final_url => final_url.to_s,
      :request_type => :ruby,
      :request_method => method,
      :request_credentials => credentials,
      :request_headers => headers,
      :request_data => data,
      :request_attempts_limit => limit,
      :request_attempts_used => attempts,
      :request_user_agent => user_agent,
      :request_proxy => proxy_config,
      :response_urls => response_urls,
      :response_object => response
    }

    # verify we have a response before adding these
    if response
      out[:response_headers] = response.each_header.map{|x| ident_encode "#{x}: #{response[x]}" }
      out[:response_body] = ident_encode(response.body)
    end

    out
  end

end
end
end