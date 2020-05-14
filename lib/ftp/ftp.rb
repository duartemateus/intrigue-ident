module Intrigue
  module Ident
    module Ftp

      include Intrigue::Ident::SimpleSocket

      def generate_ftp_request_and_check(ip, port=21, debug=false)

        # do the request (store as string and funky format bc of usage in core.. and  json conversions)
        banner_string = grab_banner_ftp(ip,port)
        details = {
          "details" => {
            "banner" => banner_string
          }
        }
  
        results = []
  
        # generate the checks 
        checks = Intrigue::Ident::Ftp::CheckFactory.checks.map{ |x| x.new.generate_checks }.compact.flatten
  
        # and run them against our result
        checks.each do |check|
          results << match_smtp_response_hash(check,details)
        end
  
      results.map{|x| (x || {}).merge({"banner" => banner_string})}.uniq.compact
      end


      private 

      def grab_banner_ftp(ip, port, timeout=30)
          
        if socket = connect_tcp(ip, port, timeout)
          #socket.writepartial("HELO friend.local\r\n\r\n")
          begin 
            out = socket.readpartial(2048, timeout: timeout)
          rescue Socketry::TimeoutError
            puts "Error while reading! Timeout."
            out = nil
          end
        else 
          out = nil
        end
        
      out
      end

    end
  end
end
