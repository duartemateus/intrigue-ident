module Intrigue
  module Ident
    module Ntp
      include Intrigue::Ident::SimpleSocket

      # gives us the recog Ntp matchers
      include Intrigue::Ident::RecogWrapper::Ntp

      def generate_ntp_request_and_check(ip, port = 123, _debug = false)
        p port
        # do the request (store as string and funky format bc of usage in core.. and  json conversions)
        banner_string = grab_banner_ntp(ip, port)
        details = {
          'details' => {
            'banner' => banner_string
          }
        }

        results = []
        checks = []
        unless Intrigue::Ident::Ntp::CheckFactory.checks.nil?
          # generate the checks
          checks = Intrigue::Ident::Ntp::CheckFactory.checks.map do |x|
            x.new.generate_checks
          end.compact.flatten
        end
        # and run them against our result
        checks.each do |check|
          results << match_ntp_response_hash(check, details)
        end

        # Run recog across the banner
        recog_results = recog_match_ntp_banner(banner_string)

        { 'fingerprint' => (results + recog_results).uniq.compact, 'banner' => banner_string, 'content' => [] }
      end

      private

      def grab_banner_ntp(ip, port, _timeout = 30)
        if socket = connect_udp(ip, port)

          # u1 = UDPSocket.new
          # u1.bind(port, ip)
          # u2 = UDPSocket.new
          # u2.connect(port, ip)
          # u2.send 'test', 0
          # p u1.recvfrom(10)

          # require 'pry'; binding.pry

          # socket.writepartial("HELO friend.local\r\n\r\n")
          begin
            out = socket.read
          rescue Errno::EHOSTUNREACH
            puts 'Error while reading! Reset.'
            out = nil
          rescue Errno::ECONNRESET
            puts 'Error while reading! Reset.'
            out = nil
          rescue Socketry::TimeoutError
            puts 'Error while reading! Timeout.'
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
