##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##
module Intrigue
  module Ident
    module RdpConnectionService
      include Intrigue::Ident::RdpConnectionHelper
      include Msf
      # include Msf::Auxiliary::Scanner
      # include Msf::Auxiliary::Report
      $port = 0
      $option = []
      def initialize(_info = {})
        register_options(
          [
            3389,
            OptBool.new('DETECT_NLA', [true, 'Detect Network Level Authentication (NLA)', true])
          ]
        )
      end

      def register_options(options, owner = self.class)
        add_option(options, owner)
        # import_defaults(false)
      end

      def add_options(opts, owner = nil, advanced = false, evasion = false)
        return false if opts.nil?

        if opts.is_a?(Array)
          add_options_array(opts, owner, advanced, evasion)
        else
          add_options_hash(opts, owner, advanced, evasion)
        end
      end

      def add_option(option, name = nil, _owner = nil, _advanced = false, _evasion = false)
        if option.is_a?(Array)
          # require 'pry'; binding.pry

          $option << [name, option]

        elsif !option.is_a?(OptBase)
          raise ArgumentError,
                "The option named #{name} did not come in a compatible format.",
                caller
        end
      end

      def add_options_array(opts, owner = nil, advanced = false, evasion = false)
        opts.each do |opt|
          add_option(opt, nil, owner, advanced, evasion)
        end
      end

      def check_rdp
        begin
          rdp_connect
          is_rdp, version_info = rdp_fingerprint
        rescue ::Errno::ETIMEDOUT, Rex::HostUnreachable, Rex::ConnectionTimeout, Rex::ConnectionRefused,
               ::Timeout::Error, ::EOFError
          return false, nil
        ensure
          rdp_disconnect
        end

        service_info = nil
        if is_rdp
          product_version = version_info && version_info[:product_version] ? version_info[:product_version] : 'N/A'
          info = "Detected RDP on #{peer} (Windows version: #{product_version})"

          if datastore['DETECT_NLA']
            service_info = "Requires NLA: #{!version_info[:product_version].nil? && requires_nla? ? 'Yes' : 'No'}"
            info << " (#{service_info})"
          end

          p info
        end

        [is_rdp, service_info]
      end

      def requires_nla?
        begin
          rdp_connect
          is_rdp, server_selected_proto = rdp_check_protocol
        rescue ::Errno::ETIMEDOUT, Rex::HostUnreachable, Rex::ConnectionTimeout, Rex::ConnectionRefused,
               ::Timeout::Error, ::EOFError
          return false
        ensure
          rdp_disconnect
        end

        return false unless is_rdp

        [RDPConstants::PROTOCOL_HYBRID, RDPConstants::PROTOCOL_HYBRID_EX].include? server_selected_proto
      end

      def run_host(_ip)
        is_rdp = false
        begin
          rdp_connect
          is_rdp, service_info = check_rdp
        rescue Rex::ConnectionError => e
          vprint_error("Error while connecting and negotiating RDP: #{e}")
          return
        ensure
          rdp_disconnect
        end
        return unless is_rdp

        report_service(
          host: rhost,
          port: rport,
          proto: 'tcp',
          name: 'RDP',
          info: service_info
        )
      end
    end
  end
end
