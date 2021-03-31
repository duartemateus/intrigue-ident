require 'socketry'

module Intrigue
  module Ident
    module SimpleSocket
      # Connect to a given IP address and port.
      # @param ip [String]
      # @param port [Integer]
      # @return [TCPSocket, false]
      def connect_tcp(ip, port, timeout = 10)
        unless ip && port
          puts 'Missing IP or Port! Refused.'
          return nil
        end

        begin
          Socketry::TCP::Socket.connect(ip.strip, port, local_addr: nil, local_port: nil, timeout: timeout)
        rescue Errno::ENETUNREACH => e
          puts 'Error connecting! Refused.'
          nil
        rescue Socketry::ConnectionRefusedError => e
          puts 'Error connecting! Refused.'
          nil
        rescue Socketry::Resolver::Error => e
          puts 'Error connecting! Unable to resolve.'
          nil
        rescue Socketry::TimeoutError => e
          puts 'Error connecting! Timeout!'
          nil
        end
      end

      # Connect to a given IP address and port.
      # @param ip [String]
      # @param port [Integer]
      # @return [UDPSocket, false]
      def connect_udp(ip, port)
        Socketry::UDP::Socket.connect(ip.strip, port)
      rescue Socketry::Resolver::Error
        puts 'Error connecting! Unable to resolve.'
        nil
      rescue Socketry::TimeoutError
        puts 'Error connecting! Timeout.'
        nil
      end
    end
  end
end
