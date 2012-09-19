# encoding : utf-8

require 'timeout'
module DIY
  class Controller
    def initialize( client, server, offline, strategy)
      @client = client
      @server = server
      @offline = offline
      @strategy = strategy
    end
    
    def run
      client = @client
      server = @server
      
      #clear
      client.terminal
      server.terminal
      
      loop do
        begin
        pkts = @offline.nexts
        one_round( client, server, pkts )
        client, server = server, client
        rescue HopePacketTimeoutError
          DIY::Logger.warn( "Timeout: Hope packet is #{pkts[0].inspect} ")
          @offline.next_pcap
          client,server = @client, @server
        rescue EOFError
          client.terminal
          server.terminal
          break
        end
      end
    end
    
    def one_round( client, server, pkts )
      @round_count = 0 unless @round_count
      @round_count += 1
      DIY::Logger.info "round #{@round_count}: #{client} #{server} #{pkts[0].inspect}:(size= #{pkts.size})"
      server.ready do |recv_pkt|
        recv_pkt = Packet.new(recv_pkt)
        @strategy.call(pkts.first, recv_pkt, pkts)
      end
      client.inject(pkts)
      wait_recv_ok(pkts)
      server.terminal
    end
    
    def wait_recv_ok(pkts)
      wait_until { pkts.empty? }
    end
    
    def wait_until( timeout = 20, &block )
      timeout(timeout, DIY::HopePacketTimeoutError.new("hope packet wait timeout after #{timeout} senconds") ) do
        loop do
          break if block.call
          sleep 0.01
        end
      end
    end
    
  end
end
  