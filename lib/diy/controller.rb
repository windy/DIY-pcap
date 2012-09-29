# encoding : utf-8

require 'timeout'
module DIY
  class Controller
    def initialize( client, server, offline, strategy)
      @client = client
      @server = server
      @offline = offline
      @strategy = strategy
      @before_send = nil
    end
    
    def run
      client = @client
      server = @server
      
      @fail_count = 0
      start_time = Time.now
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
          @fail_count += 1
          begin
          @offline.next_pcap
          rescue EOFError
            client.terminal
            server.terminal
            break
          end
          client,server = @client, @server
        rescue EOFError
          client.terminal
          server.terminal
          break
        end
      end
      DRb.stop_service
      end_time = Time.now
      stats_result( end_time - start_time, @fail_count )
    end
    
    def one_round( client, server, pkts )
      @round_count = 0 unless @round_count
      @round_count += 1
      DIY::Logger.info "round #{@round_count}: (c:#{client.__drburi} / s:#{server.__drburi}) #{pkts[0].inspect}:(size= #{pkts.size})"
      server.ready do |recv_pkt|
        recv_pkt = Packet.new(recv_pkt)
        @strategy.call(pkts.first, recv_pkt, pkts)
      end
      client_send(client, pkts)
      wait_recv_ok(pkts)
      server.terminal
    end
    
    def client_send(client, pkts)
      if ! @before_send
        client.inject(pkts)
      else
        pkts = pkts.collect do |pkt| 
          content = pkt.content
          pkt.content = @before_send.call(content)
          pkt
        end
        
        client.inject(pkts)
      end
    end
    
    def before_send(&block)
      @before_send = block
    end
    
    def stats_result( cost_time, fail_count )
      DIY::Logger.info " ====== Finished in #{cost_time} seconds"
      DIY::Logger.info " ====== Total fail_count: #{fail_count} failures"
    end
    
    def wait_recv_ok(pkts)
      wait_until { pkts.empty? }
    end
    
    def wait_until( timeout = 10, &block )
      timeout(timeout, DIY::HopePacketTimeoutError.new("hope packet wait timeout after #{timeout} seconds") ) do
        loop do
          break if block.call
          sleep 0.01
        end
      end
    end
    
  end
end
  