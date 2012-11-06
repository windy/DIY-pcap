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
      @timeout = nil
      @error_on_stop = nil
      @fail_count = 0
    end
    
    def run
      do_trap
      client = @client
      server = @server
      
      @fail_count = 0
      start_time = Time.now
      #clear
      client.terminal
      server.terminal
      
      loop do
        begin
          pkts, where = @offline.nexts
          case where
          when :A
            client, server = @client, @server
          when :B
            client, server = @server, @client
          end
          one_round( client, server, pkts )
        rescue HopePacketTimeoutError, UserError, FFI::PCap::LibError => e
          DIY::Logger.warn( "Timeout: Hope packet is #{pkts[0].pretty_print} ") if e.kind_of?(HopePacketTimeoutError)
          @fail_count += 1
          if @error_on_stop and e.kind_of?(HopePacketTimeoutError)
            client.terminal
            server.terminal
            DIY::Logger.info "Error_on_stop flag opened, stopping..."
            DIY::Logger.info "Dump mac learn table(size is #{@offline.mac_learner.size})... "
            DIY::Logger.info @offline.mac_learner.dump
            break
          end
          begin
            @offline.next_pcap
            client.terminal
            server.terminal
          rescue EOFError
            client.terminal
            server.terminal
            break
          end
          #~ client,server = @client, @server
        rescue EOFError
          client.terminal
          server.terminal
          break
        ensure
          #~ client, server = server, client
        end
      end
      DRb.stop_service
      end_time = Time.now
      stats_result( end_time - start_time, @fail_count )
    end
    
    def do_trap
      Signal.trap("INT") do
        DIY::Logger.info "bye.."
        stop
        exit 0
      end    
    end
    
    def stop
      @client.terminal
      @server.terminal
    end
    
    def one_round( client, server, pkts )
      @error_flag = nil
      @round_count = 0 unless @round_count
      @round_count += 1
      DIY::Logger.info "round #{@round_count}: (c:#{client.__drburi} / s:#{server.__drburi}) #{pkts[0].pretty_print}:(queue= #{pkts.size})"
      
      # check is client or server at this time
      # give the flag to **before_send** block
      client_or_server = client == @client
      
      before_send_call(pkts, client_or_server)
      
      recv_pkt_proc_set( pkts )
      @ready = false
      server.ready(&@recv_pkt_proc)
      @ready = true
      client_send(client, pkts)
      wait_recv_ok(pkts)
      server.terminal
    end
    
    # 设置回调入口, 由 worker 通过DRb 远程调用
    def recv_pkt_proc_set(queue)
      @queue_keeper = queue
      # 不重新赋值, 防止 DRb 回收
      @recv_pkt_proc ||= lambda do |recv_pkt|
        begin
          next unless @ready # strip this recv pkt unless it's ready to.
          next if @error_flag # error accur waiting other thread do with it
          @recv_pkt_keeper = Packet.new(recv_pkt)
          @strategy.call(@queue_keeper.first, @recv_pkt_keeper, @queue_keeper)
        rescue DIY::UserError =>e
          DIY::Logger.warn("UserError Catch: " + e.inspect)
          e.backtrace.each do |msg|
            DIY::Logger.info(msg)
          end
          @error_flag = e
        end        
      end
    end
    
    def client_send(client, pkts)
      #~ pkt_contents = pkts.collect { |pkt| pkt.content }
      begin
        client.inject(pkts)
      rescue FFI::PCap::LibError =>e
        DIY::Logger.info("SendPacketError Catch: " + e )
        raise e
      end
    end
    
    def before_send_call(pkts, client_flag)
      return unless @before_send
      pkts.delete_if do |pkt|
        begin
          ret = @before_send.call( pkt, client_flag )
        rescue Exception => e
          DIY::Logger.warn("UserError Catch: " + error = BeforeSendCallError.new(e) )
          error.backtrace.each do |msg|
            DIY::Logger.info(msg)
          end
          raise error
        end
        ! ret
      end
      pkts
    end
    
    def before_send(&block)
      @before_send = block
    end
    
    def timeout(timeout)
      @timeout = timeout
    end
    
    def error_on_stop(*)
      @error_on_stop = true
    end
    
    def stats_result( cost_time, fail_count )
      DIY::Logger.info " Finished in #{cost_time} seconds"
      DIY::Logger.info " #{offline_result}, #{fail_count} failures"
    end
    
    def offline_result
      sprintf "%4d files, running %8d packets", @offline.files_size, @offline.now_size
    end
    
    def wait_recv_ok(pkts)
      loop do 
        now_size = pkts.size
        break if now_size == 0
        wait_until(@timeout ||= 10) do
          raise @error_flag if @error_flag
          pkts.size < now_size
        end
      end
    end
    
    def wait_until( timeout = 10, &block )
      Timeout.timeout(timeout, DIY::HopePacketTimeoutError.new("hope packet wait timeout after #{timeout} seconds") ) do
        loop do
          break if block.call
          sleep 0.01
        end
      end
    end
    
  end
end
  