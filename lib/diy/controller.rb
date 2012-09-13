# encoding : utf-8
module DIY
  class Controller
    def initialize(live, strategy)
      @live = live
      @recver = Recver.new(@live)
      @recver.add_watcher(strategy)
      @recver_t = nil
      @sender = Sender.new(@live)
      @queue = strategy.queue
      @logger = DIY::Logger
    end
    attr_accessor :logger
    
    def before_send(&block)
      @sender.before_send(&block)
    end
    
    def run
      # 接收线程
      @recver_t = Thread.new do
        @recver.run
      end
      
      begin
        @queue.do_loop do |pkt|
          logger.info "send pkt: #{pp(pkt)}"
          @sender.inject(pkt)
        end
        @recver_t.join
      rescue HopePacketTimeoutError =>e
        # next offline
        DIY::Logger.warn("Timeout: #{e}")
        old = e
        begin
          @queue.clear_and_next_pcap
          retry
        rescue EOFError
          @recver.stop
          raise old
        end
      rescue EOFError
        @recver.stop
      end
    end
    
  end
end
  