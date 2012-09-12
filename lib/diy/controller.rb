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
          @sender.inject(pkt)
        end
        @recver_t.join
      rescue HopePacketTimeoutError
        # next offline
        begin
          @queue.clear_and_next_pcap
        rescue EOFError
          @recver.stop
        end
      rescue EOFError
        @recver.stop
      end
    end
    
  end
end
  