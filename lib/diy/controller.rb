module DIY
  class Controller
    def initialize(live, offline, strategy)
      @live = live
      @recver = Recver.new(@live)
      @recver.add_watcher(strategy)
      @recver_t = nil
      @sender = Sender.new(@live)
      @queue = strategy.queue
      @logger = Logger.new(STDOUT)
    end
    attr_accessor :logger
    
    def run
      @recver_t = Thread.new do
        @recver.run
      end
      
      begin
        @queue.do_loop do pkt
          @sender.inject(pkt)
        end
        @recver_t.join
      rescue EOFError
        @recver.stop
      end
    end
    
  end
end
  