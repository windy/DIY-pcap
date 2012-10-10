# encoding : utf-8
require 'diy/packet'
require 'drb'
require 'thread'

module DIY
  class Worker
    
    include DRbUndumped
    
    def initialize(live)
      @live = live
      @recv_t = nil
      @start = false
      @queue = Queue.new
      loop_recv
      loop_callback
    end
  
    # 发包
    def inject(pkts)
      pkts.each do |pkt|
        DIY::Logger.info "send pkt: #{pkt.inspect}"
        @live.send_packet(pkt.content)
      end
    end
    
    def loop_recv
      @recv_t = Thread.new do
        DIY::Logger.info "start thread recving pkt..."
        @live.loop do |this, pkt|
          next unless @start
          @queue.push(pkt.body)
        end
      end
    end
    
    def loop_callback
      @callback_t = Thread.new do 
        #~ DIY::Logger.info "start thread callbacking pkt..."
        loop do
          begin
            pkt = @queue.pop
            #~ DIY::Logger.info "callback: #{pkt}"
            @block.call(pkt) if @block
          rescue DRb::DRbConnError
            DIY::Logger.info "closed connection by controller"
          end
        end
      end
    end
    
    #收包
    def ready(&block)
      DIY::Logger.info("start recv pkt")
      @block = block
      @queue.clear
      @start = true
    end
    
    def terminal
      DIY::Logger.info("stop recv pkt")
      @start = false
      @queue.clear
    end
    
    def inspect
      "<Worker: #{@live.net}>"
    end
  
  end
end