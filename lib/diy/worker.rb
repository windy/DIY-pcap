# encoding : utf-8
require 'diy/packet'
require 'drb'
module DIY
  include DRbUndumped
  class Worker
    def initialize(live)
      @live = live
      @recv_t = nil
      @start = false
      loop_recv
    end
  
    # 发包
    def inject(pkts)
      pkts.each do |pkt|
        DIY::Logger.info "send pkt"
        @live.send_packet(pkt.content)
      end
    end
    
    def loop_recv
      @recv_t = Thread.new do
        DIY::Logger.info "ready to recv"
        @live.loop do |this, pkt|
          next unless @start
          @block.call(pkt.body) if @block
        end
      end
    end
    
    #收包
    def ready(&block)
      @block = block
      @start = true
    end
    
    def terminal
      @start = false
    end
    
    def inspect
      "<Worker: #{@live.net}>"
    end
  
  end
end