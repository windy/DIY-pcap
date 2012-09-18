# encoding : utf-8
require 'diy/packet'
require 'drb'
module DIY
  include DRbUndumped
  class Worker
    def initialize(live)
      @live = live
      @recv_t = nil
    end
  
    # 发包
    def inject(pkts)
      pkts.each do |pkt|
        DIY::Logger.info "send pkt"
        @live.inject(pkt.content)
      end
    end
    
    #收包
    def ready(&block)
      @recv_t = Thread.new do
        DIY::Logger.info "ready to recv"
        @live.loop do |this, pkt|
          #~ DIY::Logger.info "recv pkt:"
          #~ pkt = Packet.new(pkt)
          block.call(pkt.body)
        end
      end
    end
    
    def terminal
      if @recv_t
        @live.stop
      end
    end
  
  end
end