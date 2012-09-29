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
        DIY::Logger.info "send pkt: #{pkt.inspect}"
        @live.send_packet(pkt.content)
      end
    end
    
    def loop_recv
      @recv_t = Thread.new do
        DIY::Logger.info "start thread recving pkt..."
        @live.loop do |this, pkt|
          next unless @start
          begin
            @block.call(pkt.body) if @block
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
      @start = true
    end
    
    def terminal
      DIY::Logger.info("stop recv pkt")
      @start = false
    end
    
    def inspect
      "<Worker: #{@live.net}>"
    end
  
  end
end