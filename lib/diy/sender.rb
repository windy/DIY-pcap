module DIY
  class Sender
    def initialize(live)
      @live = live
      @before_send_hook = nil
    end
    
    def inject(pkt)
      pkt = before_send_call(pkt)
      @live.inject(pkt)
    end
    
    def before_send(&block)
      @before_send_hook = block
    end
    
    def before_send_call(pkt)
      if @before_send_hook
        @before_send_hook.call(pkt)
      else
        pkt
      end
    end
    
  end
end