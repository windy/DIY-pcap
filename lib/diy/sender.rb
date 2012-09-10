module DIY
  class Sender
    def initialize(live)
      @live = live
    end
    
    def inject(pkt)
      puts "send: #{Time.now}"
      @live.inject(pkt)
    end
  end
end