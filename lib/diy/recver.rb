module DIY  
  class Recver
    def initialize(live)
      @live = live
      @watchers = []
    end
    
    def run
      @live.loop do |this, pkt|
        notify_recv_pkt(pkt)
      end
    end
    
    def stop
      @live.stop
    end
    
    def notify_recv_pkt(pkt)
      @watchers.each do |watcher|
        watcher.recv_pkt(pkt.body)
      end
    end
    
    def add_watcher(watcher)
      @watchers = [] unless @watchers
      @watchers << watcher
    end
    
    def del_watcher(watcher)
      @watchers.delete(watcher)
    end
  end
end