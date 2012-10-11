# encoding : utf-8
require 'drb'
require 'diy/worker'

module DIY
  # 创建DRb服务
  class WorkerKeeper
    def initialize(worker, uri)
      @worker = worker
      @uri = uri
      @running = false
      @over = false
      yield self if block_given?
    end
    attr_accessor :running
    
    def use_timeridconv
      require 'drb/timeridconv'
      DRb.install_id_conv DRb::TimerIdConv.new    
    end
    
    def run
      Thread.abort_on_exception = true
      DIY::Logger.info "serving at #{@uri}"
      DRb.start_service(@uri, @worker)
      @running = true
      @over = false
      trap("INT") { @running = false }
      while @running
        sleep 0.5
      end
      DIY::Logger.info "bye..."
      @worker.stop
      DRb.stop_service
      @over = true
    end
    
    def stop
      @running = false
      Utils.wait_until { @over }
    end
  end
end