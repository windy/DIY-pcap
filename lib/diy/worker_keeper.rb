# encoding : utf-8
require 'drb'
require 'diy/worker'

module DIY
  # 创建DRb服务
  class WorkerKeeper
    def initialize(worker, uri)
      @worker = worker
      @uri = uri
      yield self if block_given?
    end
    
    def use_timeridconv
      require 'drb/timeridconv'
      DRb.install_id_conv DRb::TimerIdConv.new    
    end
    
    def run
      Thread.abort_on_exception = true
      DIY::Logger.info "serving at #{@uri}"
      DRb.start_service(@uri, @worker)
      running = true
      trap("INT") { running = false }
      while running
        sleep 0.5
      end
      DIY::Logger.info "bye..."
      DRb.stop_service
    end
  end
end