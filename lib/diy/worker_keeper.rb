# encoding : utf-8
require 'drb'
require 'diy/worker'

module DIY
  # 创建DRb服务
  class WorkerKeeper
    def initialize(worker, uri)
      @worker = worker
      @uri = uri
    end
    
    def run
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