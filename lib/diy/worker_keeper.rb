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
      DRb.start_service(@uri, @worker)
      DRb.thread.join
    end
  end
end