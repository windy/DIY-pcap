# encoding : utf-8
require 'logger'
module DIY
  class StrategyBuilder
    def initialize(queue)
      @ins = []
      @logger = DIY::Logger
      @queue = queue
    end
    attr_reader :queue
    
    def add(strategy)
      @ins << strategy
    end
    alias << add
    
    def logger=(logger)
      @logger = logger
    end
    
    def logger
      @logger
    end
    
    def recv_pkt(pkt)
      recv_pkt_queue(queue,pkt)
    end
    
    def recv_pkt_queue(queue, recv_pkt)
      hope_pkt = queue.peek
      logger.debug("recv_pkt, I hope: #{ hope_pkt[0..10].dump rescue nil }...")
      
      return if hope_pkt.nil?
      
      @ins.each do |strategy|
        begin
        ret = strategy.call(hope_pkt, recv_pkt, queue)
        rescue Exception => e
          logger.error("user strategy exception: #{e.class} -> #{e.message}")
          raise
          #TODO 也许仅仅忽略?
        else
          if ret == Strategy::OK
            logger.info("pkt same:")
            queue.pop
            return
          elsif ret == Strategy::OK_NO_POP
            logger.info("pkt skip:")
            return
          elsif ret == Strategy::FAIL
            logger.warn("pkt fail:")
            logger.warn("pkt fail: hope_pkt is #{Utils.pp(hope_pkt)}")
            logger.warn("pkt fail: recv_pkt is #{Utils.pp(recv_pkt)}")
            #TODO 也许需要将Queue输出?
            raise UnExpectPacketError, "strategy FAIL"
          elsif ret == Strategy::NONE
            #~ logger.debug("pkt jumpped:")
            next
          end # end of if
        end # end of begin
      end # end of each
    end
    
  end
end
