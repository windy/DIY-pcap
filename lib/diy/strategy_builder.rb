# encoding : utf-8
require 'logger'
module DIY
  class StrategyBuilder
    def initialize
      @ins = []
      @logger = DIY::Logger
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
    
    def call(hope_pkt, recv_pkt, queue)
      logger.debug("recv_pkt, I hope: #{ Utils.pp(hope_pkt) rescue nil }...")
      
      return if hope_pkt.nil?
      
      @ins.each do |strategy|
        begin
          ret = strategy.call(hope_pkt.content, recv_pkt.content, queue)
        rescue Exception => e
          logger.error("user strategy exception: #{e.class} -> #{e.message}")
          raise
        else
          if ret == Strategy::OK
            logger.info("pkt same:")
            queue.shift
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
