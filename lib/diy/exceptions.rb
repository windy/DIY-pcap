module DIY
  class Error < RuntimeError; end
  # 数据包读取完毕
  class EOFError < Error; end
  
  # 期望报文等待超时
  class HopePacketTimeoutError < Error; end
  
  # 没有报文被指定时
  class ZeroOfflineError < Error; end
  
  # 报文分解失败
  class MacLearnConflictError < Error; end
  class PacketInvalidError < Error; end
  
  class UserError < Error
    def initialize(real_exception)
      @real_exception = real_exception
      @name = real_exception.class
      @message = real_exception.message
      set_backtrace( Utils.filter_backtrace(real_exception) )
    end
    
    def inspect
      "#<#{self.class.name}: @real_exception=#{@name}, @real_msg=#{@message}>"
    end
  end
  
    # 不可能出现的报文出现
  class UnExpectPacketError < UserError; end
  
  # 策略执行异常
  class StrategyCallError < UserError; end
  # before_send 异常
  class BeforeSendCallError < UserError; end
end