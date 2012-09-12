module DIY
  class Error < RuntimeError; end
  # 数据包读取完毕
  class EOFError < Error; end
  
  # 期望报文等待超时
  class HopePacketTimeoutError < Error; end
  
  # 没有报文被指定时
  class ZeroOfflineError < Error; end
  
end