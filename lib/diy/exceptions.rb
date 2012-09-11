module DIY
  class Error < RuntimeError; end
  # 数据包读取完毕
  class EOFError < Error; end
  
  # 期望报文等待超时
  class HopePacketTimeoutError < Error; end
end