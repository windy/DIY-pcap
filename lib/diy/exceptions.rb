module DIY
  class Error < RuntimeError; end
  # 数据包读取完毕
  class EOFError < Error; end
end