module DIY
  # 这个策略是一个最基本的: 
  # 具体返回值含义见 @BasicStrategy
  class Strategy
    OK = true
    OK_NO_POP = 1
    FAIL = false
    NONE = nil
  end
  
  class BasicStrategy < Strategy
    
    # @argument:
    # hope_pkt: 期望的报文
    # recv_pkt: 接收的报文
    # queue: 期望接收队列, 如果期望乱序时,你可以使用这个参数
    # 
    # @return: 
    # OK : 匹配, 可以进行下一个报文的处理
    # OK_NO_POP: 匹配了接收队列中的报文, 但是不需要框架自动pop掉期望报文( 注意, 你需要自行处于报文 )
    # FAIL: 肯定失败时使用
    # NONE: 不匹配, 让框架进行下一个报文匹配
    def call(hope_pkt, recv_pkt, queue)
      raise "write code here"
    end
  end
  
  class SimpleStrategy < BasicStrategy
    def call(hope_pkt, recv_pkt, queue)
      if hope_pkt == recv_pkt
        return OK
      else
        return NONE
      end
    end
  end
  
end
  