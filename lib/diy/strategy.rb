module DIY
  # 这个策略是一个最基本的: 
  # 具体返回值含义见 @BasicStrategy
  class Strategy
    OK = "S_OK"
    OK_NO_POP = SKIP = "S_OK_NO_POP"
    FAIL = "S_FAIL"
    NONE = "S_NONE"
    NONE_HOPE_SKIP = NONE_HOPE_POP = "S_NONE_HOPE_POP" 
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
    # SKIP: 同上, 可用于跳过以后所有策略队列使用.
    # FAIL: 肯定失败时使用
    # NONE: 不匹配, 让框架进行下一个报文匹配
    # NONE_HOPE_POP: 跳过期望报文, 但继续让框架进行下一个报文匹配
    def call(hope_pkt, recv_pkt, queue)
      raise "write code here"
    end
  end
  
  # 一个简单的例子
  class SimpleStrategy < BasicStrategy
    def call(hope_pkt, recv_pkt, queue)
      if hope_pkt == recv_pkt
        return OK
      else
        return NONE
      end
    end
  end
  
  # 跳过相同源与目的MAC
  class SkipSameMacStrategy < BasicStrategy
    def call(hope_pkt, recv_pkt, queue)
      if hope_pkt[0..5] == hope_pkt[6..11]
        return NONE_HOPE_POP
      else
        return NONE
      end
    end    
  end
  
end
  