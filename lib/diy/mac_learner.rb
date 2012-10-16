module DIY
  class MacLearner
    def initialize(default_host = :A)
      @default_host = default_host
      @table = {}
    end
    
    #
    def learn(packet, where)
      raise "Only receive :A or B for where argument" unless where == :A or where == :B
      #~ @table.delete( src(packet) )
      _learn( src(packet), where)
    end
    
    def _learn(mac, where)
      @table[mac] = where
    end
    
    # 报告包所在的端口 A or B
    # 如果包不在学习表内, 返回缺省端口(默认为A)
    def tellme(packet)
      src_p = src(packet)
      dst_p = dst(packet)
      
      if src_p == dst_p
        DIY::Logger.warn("Found SRC mac is the same with DST mac: #{Utils.pp(packet)}")
        return @default_host
      end
      
      if @table.has_key?(src_p) && @table.has_key?(dst_p) && @table[src_p] == @table[dst_p]
        raise "Found the same mac learner: packet is #{Utils.pp(packet)}"
      end
      
      if @table.has_key? src_p
        where =  @table[src_p]
      elsif @table.has_key? dst_p
        where = other( @table[dst_p] )
        _learn( src(packet), where )
      else
        where = @default_host
        _learn( src(packet), where )
      end
      _learn( dst(packet), other(where) )
      where
    end
    
    def other(where)
      if where == :A
        return :B
      elsif where == :B
        return :A
      else
        raise "Argument error"
      end
    end
    
    
    private
    def  src(packet)
      Utils.src_mac(packet)
    end
    
    def dst(packet)
      Utils.dst_mac(packet)
    end
  end
end