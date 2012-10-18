module DIY
  class MacLearner
    BROAD_MAC = "\377" * 6 # ff:ff:ff:ff:ff:ff
    GROUP_MAC = 1
    LEARN_TIME = 60 * 5 # five minutes
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
      # 除去组播与广播
      return if mac == BROAD_MAC
      return if mac[0] & GROUP_MAC == 1
      set(mac, where)
    end
    
    def get(mac)
      @table[mac] && @table[mac][0]
    end
    
    def get_time(mac)
      @table[mac] && @table[mac][1]
    end
    
    def set(mac, where)
      time_now = Time.now
      if @table[mac]
        if @table[mac][0] != where
          if (time_now - @table[mac][1]) <= LEARN_TIME
            raise DIY::MacLearnConflictError, "Found mac learn port confict when set #{Utils.pp_mac(mac)} to #{where}"
          end
        end
      end
      @table[mac] = [ where, time_now ]
    end
    
    def clear(mac)
      @table[mac] = nil
    end
    
    # 报告包所在的端口 A or B
    # 如果包不在学习表内, 返回缺省端口(默认为A)
    def tellme(packet)
      valid!(packet)
      src_p = src(packet)
      dst_p = dst(packet)
      
      if src_p == dst_p
        DIY::Logger.debug("Found SRC mac is the same with DST mac: #{Utils.pp(packet)}")
        #~ where = @default_host
        #~ _learn(src_p, where)
        #~ return where
      end
      
      if src_p != dst_p && get(src_p) && get(src_p) == get(dst_p)
        #~ if (get_time(src_p) - get_time(dst_p)).abs <= LEARN_TIME
          #~ DIY::Logger.warn "Found the same mac learner: packet is #{Utils.pp(packet)}"
          raise DIY::MacLearnConflictError, "Found mac learn port confict"
        #~ else
          #~ cls = get_time(src_p) > get_time(dst_p) ? dst_p : src_p
          #~ clear(cls)
        #~ end
      end
      
      if get(src_p)
        where =  get(src_p)
        _learn( src_p, where )
      elsif get(dst_p)
        where = other( get(dst_p) )
        _learn( src_p, where )
      else
        where = @default_host
        _learn( src_p, where )
      end
      _learn( dst_p, other(where) )
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
    
    def valid!(packet)
      raise DIY::PacketInvalidError, "packet too small" unless packet.size >= 12
    end
  end
end