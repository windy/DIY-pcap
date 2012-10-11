# encoding : utf-8

module DIY
  class Offline
    def initialize( pcap_files )
      @pcap_files = [ pcap_files ] if pcap_files.kind_of?(String)
      @pcap_files ||= pcap_files
      @off = FFI::PCap::Offline.new(@pcap_files[0])
      # 记录文件在目录中的位置
      @position = 0
      # 记录包在当前文件的位置
      @num = 0
      
      @tmp_pcap = nil
    end
    
    def nexts
      ret = []
      # 取一个
      pkt = fetch_one
      if pkt.nil?
        next_pcap
        pkt = fetch_one
      end
      
      ret << pkt
      op = "=="
      if ! fetch_cached_mac
        cached_mac(pkt)
      else
        if Utils.src_mac(pkt) != fetch_cached_mac
          op = "!="
        end
      end
      
      loop do
        pkt = self.next
        if pkt.nil?
          return ret
        end
        
        if compare_mac( op, Utils.src_mac(pkt), fetch_cached_mac)
          ret << pkt
        else
          cached(pkt)
          return ret
        end
        
      end
      
    end
    
    def compare_mac( op, mac1, mac2)
      if op == "=="
        mac1 == mac2
      elsif op == "!="
        mac1 != mac2
      else
        raise "error op"
      end
    end
    
    def fetch_one
      pkt = fetch_cache
      if pkt.nil?
        pkt = self.next
      end
      pkt
    end
    protected
    # 只处理当前文件
    def next
      pkt = @off.next
      @num += 1
      return nil if pkt.nil?

      return Packet.new(pkt.copy.body, fullname)
    end
    
    def cached(pkt)
      raise "Can't cached one pkt twice" if @tmp_pcap
      @tmp_pcap = pkt
    end
    
    def cached_mac(pkt)
      @src = Utils.src_mac(pkt)
    end
    
    def fetch_cached_mac
      @src
    end
    
    def clear_cached_mac
      @src = nil
    end
    
    def fetch_cache
      if @tmp_pcap
        tmp = @tmp_pcap
        @tmp_pcap = nil
        return tmp
      end
      return nil
    end
    
    def first_pkt?
      puts @num
      @num == 1
    end
    public
    def next_pcap
      if @position >= @pcap_files.size - 1
        raise EOFError, " end of pcaps "
      end
      @position += 1
      DIY::Logger.info("pcap file changed: #{@pcap_files[@position]} ( #{@position} of #{@pcap_files.size} )")
      @off = FFI::PCap::Offline.new(@pcap_files[@position])
      @num = 0
      clear_cached_mac
      fetch_cache
    end
    
    def filename
      @pcap_files[@position]
    end
    
    def fullname
      "pkt: `#{filename}: #{@num}th' "
    end
    
  end
end