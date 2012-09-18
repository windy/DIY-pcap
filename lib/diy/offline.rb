# encoding : utf-8

module DIY
  class Offline
    def initialize( pcap_files )
      @pcap_files = [ pcap_files ] if pcap_files.kind_of?(String)
      @pcap_files ||= pcap_files
      @off = FFI::PCap::Offline.new(@pcap_files[0])
      @position = 0
      @num = 0
      
      @tmp_pcap = nil
    end
    
    def next
      if @tmp_pcap
        ret = @tmp_pcap
        @tmp_pcap = nil
        return ret
      end
      
      pkt = @off.next
      if pkt.nil?
        begin
          next_pcap
          pkt = @off.next
        rescue EOFError
          pkt = nil
        end
      end
      
      #record num of pkt
      @num += 1 if pkt
      
      pkt
    end
    
    def nexts
      ret = []
      pkt = self.next
      
      raise EOFError, "end of pcaps" if pkt.nil?
      
      if first_pkt?
        @src = Utils.src_mac(pkt.body)
      end
      
      if Utils.src_mac( pkt.body ) == @src
        while( pkt and (Utils.src_mac( pkt.body ) == @src) ) do
          ret << Packet.new(pkt.copy.body, fullname)
          pkt = self.next
        end     
      else
        while( pkt and (Utils.src_mac( pkt.body ) != @src) ) do
          ret << Packet.new(pkt.copy.body, fullname)
          pkt = self.next
        end            
      end
      
      @tmp_pcap = pkt.copy if pkt
      ret
    end
    
    def first_pkt?
      @num == 1
    end
    
    def next_pcap
      if @position >= @pcap_files.size - 1
        raise EOFError, " end of pcaps "
      end
      @position += 1
      DIY::Logger.info("pcap file changed: #{@pcap_files[@position]}")
      @off = FFI::PCap::Offline.new(@pcap_files[@position])
      @num = 0
      @tmp_pcap = nil
    end
    
    def filename
      @pcap_files[@position]
    end
    
    def fullname
      "pkt: `#{filename}: #{@num}th' "
    end
    
  end
end