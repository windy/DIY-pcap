# encoding : utf-8
require 'diy/mac_learner'

module DIY
  class Offline
    def initialize( pcap_files )
      @pcap_files = [ pcap_files ] if pcap_files.kind_of?(String)
      @pcap_files ||= pcap_files
      raise ZeroOfflineError, "no files found" if @pcap_files.size == 0
      @off = FFI::PCap::Offline.new(@pcap_files[0])
      
      @ml = MacLearner.new
      
      # 记录文件在目录中的位置
      @position = 0
      # 记录包在当前文件的位置
      @num = 0
      
      @tmp_pcap = nil
    end
    
    def nexts
      begin
        _nexts
      rescue DIY::MacLearnConflictError, DIY::PacketInvalidError =>e
        DIY::Logger.warn "Found Error when parse #{fullname}: #{e.message}"
        next_pcap
        retry
      end
    end
    
    def _nexts
      ret = []
      # 取一个
      pkt = fetch_one
      if pkt.nil?
        next_pcap
        pkt = fetch_one
      end
      
      ret << pkt
      where = @ml.tellme(pkt.content)
      
      loop do
        pkt = fetch_one
        return ret if pkt.nil?
        if @ml.tellme(pkt.content) != where
          cached(pkt)
          return ret
        else
          ret << pkt
        end
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
    
    def fetch_cache
      if @tmp_pcap
        tmp = @tmp_pcap
        @tmp_pcap = nil
        return tmp
      end
      return nil
    end
    
    def first_pkt?
      @num == 1
    end
    public
    def next_pcap
      if @position >= @pcap_files.size - 1
        raise EOFError, " end of pcaps "
      end
      # must close before's handle
      @off.close
      @position += 1
      DIY::Logger.info("pcap file changed: #{@pcap_files[@position]} ( #{@position} of #{@pcap_files.size} )")
      @off = FFI::PCap::Offline.new(@pcap_files[@position])
      @num = 0
      fetch_cache
    end
    
    def filename
      @pcap_files[@position]
    end
    
    def fullname
      "pkt: `#{filename}: #{@num}th' "
    end
    
    def now_size
      @num
    end
    
    def files_size
      @pcap_files.size
    end
    
  end
end