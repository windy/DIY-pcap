module DIY
  class Offline
    def initialize( file_or_files)
      @file_or_files = file_or_files
      if file_or_files.kind_of?(String)
        @off = FFI::PCap::Offline.new(file_or_files)
      elsif file_or_files.kind_of?(Array)
        raise ZeroOfflineError," no pcap files found " if file_or_files.empty?
        @off = FFI::PCap::Offline.new(file_or_files[0])
        @position = 0
      end
    end
    
    def next
      pkt = @off.next
      if pkt.nil? and @file_or_files.kind_of?(Array) and @position < @file_or_files.size - 1
        @position += 1
        DIY::Logger.info("swith to next file: #{@file_or_files[@position]}")
        @off = FFI::PCap::Offline.new(@file_or_files[@position])
      end
      pkt
    end
    
    def next_pcap
      if @file_or_files.kind_of?(String) or @position >= @file_or_files.size - 1
        raise EOFError, " end of pcaps "
      end
      @position += 1
      off = FFI::PCap::Offline.new(@file_or_files[@position])
    end
    
  end
end