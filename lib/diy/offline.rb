# encoding : utf-8

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
      @new_pcap = true
      @num = 0
    end
    
    def next
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
    
    def first_pkt?
      @num == 1
    end
    
    def next_pcap
      if @file_or_files.kind_of?(String) or @position >= @file_or_files.size - 1
        raise EOFError, " end of pcaps "
      end
      @position += 1
      @off = FFI::PCap::Offline.new(@file_or_files[@position])
      @num = 0
    end
    
    def filename
      if @file_or_files.kind_of?(String)
        @file_or_files
      else
        @file_or_files[@position]
      end
    end
    
    def fullname
      "pkt: `#{filename}: #{@num}th' "
    end
    
  end
end