module DIY
  class Packet
    def initialize( content, detail_msg = nil )
      @content = content
      @detail_msg = detail_msg
    end
    attr_reader :content, :detail_msg
    attr_writer :content
    
    def to_s
      @content
    end
    
    def inspect
      "#<#{self.class.name}: #{Utils.pp(@content)}, from #{@detail_msg}>"
    end
    
    def pretty_print(lsize = 150)
      real = Utils.pp(@content, false)
      dot = nil
      if inspect.size >= lsize
        dot = "..."
      end
      sprintf "%-#{lsize+2}.#{lsize}s%3s (size= %4d), from %20s", real,dot,@content.size,@detail_msg
    end
  end
end