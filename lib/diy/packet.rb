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
      "#{Utils.pp(@content)} : from #{@detail_msg}"
    end
  end
end