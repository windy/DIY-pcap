# encoding : utf-8

require 'diy/ext/capture_wrapper'

module DIY
  class Live
    def initialize(device_name)
      DIY::Logger.info( "Initialize Live: #{device_name}" )
      @live = FFI::PCap::Live.new(:dev=>device_name, :handler => FFI::PCap::CopyHandler, :promisc => true)
      #~ @live.non_blocking= true
    end
    attr_reader :live
    
    # 发包
    def inject(packet_str)
      @live.send_packet(packet_str)
    end
    alias send_packet inject
    
    def loop(&block)
      Kernel.loop do
        @live.dispatch do |this, pkt|
          next unless pkt
          block.call(this, pkt)
        end
        sleep 0.1
      end
    end
    
  end # end of class Live
  
end