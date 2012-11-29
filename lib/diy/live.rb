# encoding : utf-8

require 'diy/ext/capture_wrapper'

module DIY
  class Live
    def initialize(device_name, args = {})
      DIY::Logger.info( "Initialize Live: #{device_name}" )
      
      default = { :dev=>device_name, :handler => FFI::PCap::CopyHandler, :promisc => true, :timeout=>1 }
      default = merge_arguments(default, args)
      @live = FFI::PCap::Live.new(default)
      DIY::Logger.info( "Listen on:  #{net} " )
      @running = false
      @live.non_blocking= true
    end
    attr_reader :live
    
    # 发包
    def inject(packet_str)
      @live.send_packet(packet_str)
    end
    alias send_packet inject
    
    def loop(&block)
      @running = true
      while @running do
        @live.dispatch do |this, pkt|
          next unless pkt
          block.call(this, pkt)
        end
        block.call(nil, nil) # at least every 0.01 min do it. 
        sleep 0.01
      end
      DIY::Logger.debug "stopped loop recv..."
    end
    
    def set_filter(reg)
      @live.set_filter(reg)
    end
    
    def break
      DIY::Logger.debug "stopping loop recv..."
      @running = false
    end
    
    def net
      @live.network + " / " + @live.netmask
    end
    
    def merge_arguments(default, new)
      default.merge(new)
    end
    
  end # end of class Live
  
end