module DIY
  class Builder
    def initialize(&block)
      @strategies = []
      instance_eval(&block)
    end
    
    def find_device
      @device_name ||= FFI::PCap.dump_devices[0][0]
      @live = FFI::PCap::Live.new(:dev=>@device_name, :handler => FFI::PCap::Handler, :promisc => true)
    end
    
    def device(name)
      @device_name = name
    end
    
    def use(what)
      @strategies.unshift(what)
    end
    
    def pcapfile(pcaps)
      @offline = FFI::PCap::Offline.new(pcaps)
    end
    
    def run
      @offline ||= FFI::PCap::Offline.new('pcaps/example.pcap')
      @queue = Queue.new(@offline)
      @strategy_builder = DIY::StrategyBuilder.new(@queue)
      @strategies.each { |builder| @strategy_builder.add(builder) }
      find_device
      controller = Controller.new( @live, @offline, @strategy_builder )
      controller.run
    end
    
  end
end