require 'drb'
module DIY
  class Builder
    def initialize(server = false, &block)
      @strategies = []
      instance_eval(&block)
      @server = server
    end
    
    def use(what)
      @strategies.unshift(what)
    end
    
    def before_send(&block)
      @before_send_hook = block
    end
    
    def find_worker_keepers
      @curi ||= "druby://localhost:7878"
      @suri ||= "druby://localhost:7879"
      DRb.start_service
      @client = DRbObject.new_with_uri(@curi)
      @server = DRbObject.new_with_uri(@suri)
    end
    
    def pcapfile(pcaps)
      DIY::Logger.info( "Initialize Offline: #{pcaps.to_a.join(', ')}" )
      @offline = DIY::Offline.new(pcaps)
    end
    alias pcapfiles pcapfile
    
    def run
      @offline ||= DIY::Offline.new('pcaps/example.pcap')
      @strategy_builder = DIY::StrategyBuilder.new
      @strategies.each { |builder| @strategy_builder.add(builder) }
      find_worker_keepers
      controller = Controller.new( @client, @server, @offline, @strategy_builder )
      #~ controller.before_send(&@before_send_hook)
      controller.run
    end
    
  end
end