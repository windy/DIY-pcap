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
    
    def before_send(arg= nil, &block)
      if arg
        @before_send_hook = arg
      else
        @before_send_hook = block
      end
    end
    
    def find_worker_keepers
      @curi ||= "druby://localhost:7878"
      @suri ||= "druby://localhost:7879"
      @me  ||= "druby://localhost:7880"
      # controller drb server
      DRb.start_service(@me)
      # client and server drb server
      @client = DRbObject.new_with_uri(@curi)
      @server = DRbObject.new_with_uri(@suri)
    end
    
    def client(ip_or_iport)
      default_port = "7878"
      if ! ip_or_iport.include?(':')
        iport = ip_or_iport + ':' + default_port
      else
        iport = ip_or_iport
      end
      @curi = ip2druby(iport)
    end
    
    def server(ip_or_iport)
      default_port = "7879"
      if ! ip_or_iport.include?(':')
        iport = ip_or_iport + ':' + default_port
      else
        iport = ip_or_iport
      end
      @suri = ip2druby(iport)
    end
    
    def me(ip_or_iport)
      default_port = "7880"
      if ! ip_or_iport.include?(':')
        iport = ip_or_iport + ':' + default_port
      else
        iport = ip_or_iport
      end
      @me = ip2druby(iport)      
    end
    
    def ip2druby(ip)
      if ! ip.include?('://')
        return "druby://" + ip
      end
      return ip
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
      controller.before_send(&@before_send_hook)
      controller.run
    end
    
  end
end