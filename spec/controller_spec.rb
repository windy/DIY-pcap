require 'spec_helper'

describe DIY::Builder do
  
  before(:each) do
    @device_name = FFI::PCap.dump_devices[0][0]
    DIY::Logger.info( "Initialize Live: #{@device_name}" )
    @live = DIY::Live.new(@device_name)#FFI::PCap::Live.new(:dev=>@device_name, :handler => FFI::PCap::Handler, :promisc => true)
    @live2 = DIY::Live.new(@device_name)#FFI::PCap::Live.new(:dev=>@device_name, :handler => FFI::PCap::Handler, :promisc => true)
    
    @curi = "druby://localhost:7878"
    @suri = "druby://localhost:7879"
    
  end
    
  it "#run" do
    # client create
    Thread.abort_on_exception = true
    client_t = Thread.new do
      client = DIY::Worker.new(@live)
      DIY::WorkerKeeper.new(client, @curi).run
    end
    
    server_t = Thread.new do
      server = DIY::Worker.new(@live2)
      DIY::WorkerKeeper.new(server, @suri).run
    end
    
    sleep 1
    builder = DIY::Builder.new do
      pcapfiles "helper/http.pcap"
      use DIY::SimpleStrategy.new
      timeout 10
    end
    builder.run
  end
end