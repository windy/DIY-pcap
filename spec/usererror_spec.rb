require 'spec_helper'
require 'diy/device_finder'

def raise_me
  raise "Error on me"
end

describe "Controller" do

  before(:all) do
    @device_name = DIY::DeviceFinder.smart_select
    @live = DIY::Live.new(@device_name)
    @live2 = DIY::Live.new(@device_name)
    
    @curi = "druby://localhost:7878"
    @suri = "druby://localhost:7879"
    
    # client create
    Thread.abort_on_exception = true
    @client_t ||= Thread.new do
      client = DIY::Worker.new(@live)
      DIY::WorkerKeeper.new(client, @curi).run
    end
    
    @server_t ||= Thread.new do
      server = DIY::Worker.new(@live2)
      DIY::WorkerKeeper.new(server, @suri).run
    end    
  end
  
  after(:all) do
    @client_t.kill
    @server_t.kill
  end
  
  it "#run " do
    sleep 1
    builder = DIY::Builder.new do
      pcapfiles "helper/http.pcap"
      use DIY::SimpleStrategy.new
      timeout 10
    end
    lambda { builder.run }.should_not raise_error  
  end
    
  it "#run stragety error" do
    
    
    wrongUserStragety = lambda {
        raise_me
        #~ raise "error one me"
    }
    
    sleep 1
    builder = DIY::Builder.new do
      pcapfiles "helper/http.pcap"
      use wrongUserStragety
      timeout 10
    end
    lambda { builder.run }.should_not raise_error
  end
  
  it "#run before_send error" do
    sleep 1
    build2 = DIY::Builder.new do
      before_send do
        raise "error on me"
      end
      pcapfiles "helper/http.pcap"
    end
    lambda { build2.run }.should_not raise_error
  end
  
  it "#run big packet " do
    sleep 1
    build2 = DIY::Builder.new do
      before_send do |pkt|
        new_pkt = "a" * 10000
      end
      pcapfiles "helper/http.pcap"
    end
    lambda { build2.run }.should_not raise_error  
  end

end