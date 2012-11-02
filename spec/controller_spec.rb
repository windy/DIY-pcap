require 'spec_helper'
require 'diy/device_finder'

def raise_me
  raise "Error on me"
end

describe "Controller" do
  Thread.abort_on_exception = true
  before(:all) do
    @device_name = DIY::DeviceFinder.smart_select
    @live = DIY::Live.new(@device_name)
    @live2 = DIY::Live.new(@device_name)
    
    @curi = "druby://localhost:7878"
    @suri = "druby://localhost:7879"
    @c1 = @s1 = nil
    # client create
    Thread.abort_on_exception = true
    @client_t ||= Thread.new do
      client = DIY::Worker.new(@live)
      @c1 = DIY::WorkerKeeper.new(client, @curi)
      @c1.run
    end
    
    @server_t ||= Thread.new do
      server = DIY::Worker.new(@live2)
      @s1 = DIY::WorkerKeeper.new(server, @suri)
      @s1.run
    end    
  end
  
  after(:all) do
    #~ @c1.stop #if @c
    #~ @s1.stop #if @s
    #~ DIY::Utils.wait_until { ! @client_t.alive? && ! @server_t.alive? }
  end
  
  it "#run " do
    sleep 1
    builder = DIY::Builder.new do
      pcapfiles "helper/http.pcap"
      use DIY::SimpleStrategy.new
      timeout 1
    end
    #~ builder.run
    lambda { builder.run }.should_not raise_error  
    builder.instance_variable_get("@controller").instance_variable_get("@fail_count").should == 0
  end
  
  it "#run none_hope_skip" do
    running = false
    hope_skip = lambda { |h, r, q|
      if running == false
        running == true
        return DIY::Strategy::NONE_HOPE_SKIP
      else
        return DIY::Strategy::NONE
      end
    }
    
    sleep 1
    builder = DIY::Builder.new do
      pcapfiles "helper/http.pcap"
      use hope_skip
      use DIY::SimpleStrategy.new
      timeout 2
    end
    lambda { builder.run }.should_not raise_error    
    builder.instance_variable_get("@controller").instance_variable_get("@fail_count").should == 0
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
      timeout 1
    end
    lambda { builder.run }.should_not raise_error
    builder.instance_variable_get("@controller").instance_variable_get("@fail_count").should == 1
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
    build2.instance_variable_get("@controller").instance_variable_get("@fail_count").should == 1
  end
  
  it "#run big packet " do
    sleep 1
    build2 = DIY::Builder.new do
      before_send do |pkt, flag|
        new_pkt = "a" * 10000
        pkt.content = new_pkt
        true
      end
      pcapfiles "helper/http.pcap"
    end
    lambda { build2.run }.should_not raise_error  
    build2.instance_variable_get("@controller").instance_variable_get("@fail_count").should == 1
  end
  
  it "#run stragety fail" do
    
    def return_fail
      DIY::Strategy::FAIL
    end
    
    fail = lambda { |h,r,q|
      return_fail
    }
    build2 = DIY::Builder.new do
      use fail
      pcapfiles "helper/http.pcap"
    end
    lambda { build2.run }.should_not raise_error  
    build2.instance_variable_get("@controller").instance_variable_get("@fail_count").should == 1
  end
  
  it "#run with filter" do
    build2 = DIY::Builder.new do
      use DIY::SimpleStrategy.new
      filter "not host 127.0.0.1"
      pcapfiles "helper/http.pcap"
    end
    lambda { build2.run }.should_not raise_error  
  end

  it "#run with error_on_stop" do
    build2 = DIY::Builder.new do
      use DIY::SimpleStrategy.new
      filter "not tcp"
      error_on_stop
      pcapfiles ["helper/http.pcap", "helper/gre.pcap"]
      timeout 1
    end
    lambda { build2.run }.should_not raise_error    
  end

end