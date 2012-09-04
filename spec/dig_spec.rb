require 'spec_helper'
describe DIY::Queue do
  
  before(:all) do 
    @device_name = FFI::PCap.dump_devices[0][0]
    @live = FFI::PCap::Live.new(:dev=>@device_name, :handler => FFI::PCap::Handler, :promisc => true)
  end
  
  before(:each) do
    @offline = FFI::PCap::Offline.new('../simple/pcaps/gre.pcap')
  end
  
  it "#next_send_pkt" do
    q = DIY::Queue.new(@offline)
    q.stub(:wait_until).and_return(true)
    q.next_send_pkt.should == File.read( File.join( File.dirname(__FILE__), 'helper/pkt1' ) )
    pkt1 = q.instance_variable_get("@expect_recv_queue")[0]
    pkt1.should == File.read( File.join( File.dirname(__FILE__), 'helper/pkt2' ) )
    q.next_send_pkt
    pkt2 = q.instance_variable_get("@expect_recv_queue")[1]
    pkt1.should_not == pkt2
    lambda { loop { q.next_send_pkt } }.should raise_error
  end
  
  it "#peek #pop" do
    q = DIY::Queue.new(@offline)
    q.stub(:wait_until).and_return(true)
    q.next_send_pkt
    q.peek.should == File.read( File.join( File.dirname(__FILE__), 'helper/pkt2' ) )
    q.pop.should == File.read( File.join( File.dirname(__FILE__), 'helper/pkt2' ) )
    q.peek.should be_nil
  end

end

describe DIY::Controller do
  
end