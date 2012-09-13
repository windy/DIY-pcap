require 'spec_helper'

describe DIY::Offline do
  it "should get single pkt" do
    file = "helper/gre.pcap"
    offline = DIY::Offline.new(file)
    offline.next.body.should == File.read( File.join( File.dirname(__FILE__), 'helper/pkt1' ) )
  end
  
  it "should get single pkt nil " do
    file = "helper/gre.pcap"
    offline = DIY::Offline.new(file)
    lambda { while( offline.next ) do ; end }.should_not raise_error
  end
  
  it "should get correct pkt in two files" do
    files = [ "helper/gre.pcap", "helper/app.pcap" ]
    offline = DIY::Offline.new(files)
    lambda { while( offline.next ) do ; end }.should_not raise_error
  end
  
  it "should get next pcap" do
    files = [ "helper/gre.pcap", "helper/app.pcap" ]
    offline = DIY::Offline.new(files)
    offline.next_pcap
    lambda { offline.next_pcap }.should raise_error(DIY::EOFError)
  end
  
  it "should get correct first_pkt flag" do
    files = [ "helper/gre.pcap", "helper/app.pcap" ]
    offline = DIY::Offline.new(files)
    offline.next
    offline.should be_first_pkt
    offline.fullname.should == "pkt: `helper/gre.pcap: 1th' "
    offline.next
    offline.should_not be_first_pkt
    offline.fullname.should == "pkt: `helper/gre.pcap: 2th' "
    offline.next_pcap
    offline.next
    offline.fullname.should == "pkt: `helper/app.pcap: 1th' "
    offline.should be_first_pkt
    offline.next
    offline.should_not be_first_pkt
    offline.fullname.should == "pkt: `helper/app.pcap: 2th' "
  end
  
end