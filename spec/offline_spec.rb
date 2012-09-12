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
end