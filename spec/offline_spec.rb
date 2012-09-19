require 'spec_helper'

describe DIY::Offline do
  
  it "should get next pcap" do
    files = [ "helper/gre.pcap", "helper/app.pcap" ]
    offline = DIY::Offline.new(files)
    offline.next_pcap
    lambda { offline.next_pcap }.should raise_error(DIY::EOFError)
  end
  
  it "should get next special first_pkt" do
    files = [ "helper/app.pcap", "helper/gre.pcap" ]
    offline = DIY::Offline.new(files)
    22.times { offline.nexts }
    offline.nexts.size.should == 1
  end
  
  it "should get nexts two" do
    files = [ "helper/gre.pcap", "helper/app.pcap" ]
    offline = DIY::Offline.new(files)
    offline.nexts.size.should == 1
    offline.nexts.size.should == 2
    offline.nexts.size.should == 2
    offline.next_pcap
    offline.nexts.size.should == 1
    offline.nexts.size.should == 7
    lambda { loop do offline.nexts end }.should raise_error(DIY::EOFError)
  end
  
  it "should get another two" do
    files = [ "helper/http.pcap", "helper/gre.pcap" ]
    offline = DIY::Offline.new(files)
    offline.nexts.size.should == 1
    offline.nexts.size.should == 1
    offline.nexts.size.should == 1
    #change to next
    offline.nexts.size.should == 1
    offline.nexts.size.should == 2
    offline.nexts.size.should == 2
    lambda { loop do offline.nexts end }.should raise_error(DIY::EOFError)
  end
  
end