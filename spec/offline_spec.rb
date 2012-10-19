require 'spec_helper'

describe DIY::Offline do
  
  it "should get next pcap" do
    files = [ "helper/gre.pcap", "helper/app.pcap" ]
    offline = DIY::Offline.new(files)
    offline.next_pcap
    lambda { offline.next_pcap }.should raise_error(DIY::EOFError)
  end
  
  it "no file" do
    lambda { DIY::Offline.new([]) }.should raise_error(DIY::ZeroOfflineError)
  end
  
  it "should get next special first_pkt" do
    files = [ "helper/app.pcap", "helper/gre.pcap" ]
    offline = DIY::Offline.new(files)
    22.times { offline.nexts }
    offline.nexts[0].size.should == 1
  end
  
  it "should get nexts two" do
    files = [ "helper/gre.pcap", "helper/app.pcap" ]
    offline = DIY::Offline.new(files)
    offline.nexts[0].size.should == 1
    offline.nexts[0].size.should == 2
    offline.nexts[0].size.should == 2
    offline.next_pcap
    offline.nexts[0].size.should == 1
    offline.nexts[0].size.should == 7
    lambda { loop do offline.nexts end }.should raise_error(DIY::EOFError)
  end
  
  it "should get another two" do
    files = [ "helper/http.pcap", "helper/gre.pcap" ]
    offline = DIY::Offline.new(files)
    offline.nexts[0].size.should == 1
    offline.nexts[0].size.should == 1
    offline.nexts[0].size.should == 1
    #change to next
    a = offline.nexts
    a[0].size.should == 1
    a[1].should == :A
    offline.nexts[0].size.should == 2
    offline.nexts[0].size.should == 2
    lambda { loop do offline.nexts end }.should raise_error(DIY::EOFError)
  end
  
  it "should open many files" do
      files = []
      600.times do
        files << "helper/http.pcap"
      end
      #~ puts "files size = #{files.size}"
      offline = DIY::Offline.new(files)
      lambda {
      loop do
        offline.next_pcap
      end }.should raise_error(DIY::EOFError)
  end
  
end