require 'spec_helper'

describe DIY::Builder do
  it "should respond before_send" do
    DIY::Builder.new { ; }.should be_respond_to("before_send")
  end
  
  it "should run two pcaps success " do
    builder = DIY::Builder.new(true) do 
      use DIY::SimpleStrategy.new
      pcapfile ["helper/ssh.pcap", "helper/http.pcap"]
    end
    
    b = Thread.new do
      builder.run
    end
    
    builder2 = DIY::Builder.new do 
      use DIY::SimpleStrategy.new
      pcapfile ["helper/ssh.pcap", "helper/http.pcap"]
    end    
    builder2.run
    b.join
  end
  
  it "should run one pcap success" do
    builder = DIY::Builder.new(true) do 
      use DIY::SimpleStrategy.new
      pcapfile ["helper/ssh.pcap"]
    end
    
    b = Thread.new do
      builder.run
    end
    
    builder2 = DIY::Builder.new do 
      use DIY::SimpleStrategy.new
      pcapfile ["helper/ssh.pcap"]
    end    
    builder2.run
    b.join
  end
  
  it "should run one pcap error" do
    builder = DIY::Builder.new(true) do 
      use DIY::SimpleStrategy.new
      pcapfile ["helper/ssh.pcap"]
    end
    
    b = Thread.new do
      builder.run
    end
    
    builder2 = DIY::Builder.new do 
      use DIY::SimpleStrategy.new
      pcapfile ["helper/http.pcap"]
    end    
    lambda { builder2.run }.should raise_error(DIY::HopePacketTimeoutError)
    lambda { b.join }.should raise_error(DIY::HopePacketTimeoutError)
  end
  
  it "should run two pcap error" do
    builder = DIY::Builder.new(true) do 
      use DIY::SimpleStrategy.new
      pcapfile ["helper/ssh.pcap", "helper/http.pcap"]
    end
    
    b = Thread.new do
      builder.run
    end
    
    builder2 = DIY::Builder.new do 
      use DIY::SimpleStrategy.new
      pcapfile ["helper/http.pcap"]
    end    
    lambda { builder2.run }.should raise_error(DIY::HopePacketTimeoutError)
    lambda { b.join }.should raise_error(DIY::HopePacketTimeoutError)
  end
  
   
  
end