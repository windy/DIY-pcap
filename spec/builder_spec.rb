require 'spec_helper'

describe DIY::Builder do
  it "should respond before_send" do
    DIY::Builder.new { ; }.should be_respond_to("before_send")
  end
  
  it "should run success " do
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
  
end