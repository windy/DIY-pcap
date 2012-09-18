require 'spec_helper'

require 'diy/worker'
describe DIY::Worker do
  
  class FakeLive
    def inject
    end
    class ::String
      def body
        self
      end
    end
    def loop
      pkt = 1
      @go = true
      while(@go) do
        pkt += 1
        sleep 0.01
        yield( nil, "pkt #{pkt}" )
      end
    end
    
    def stop
      #~ @go = false
    end
    
  end
  
  let(:live) { FakeLive.new }
  
  it "should create ok" do
    DIY::Worker.new(live)
  end
  
  it "#inject" do
  end
  
  it "#ready" do
  end
  
  it "#terminal" do
    #~ live.should_recieve(:stop)
    worker = DIY::Worker.new(live)
    worker.terminal
    
    
    worker.ready do |pkt|
      puts pkt.inspect
    end
    
    sleep 0.1
    worker.terminal
    worker.terminal
    
  end
  
end