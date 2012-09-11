require 'spec_helper'

describe DIY::Sender do
  
  class FakeLive
    def inject
    end
  end
  
  it "#before_send" do
    live = double(FakeLive)
     
    before_send_call = lambda { |pkt| pkt[0..2] = "111"; pkt }
    pkt = "222222"
    npkt = "111222"
    live.should_receive(:inject).with(npkt).and_return(nil)
    sender = DIY::Sender.new(live )
    sender.before_send(&before_send_call)
    lambda { sender.inject(pkt) }.should_not raise_error
  end
end