require 'spec_helper'

describe DIY::Packet do
  let(:normal_content) { File.open('helper/tcp.dat', 'rb') { |io| io.read } }
  let(:long_content) { File.open('helper/long.dat', 'rb') { |io| io.read } }
  it "#pretty_print normal_content" do
    pkt = DIY::Packet.new(normal_content, "xxx")
    puts pkt.pretty_print
  end
  
  it "#pretty_print long_content" do
    pkt = DIY::Packet.new(long_content, "xxx")
    puts pkt.pretty_print
  end  
end