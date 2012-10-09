require 'spec_helper'

describe Mu do
  let(:pkt) { File.open("helper/tcp.dat", "rb") { |f| f.read } }
  it "#ethernet parse" do
    eth = Mu::Pcap::Ethernet.from_bytes(pkt)
    eth.should be_ip
    ip = eth.payload
    tcp = ip.payload
    tcp.should be_kind_of(Mu::Pcap::TCP)
  end
end