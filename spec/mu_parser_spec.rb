require 'spec_helper'

describe Mu do
  let(:pkt) { File.open("helper/tcp.dat", "rb") { |f| f.read } }
  let(:vlan_pkt) { File.open("helper/vlan.dat", "rb") { |f| f.read } }
  it "#ethernet parse" do
    eth = Mu::Pcap::Ethernet.from_bytes(pkt)
    eth.vlan.should == false
    eth.should be_ip
    ip = eth.payload
    tcp = ip.payload
    tcp.should be_kind_of(Mu::Pcap::TCP)
  end

  it "#ethernet vlan" do
    eth = Mu::Pcap::Ethernet.from_bytes(vlan_pkt)
    eth.vlan.should == true
    eth.should be_vlan
  end
end