class NoMacEqualStrategy < DIY::BasicStrategy
  def call(hope_pkt, recv_pkt, queue)
    return OK if hope_pkt[11..-1] == recv_pkt[11..-1]
    return NONE
  end
end

nomac = NoMacEqualStrategy.new

change_mac = lambda do |pkt|
  pkt[6..11] = "aaaaaa"
  return pkt
end

builder = DIY::Builder.new do
  use nomac
  before_send change_mac
  pcapfile "pcaps/gre.pcap"
end

builder.run
