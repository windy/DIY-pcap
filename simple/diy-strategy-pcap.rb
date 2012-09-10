class NoMacEqualStrategy < DIY::BasicStrategy
  def call(hope_pkt, recv_pkt, queue)
    return OK if hope_pkt[11..-1] == recv_pkt[11..-1]
    return NONE
  end
end

nomac = NoMacEqualStrategy.new

builder = DIY::Builder.new do
  use nomac
  pcapfile "pcaps/gre.pcap"
end

builder.run
