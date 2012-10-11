module DIY
  module Utils
    class << self
      # 漂亮输出包的前十个内容
      def pp(pkt, size_print = true)
        pkt = pkt.content if pkt.kind_of?(DIY::Packet)
        return nil if pkt.nil?
        #~ ( pkt[0..10] + "..." ).dump + "(#{pkt.size} sizes)"
        size = pkt.size
        size_print_str = ""
        if size_print
          size_print_str = "(#{size} sizes)"
        end
        begin
          new_pkt = pkt.dup
          Mu::Pcap::Ethernet.from_bytes(new_pkt).to_s + size_print_str
        rescue Mu::Pcap::ParseError =>e
          DIY::Logger.warn "parse error from pkt: " + ( pkt[0..10] + "..." ).dump + size_print_str
          return  ( pkt[0..10] + "..." ).dump + size_print_str
        end
      end
      
      def src_mac(pkt)
        pkt = pkt.content if pkt.kind_of?(DIY::Packet)
        pkt[6..11]
      end
      
      def dst_mac(pkt)
        pkt = pkt.content if pkt.kind_of?(DIY::Packet)
        pkt[0..5]
      end
      
      def wait_until( timeout = 20, &block )
        timeout(timeout) do
          loop do
            break if block.call
            sleep 0.01
          end
        end
      end
      
      def filter_backtrace(e) 
        filter_ary = [ "/lib/diy/controller.rb", "/lib/diy/strategy_builder.rb" ]
        new_bt = []
        e.backtrace.each do |msg|
          if ! Utils.ary_match(filter_ary, msg)
           new_bt << msg
          else
            puts "break"
            break
          end
        end
        new_bt
      end
      
      def ary_match(ary, msg)
        ary.each do |e|
          return true if /#{Regexp.escape(e)}/ === msg
        end
        nil
      end
      
    end
  end
end